package com.geekinasuit.agency.nostr

import java.time.Duration
import java.util.concurrent.TimeUnit

/**
 * A subscription that outlives the connection it runs on. A [RelayConnection] connects once: after
 * it records a fault (a breach, a relay close, a transport error), [RelayConnection.receive] returns
 * the messages already queued and then nothing, so a consumer that holds one connection stops
 * receiving at the first fault.
 *
 * [next] opens a connection when none is open, authenticates it as [auth] says, and sends the REQ
 * for [subscriptionId] and [filters]. When the connection records a fault, or the relay ends the
 * subscription with a CLOSED for [subscriptionId], [next] reports [Delivery.Interrupted] and closes
 * the connection, which zeroes its key. A later [next] opens a new connection once the delay has
 * passed, and sends the same REQ on it.
 *
 * The REQ is the same on every connection and carries no `since`, so the relay sends again every
 * stored event that matches [filters], up to its own cap on stored events. That covers the events it
 * stored while no connection was open, and a consumer sees each earlier event again after a
 * reconnect: it must treat such a repeat as nothing new. A cursor taken from the events' `created_at`
 * would ask for less, but `created_at` is whatever an event's author wrote. One matching event
 * stamped far in the future would move such a cursor past every event the relay stored after it, and
 * every later reconnect would ask for none of them.
 *
 * Messages from the relay are passed on as they arrive, in [Delivery.Received], with no dedup and no
 * reordering, as [RelayConnection.receive] delivers them. A CLOSED or EOSE for another subscription
 * id is passed on and changes nothing here.
 *
 * The delay before a new connection is [Backoff.initial] after the first interruption or failed
 * attempt, and doubles after each one that follows, up to [Backoff.max]. It returns to
 * [Backoff.initial] when the relay sends EOSE for [subscriptionId], which shows that the relay served
 * the subscription. A relay that serves the subscription and then drops it is therefore tried again
 * after [Backoff.initial]. One that is down, or that refuses the connection, the authentication or
 * the subscription, is tried at most once per [Backoff.max] once the delay has grown.
 *
 * [newConnection] belongs to the deployment and has the contract [ReconnectingPublisher] states: a new
 * [RelayConnection], around a new [RelayConfig] and a new [SecretKeyHex], on every call. An exception
 * from it is reported by the exception's class alone.
 *
 * [next] and [close] run one at a time, but [close] does not wait out a [next] that is waiting for a
 * message or for the delay: those waits check for [close] about every 100 ms. It does wait for a
 * connection attempt in progress, which [connectTimeout], the auth timeout and [RelayConnection]'s
 * own allowances bound, plus however long [newConnection] takes.
 */
class ReconnectingSubscription(
  private val newConnection: () -> RelayConnection,
  /** Bounds the connect, and separately the send of the REQ. */
  private val connectTimeout: Duration,
  // Required, with no default: whether the relay needs NIP-42 is the deployment's to say.
  private val auth: RelayAuth,
  private val subscriptionId: String,
  filters: List<NostrFilter>,
  private val backoff: Backoff,
) {
  private val filters: List<NostrFilter> = filters.toList()

  init {
    requireValidSubscriptionId(subscriptionId)
    require(this.filters.isNotEmpty()) { "a REQ must carry at least one filter (NIP-01)" }
  }

  /**
   * The delay before a new connection: [initial] after the first interruption or failed attempt,
   * doubled after each one that follows, up to [max]. Counted in whole milliseconds, so [initial]
   * must be at least one: a delay of zero would never grow.
   */
  class Backoff(val initial: Duration, val max: Duration) {
    internal val initialMillis: Long = initial.toMillis()
    internal val maxMillis: Long = max.toMillis()

    init {
      require(initialMillis >= 1) { "the initial delay must be at least 1 ms, was $initial" }
      require(maxMillis >= initialMillis) { "the maximum delay must be at least the initial delay" }
    }
  }

  /** What one [next] reports. */
  sealed interface Delivery {
    /** A message from the relay, as it arrived. */
    data class Received(val message: RelayMessage) : Delivery

    /** A new connection is open and the REQ was sent on it. A relay that follows NIP-01 then sends
     * the stored events that match, then EOSE. */
    data object Subscribed : Delivery

    /** The subscription ended: the connection recorded a fault, or the relay closed the
     * subscription, as [detail] says. The next connection is tried once [retryAfter] has passed. */
    data class Interrupted(val detail: String, val retryAfter: Duration) : Delivery

    /** A connection could not be opened, authenticated or subscribed on, as [detail] says. The next
     * attempt comes once [retryAfter] has passed. */
    data class Unavailable(val detail: String, val retryAfter: Duration) : Delivery

    /** [close] was called. Every later [next] returns this. */
    data object Stopped : Delivery
  }

  private val lock = Any()
  @Volatile private var closed = false
  private var connection: RelayConnection? = null
  private var delayMillis = backoff.initialMillis
  private var nextAttemptNanos = System.nanoTime()

  /**
   * The next thing to report, or null if there is none before [timeout] passes. When no connection
   * is open and the delay has passed, it first opens one and sends the REQ. Never throws for a
   * remote fault.
   *
   * It can block for [timeout], or, when a connection attempt is due, for the attempt instead:
   * [connectTimeout], the auth timeout and the REQ's send, plus [RelayConnection]'s fixed allowances
   * for the handshake and for closing a connection that fails, plus however long [newConnection]
   * takes. A negative [timeout] counts as zero, and one longer than about 146 years is cut to that.
   *
   * On a thread whose interrupt status is set, it makes no connection attempt. It reports only a
   * message or a fault the open connection already holds, and otherwise returns null, leaving the
   * status set.
   */
  fun next(timeout: Duration): Delivery? {
    val deadline =
      System.nanoTime() + TimeUnit.NANOSECONDS.convert(timeout).coerceIn(0L, MAX_WAIT_NANOS)
    synchronized(lock) {
      if (closed) return Delivery.Stopped
      val conn = connection
      if (conn == null) {
        if (!awaitAttemptTime(deadline)) return if (closed) Delivery.Stopped else null
        return open()
      }
      val message = receive(conn, deadline)
      return when {
        message != null -> deliver(message)
        closed -> Delivery.Stopped
        // The connection queues a message before it records the fault that follows it, so a
        // message can land after receive's last poll and before its fault check. Take it before
        // closing the connection, which would drop it.
        conn.hasFailed() ->
          conn.receive(Duration.ZERO)?.let { deliver(it) }
            ?: interrupt("connection failed: ${conn.failureReason()}")
        else -> null
      }
    }
  }

  /** Close the connection, which zeroes its key. Every later [next] returns [Delivery.Stopped].
   * Idempotent. */
  fun close() {
    closed = true
    synchronized(lock) {
      connection?.close()
      connection = null
    }
  }

  private fun open(): Delivery {
    val conn =
      when (val opened = openConnection(newConnection, connectTimeout, auth)) {
        is OpenedConnection.Ready -> opened.connection
        is OpenedConnection.Unavailable -> return Delivery.Unavailable(opened.detail, scheduleRetry())
      }
    // A close() called during the attempt is waiting for the lock this call holds.
    if (closed) {
      conn.close()
      return Delivery.Stopped
    }
    return when (val sent = conn.subscribe(subscriptionId, filters, connectTimeout)) {
      SubscribeResult.Sent -> {
        connection = conn
        Delivery.Subscribed
      }
      is SubscribeResult.Failed -> {
        conn.close()
        Delivery.Unavailable("could not subscribe: ${sent.detail}", scheduleRetry())
      }
    }
  }

  private fun deliver(message: RelayMessage): Delivery {
    if (message is RelayMessage.Closed && message.subscriptionId == subscriptionId) {
      return interrupt("relay closed the subscription: ${message.message}")
    }
    if (message is RelayMessage.Eose && message.subscriptionId == subscriptionId) {
      delayMillis = backoff.initialMillis
    }
    return Delivery.Received(message)
  }

  private fun interrupt(detail: String): Delivery {
    connection?.close()
    connection = null
    return Delivery.Interrupted(detail, scheduleRetry())
  }

  // Schedule the next attempt after the current delay, double the delay for the attempt after that,
  // up to the maximum, and return the delay this attempt waits.
  private fun scheduleRetry(): Duration {
    val delay = delayMillis
    nextAttemptNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(delay)
    delayMillis = if (delay > backoff.maxMillis / 2) backoff.maxMillis else delay * 2
    return Duration.ofMillis(delay)
  }

  // Wait in slices until the next attempt is due, and return whether it is. False after close() or
  // when the thread is interrupted, even if the attempt is already due; otherwise false at
  // [deadline] if the attempt is not yet due.
  private fun awaitAttemptTime(deadline: Long): Boolean {
    while (true) {
      if (closed || Thread.currentThread().isInterrupted) return false
      val now = System.nanoTime()
      if (now - nextAttemptNanos >= 0) return true
      if (now - deadline >= 0) return false
      try {
        TimeUnit.NANOSECONDS.sleep(minOf(nextAttemptNanos - now, deadline - now, SLICE_NANOS))
      } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        return false
      }
    }
  }

  // Take the connection's next message. [RelayConnection.receive] waits out its whole timeout when
  // the connection fails mid-wait, so this waits in slices and sees a fault or close() within one
  // slice. Null at [deadline], after close(), when the thread is interrupted, or once the connection
  // has failed. A message can still be queued then, one that landed after the last poll, and [next]
  // takes it before it closes the connection.
  private fun receive(conn: RelayConnection, deadline: Long): RelayMessage? {
    while (true) {
      val remaining = deadline - System.nanoTime()
      val slice = if (remaining > 0) minOf(remaining, SLICE_NANOS) else 0L
      conn.receive(Duration.ofNanos(slice))?.let { return it }
      if (closed || conn.hasFailed() || remaining <= 0 || Thread.currentThread().isInterrupted) {
        return null
      }
    }
  }

  private companion object {
    // How often a wait checks for a fault or close(): 100 ms.
    const val SLICE_NANOS: Long = 100_000_000L

    // The longest wait next() counts: about 146 years, half the span over which a subtraction of
    // System.nanoTime() values comes out right. Every wait here compares the deadline that way.
    const val MAX_WAIT_NANOS: Long = Long.MAX_VALUE / 2
  }
}
