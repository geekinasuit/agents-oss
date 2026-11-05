package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.lead.ApprovalAccept
import com.geekinasuit.agency.lead.ApprovalCandidate
import com.geekinasuit.agency.nostr.Bip340
import com.geekinasuit.agency.nostr.Nip59
import com.geekinasuit.agency.nostr.NostrEvent
import com.geekinasuit.agency.nostr.NostrFilter
import com.geekinasuit.agency.nostr.ReconnectingSubscription
import com.geekinasuit.agency.nostr.ReconnectingSubscription.Delivery
import com.geekinasuit.agency.nostr.RelayAuth
import com.geekinasuit.agency.nostr.RelayConnection
import com.geekinasuit.agency.nostr.RelayMessage
import com.geekinasuit.agency.nostr.SecretKeyHex
import com.geekinasuit.agency.nostr.UntilPager
import com.geekinasuit.agency.nostr.decodeApproval
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** Where the ingress hands each decoded approval: the host's accept boundary, `AgentHost::injectApproval`. */
fun interface ApprovalSink {
  fun accept(candidate: ApprovalCandidate): ApprovalAccept
}

/**
 * Carries approvals from a relay to the host's accept boundary (order item 3, carrier (a)). It holds
 * ONE kept subscription on ONE connection, with ONE filter: gift wraps (kind [Nip59.GIFT_WRAP_KIND])
 * addressed to the lead's key, with a `limit` of [PAGE_LIMIT]. A replay with no limit could overflow
 * the connection's queue, and it would then break before its EOSE, on every connection, so no walk
 * would start. Nothing else may share that connection: the relay's replay window and the connection's
 * queue bound are counted per connection, so another subscription or a publisher on it would crowd
 * approvals out. The pages below are the one exception, and they run one at a time with the same
 * limit. [newConnection] must therefore open a connection used for nothing else, as
 * [ReconnectingSubscription] requires.
 *
 * A relay replays only the newest wraps it allows, so a member that stores enough newer wraps pushes
 * an approval out of the replay. So after the replay of each new connection, while [approvalsAwaited]
 * says an approval could count, the ingress walks back through the older wraps with `until`, a page
 * at a time, each after the EOSE of the one before, as [UntilPager] decides. The filter is otherwise
 * the same. Each page has a subscription id of its own, [PAGE_SUBSCRIPTION_PREFIX]
 * and its number, so a wrap that arrives under a page after its EOSE, which a member times and stamps
 * as it likes, reaches [sink] and cannot move the walk. One a relay puts before a page's EOSE can: a
 * relay that sends live events into a stored replay lets a member stamp the walk past what lies
 * between. The kept subscription stays open, so an approval published during the walk arrives on it.
 * [approvalsAwaited] is asked before each page, and while it says no, a walk ends, and none starts, so
 * a lead with nothing open reads no old wraps.
 *
 * The walk goes back to the end of what the relay gives, on every new connection. It cannot stop
 * sooner on what it has seen: a wrap already journaled says nothing about an older one, which is the
 * crowded-out approval it is looking for. So each reconnect while a gate is open costs a read of the
 * lead's whole stored mailbox. Its wraps go through [sink] like any others, which drops the repeats.
 *
 * A walk can end short, and [Counts.stalledWalks] counts the ways the ingress can see: [UntilPager]
 * reports a stall, the relay refuses a page, or a page cannot be sent. An approval below that point
 * stays held until it is sent again. Three ways go uncounted: a relay that caps a page below
 * [PAGE_LIMIT] can make a stall read as an end, one that sends no EOSE for a page holds its walk
 * until a new connection starts another, and frames the connection drops as unparseable count for
 * nothing, so a replay made only of those reads as empty. This never forges a release: the worst a
 * relay or a member can do here is delay one.
 *
 * For each event it receives, it opens the gift wrap with [leadKey], decodes the rumor as an approval
 * by shape alone, and hands the result to [sink]. An event that is not a wrap, a wrap that does not
 * open under [leadKey], and a rumor that carries no approval are counted as malformed and dropped:
 * no approval signature reached the lead, so there is nothing to record. Everything that decodes goes
 * to [sink], whose accept boundary judges, records and bounds it.
 *
 * When [sink] THROWS, the approval was not journaled (a failed append, or a boundary that has stopped),
 * and the relay sends stored events again only on a new subscription. So the ingress closes its
 * subscription and opens a new one after a delay, which makes the relay replay the approval. The delay
 * is [resubscribeBackoff], doubling up to its maximum while the sink keeps throwing, and back to its
 * initial value after an accept that does not throw. A stopped boundary therefore costs one
 * resubscription per maximum delay, not a busy loop.
 *
 * [leadKey] must be a holder of its own: [close] zeroes it, and a holder another component also
 * clears (a [com.geekinasuit.agency.nostr.RelayNotifier]'s, a [com.geekinasuit.agency.nostr.RelayConfig]'s)
 * would zero this one's key or be zeroed by it.
 *
 * [counts] reports what the ingress has seen since it was built, for a reader or the runner to show.
 * [step] handles at most one delivery and is what [start]'s thread runs in a loop; a test drives it
 * directly.
 */
class ApprovalIngress(
  private val newConnection: () -> RelayConnection,
  private val connectTimeout: Duration,
  private val auth: RelayAuth,
  private val backoff: ReconnectingSubscription.Backoff,
  private val resubscribeBackoff: ReconnectingSubscription.Backoff,
  private val leadKey: SecretKeyHex,
  /** Whether an approval could count now, `AgentHost::approvalsAwaited`. When it throws, the ingress
   * treats it as a throw from [sink]. */
  private val approvalsAwaited: () -> Boolean,
  private val sink: ApprovalSink,
) {
  /** What the ingress has seen. [accepted] counts each [ApprovalAccept] the sink returned. [pages]
   * counts each page of stored wraps asked for, and [stalledWalks] each walk the ingress saw end
   * before the relay's oldest wrap, as the class KDoc lists. */
  data class Counts(
    val accepted: Map<ApprovalAccept, Long>,
    val malformed: Long,
    val sinkFailures: Long,
    val resubscriptions: Long,
    val interruptions: Long,
    val pages: Long,
    val stalledWalks: Long,
  )

  /** The walk in progress: [reading] is the subscription whose stored wraps it is reading, and it is
   * on page [page]. */
  private class Walk(val pager: UntilPager, var reading: String, var page: Long = 0)

  private val leadPubkey: String = leadKey.useKeyBytes { Bip340.xonlyPubkeyFromKeyBytes(it) }
  private val filter =
    NostrFilter(kinds = listOf(Nip59.GIFT_WRAP_KIND), tags = mapOf('p' to listOf(leadPubkey)), limit = PAGE_LIMIT)

  private val lock = Any()
  @Volatile private var closed = false
  private var subscription: ReconnectingSubscription? = null
  private var resubscribeDelayMillis = resubscribeBackoff.initial.toMillis()
  private var resubscribeAtNanos = System.nanoTime()
  private var worker: Thread? = null

  private val accepted = mutableMapOf<ApprovalAccept, Long>()
  private var malformed = 0L
  private var sinkFailures = 0L
  private var resubscriptions = 0L
  private var interruptions = 0L
  private var pages = 0L
  private var stalledWalks = 0L

  // Touched only by the thread that runs [step].
  private var walk: Walk? = null

  fun counts(): Counts =
    synchronized(lock) {
      Counts(accepted.toMap(), malformed, sinkFailures, resubscriptions, interruptions, pages, stalledWalks)
    }

  /** Handle at most one delivery, waiting up to [timeout] for it. Never throws for anything a relay or
   * a sender does. Returns false once [close] has been called, and on a thread whose interrupt status
   * is set, which it leaves set: such a thread can no longer wait, so [start]'s loop ends rather than
   * spin. */
  fun step(timeout: Duration): Boolean {
    if (Thread.currentThread().isInterrupted) return false
    var waitUntil: Long? = null
    val sub =
      synchronized(lock) {
        if (closed) return false
        subscription
          ?: if (System.nanoTime() - resubscribeAtNanos < 0) {
            waitUntil = resubscribeAtNanos
            null
          } else {
            ReconnectingSubscription(newConnection, connectTimeout, auth, SUBSCRIPTION_ID, listOf(filter), backoff)
              .also { subscription = it }
          }
      }
    if (sub == null) {
      waitUntil?.let { sleepUntil(it, timeout) }
      return !closed
    }
    when (val delivery = sub.next(timeout)) {
      is Delivery.Received -> receive(sub, delivery.message)
      is Delivery.Interrupted, is Delivery.Unavailable -> {
        walk = null
        synchronized(lock) { interruptions++ }
      }
      Delivery.Subscribed -> walk = Walk(UntilPager(PAGE_LIMIT), SUBSCRIPTION_ID)
      Delivery.Stopped, null -> Unit
    }
    return !closed
  }

  private fun receive(sub: ReconnectingSubscription, message: RelayMessage) {
    when (message) {
      is RelayMessage.Event -> {
        walk?.takeIf { it.reading == message.subscriptionId }?.pager?.saw(message.event.createdAt)
        handle(message)
      }
      is RelayMessage.Eose -> walk?.takeIf { it.reading == message.subscriptionId }?.let { advance(sub, it) }
      is RelayMessage.Closed ->
        walk?.takeIf { it.reading == message.subscriptionId }?.let {
          walk = null
          synchronized(lock) { stalledWalks++ }
        }
      else -> Unit
    }
  }

  // The page [w] is reading has ended: ask for the next one, or end the walk.
  private fun advance(sub: ReconnectingSubscription, w: Walk) {
    val decision = w.pager.pageEnded()
    if (decision is UntilPager.Decision.Stalled) synchronized(lock) { stalledWalks++ }
    val next = decision as? UntilPager.Decision.Next
    val goOn = if (next != null) awaited() ?: return else false
    if (w.page > 0) sub.closeOnOpenConnection(w.reading)
    if (next == null || !goOn) {
      walk = null
      return
    }
    w.page++
    w.reading = PAGE_SUBSCRIPTION_PREFIX + w.page
    val page = NostrFilter(filter.kinds, filter.tags, limit = PAGE_LIMIT, until = next.until)
    if (sub.requestOnOpenConnection(w.reading, listOf(page))) {
      synchronized(lock) { pages++ }
    } else {
      walk = null
      synchronized(lock) { stalledWalks++ }
    }
  }

  // Whether to go on, or null when asking threw and the ingress is resubscribing.
  private fun awaited(): Boolean? =
    try {
      approvalsAwaited()
    } catch (x: Exception) {
      if (x is InterruptedException) Thread.currentThread().interrupt()
      resubscribeLater()
      null
    }

  /**
   * Run [step] on a daemon thread until [close]. When the thread ends any other way, approvals stop
   * reaching the host, so it closes the subscription and calls [onExit] with why, on that thread. Two
   * paths lead there: the thread is interrupted, or something escapes a delivery, such as an [Error]
   * from the sink, which a delivery does not catch. What escaped is rethrown after [onExit], to the
   * thread's uncaught-exception handler, with anything [onExit] throws attached as suppressed. A
   * [close] that comes before the thread ends ends it without calling [onExit]; one that comes after
   * the thread has closed its subscription does not stop the call. [onExit] may call [close]. The
   * ingress does not restart the thread, and a started ingress cannot be started again: whoever runs
   * it decides, in [onExit], whether to stop, and still calls [close] to zero [leadKey]. The reason
   * carries the escaped throwable's message, which may hold text the sink did not write, so show it
   * through [com.geekinasuit.agency.shared.text.inert].
   */
  fun start(onExit: (reason: String) -> Unit) {
    synchronized(lock) {
      check(worker == null) { "the ingress is already started" }
      worker = thread(isDaemon = true, name = "approval-ingress") { work(onExit) }
    }
  }

  private fun work(onExit: (reason: String) -> Unit) {
    var escaped: Throwable? = null
    val reason =
      try {
        while (step(POLL)) Unit
        "the ingress thread was interrupted"
      } catch (x: Throwable) {
        escaped = x
        "the ingress thread ended on ${x.javaClass.name}: ${x.message}"
      }
    // The thread is ending, so its interrupt status has nothing left to stop; cleared, it no longer
    // fails a close or an [onExit] that waits.
    Thread.interrupted()
    // Under the lock, so this and [close] agree on which of them came first.
    val report =
      synchronized(lock) {
        if (closed) {
          false
        } else {
          subscription?.close()
          subscription = null
          true
        }
      }
    if (report) {
      try {
        onExit(reason)
      } catch (t: Throwable) {
        val first = escaped ?: throw t
        first.addSuppressed(t)
      }
    }
    escaped?.let { throw it }
  }

  /** Stop the thread, close the subscription, and zero [leadKey]. Idempotent. Called on the thread
   * itself, from [start]'s `onExit`, it does not wait for the thread to end. */
  fun close() {
    val running =
      synchronized(lock) {
        closed = true
        subscription?.close()
        subscription = null
        worker
      }
    if (running !== Thread.currentThread()) running?.join(JOIN_MILLIS)
    leadKey.clear()
  }

  private fun handle(message: RelayMessage.Event) {
    if (message.subscriptionId != SUBSCRIPTION_ID && !message.subscriptionId.startsWith(PAGE_SUBSCRIPTION_PREFIX)) return
    val carrier = open(message.event)?.let { decodeApproval(it) }
    if (carrier == null) {
      synchronized(lock) { malformed++ }
      return
    }
    val candidate = ApprovalCandidate(carrier.gateId, carrier.nonce, carrier.payloadDigest, carrier.evidence)
    val outcome =
      try {
        sink.accept(candidate)
      } catch (x: Exception) {
        if (x is InterruptedException) Thread.currentThread().interrupt()
        resubscribeLater()
        return
      }
    synchronized(lock) {
      accepted[outcome] = (accepted[outcome] ?: 0L) + 1
      resubscribeDelayMillis = resubscribeBackoff.initial.toMillis()
    }
  }

  private fun open(event: NostrEvent) =
    if (event.kind != Nip59.GIFT_WRAP_KIND) null
    else
      try {
        leadKey.useKeyBytes { Nip59.unwrap(it, event) }
      } catch (_: Exception) {
        null
      }

  // The approval the sink failed to record is replayed only on a new subscription, after the delay.
  private fun resubscribeLater() {
    walk = null
    synchronized(lock) {
      sinkFailures++
      resubscriptions++
      subscription?.close()
      subscription = null
      val delay = resubscribeDelayMillis
      resubscribeAtNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(delay)
      val max = resubscribeBackoff.max.toMillis()
      resubscribeDelayMillis = if (delay > max / 2) max else delay * 2
    }
  }

  private fun sleepUntil(atNanos: Long, timeout: Duration) {
    val waitNanos = minOf(atNanos - System.nanoTime(), timeout.toNanos())
    if (waitNanos <= 0) return
    try {
      TimeUnit.NANOSECONDS.sleep(minOf(waitNanos, SLICE_NANOS))
    } catch (_: InterruptedException) {
      Thread.currentThread().interrupt()
    }
  }

  companion object {
    /** The subscription id the ingress sends its one REQ under. */
    const val SUBSCRIPTION_ID = "approvals"

    /** The start of the subscription id of each page of a walk, followed by the page's number. */
    const val PAGE_SUBSCRIPTION_PREFIX = "approvals-page-"

    /** The most wraps the replay or a page asks for. Below the connection's queue, so each leaves room
     * for the live events that share it. */
    const val PAGE_LIMIT = 500

    private val POLL: Duration = Duration.ofMillis(500)
    private const val SLICE_NANOS: Long = 100_000_000L
    private const val JOIN_MILLIS: Long = 5_000
  }
}
