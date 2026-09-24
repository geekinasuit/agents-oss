package com.geekinasuit.agency.nostr

import java.time.Duration

/**
 * An [EventPublisher] that replaces its [RelayConnection] before a publish when it can no longer
 * trust it. A [RelayConnection] connects once: after it records a fault it fails every later
 * publish, so a publisher bound to one connection fails every publish after the first fault,
 * including the rest of a [RelayNotifier] fan-out.
 *
 * A publish opens a new connection first when there is none yet, when the one it holds has
 * recorded a fault (a breach, a relay close, a transport error, including one that came between
 * publishes), or when the previous publish on it returned [PublishResult.Failed]. That last case
 * covers a half-open socket, where the send succeeds and no OK comes back. A publish that got a
 * verdict, [PublishResult.Accepted] or [PublishResult.Rejected], keeps the connection. A replaced
 * connection is closed, which zeroes its key.
 *
 * It never sends an event again. A publish that fails returns [PublishResult.Failed], and only the
 * next publish uses a new connection. Each publish makes at most one connection attempt, so a relay
 * that is down costs one connect timeout per publish. Whether to send a failed event again is the
 * caller's decision.
 *
 * [newConnection] belongs to the deployment. It must return a new [RelayConnection], around a new
 * [RelayConfig] and a new [SecretKeyHex], on every call: closing a connection zeroes its config's
 * key, so a factory that hands back one config, or one key holder, fails every reconnect at
 * authentication. An exception from it is reported as [PublishResult.Failed] naming only the
 * exception's class, because the factory handles key material and its message could carry some.
 *
 * The bound: a publish that opens a connection can block for [connectTimeout], the auth timeout
 * and its own timeout, plus [RelayConnection]'s fixed allowances for the handshake and for up to
 * two closes (the connection it replaces, and the new one if its publish fails), plus however long
 * [newConnection] takes, which nothing here bounds. Signing can overrun the auth timeout (see
 * [RelayConnection.authenticate]). A fan-out to N recipients can block for N times that.
 *
 * Nothing reads the connection's [RelayConnection.receive] feed. A message from the relay that is
 * not an OK waits there, and more than [RelayConnection.MAX_QUEUED_MESSAGES] of them breach the
 * connection, which the next publish then replaces.
 *
 * Publishes and [close] run one at a time: [close] waits for a publish in progress, and a publish
 * waits for the one before it to finish, which its own timeout does not cover.
 */
class ReconnectingPublisher(
  private val newConnection: () -> RelayConnection,
  private val connectTimeout: Duration,
  // Required, with no default: whether the relay needs NIP-42 is the deployment's to say.
  private val auth: RelayAuth,
) : EventPublisher {
  private val lock = Any()
  private var connection: RelayConnection? = null
  private var closed = false

  override fun publish(event: NostrEvent, timeout: Duration): PublishResult =
    synchronized(lock) {
      if (closed) return PublishResult.Failed("publisher closed")
      if (connection?.hasFailed() == true) discard()
      val conn =
        connection
          ?: when (val opened = openConnection(newConnection, connectTimeout, auth)) {
            is OpenedConnection.Ready -> opened.connection.also { connection = it }
            is OpenedConnection.Unavailable -> return PublishResult.Failed(opened.detail)
          }
      conn.publish(event, timeout).also { if (it is PublishResult.Failed) discard() }
    }

  /** Close the connection, which zeroes its key, and refuse every later publish. Idempotent. */
  fun close() {
    synchronized(lock) {
      closed = true
      discard()
    }
  }

  private fun discard() {
    connection?.close()
    connection = null
  }
}
