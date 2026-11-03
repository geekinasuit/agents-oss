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
 * ONE subscription on ONE connection, with ONE filter: gift wraps (kind [Nip59.GIFT_WRAP_KIND])
 * addressed to the lead's key, with no `limit`. Nothing else may share that connection: the relay's
 * replay window and the connection's queue bound are counted per connection, so a second
 * subscription or a publisher on it would crowd approvals out. [newConnection] must therefore open a
 * connection used for nothing else, as [ReconnectingSubscription] requires.
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
  private val sink: ApprovalSink,
) {
  /** What the ingress has seen. [accepted] counts each [ApprovalAccept] the sink returned. */
  data class Counts(
    val accepted: Map<ApprovalAccept, Long>,
    val malformed: Long,
    val sinkFailures: Long,
    val resubscriptions: Long,
    val interruptions: Long,
  )

  private val leadPubkey: String = leadKey.useKeyBytes { Bip340.xonlyPubkeyFromKeyBytes(it) }
  private val filter = NostrFilter(kinds = listOf(Nip59.GIFT_WRAP_KIND), tags = mapOf('p' to listOf(leadPubkey)))

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

  fun counts(): Counts =
    synchronized(lock) { Counts(accepted.toMap(), malformed, sinkFailures, resubscriptions, interruptions) }

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
      is Delivery.Received -> (delivery.message as? RelayMessage.Event)?.let { handle(it) }
      is Delivery.Interrupted, is Delivery.Unavailable -> synchronized(lock) { interruptions++ }
      Delivery.Subscribed, Delivery.Stopped, null -> Unit
    }
    return !closed
  }

  /** Run [step] on a daemon thread until [close]. */
  fun start() {
    synchronized(lock) {
      check(worker == null) { "the ingress is already started" }
      worker = thread(isDaemon = true, name = "approval-ingress") { while (step(POLL)) Unit }
    }
  }

  /** Stop the thread, close the subscription, and zero [leadKey]. Idempotent. */
  fun close() {
    closed = true
    val running = synchronized(lock) { worker }
    synchronized(lock) {
      subscription?.close()
      subscription = null
    }
    running?.join(JOIN_MILLIS)
    leadKey.clear()
  }

  private fun handle(message: RelayMessage.Event) {
    if (message.subscriptionId != SUBSCRIPTION_ID) return
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

    private val POLL: Duration = Duration.ofMillis(500)
    private const val SLICE_NANOS: Long = 100_000_000L
    private const val JOIN_MILLIS: Long = 5_000
  }
}
