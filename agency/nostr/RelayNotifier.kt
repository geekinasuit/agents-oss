package com.geekinasuit.agency.nostr

import java.security.SecureRandom
import java.time.Duration
import java.time.Instant

/**
 * Carries a signed event to a relay and reports the relay's verdict. [RelayConnection.publish]
 * already has this exact shape, so a `RelayConnection` satisfies it by a method reference and a
 * fake satisfies it in a test — which lets [RelayNotifier]'s fan-out (recipient dedup, per-recipient
 * result mapping, crypto-before-deadline) be tested without a socket, the same seam
 * [RelayConnection] uses to inject its HTTP client.
 */
fun interface EventPublisher {
  fun publish(event: NostrEvent, timeout: Duration): PublishResult
}

/**
 * Publishes a gate-open notice to a SET of operator custodians (A4-6). NIP-44 encrypts to exactly
 * one recipient, so notification is pairwise BY CONSTRUCTION — the interface takes a recipient set,
 * and partial delivery to some custodians is a LIVENESS gap (A4-3's posture), never a quorum
 * failure: the release decision is the fold's, and it does not depend on who received a notice.
 *
 * A cost of that pairwise shape: one gate-open publishes N events from the lead's key in a burst,
 * so the relay learns the custodian-set CARDINALITY (how many custodians a gate has), even with no
 * recipient tag on any event. That disclosure is not among A4-6's ratified residuals — it is
 * inherent to per-recipient NIP-44 delivery, not a defect in this codec.
 *
 * Mechanism, not policy — WHICH custodians and WHICH relay live in coach (§REPO_SEAM).
 */
interface Notifier {
  /**
   * Encrypt [notice] to each of [recipients] and publish. [timeout] bounds EACH publish's socket
   * I/O only — see [RelayNotifier] for why the encryption cost sits outside it. Returns a
   * per-recipient report; throws only for the caller bug of an empty recipient set (a gate opened
   * with nobody to tell).
   */
  fun notifyGateOpen(
    notice: GateOpenNotice,
    recipients: Set<RecipientKey>,
    timeout: Duration,
  ): NotifyReport
}

/**
 * The per-recipient outcome of a [Notifier.notifyGateOpen]. Keyed by recipient so partial delivery
 * is legible: some custodians Delivered, others Failed, and the caller sees exactly which.
 */
data class NotifyReport(val outcomes: Map<RecipientKey, NotifyOutcome>)

sealed interface NotifyOutcome {
  /** The relay accepted the notice (OK true). */
  object Delivered : NotifyOutcome

  /** The relay rejected the notice with [message] (OK false) — a verdict, not a transport fault. */
  data class Rejected(val message: String) : NotifyOutcome

  /** The publish produced no relay verdict — a send fault, timeout, or closed socket ([detail]). */
  data class Failed(val detail: String) : NotifyOutcome

  /**
   * The serialized notice was too large to encrypt inline ([plaintextBytes] over [ceilingBytes]);
   * nothing was published. The size test is on the notice plaintext, which is identical for every
   * recipient (a recipient's key changes the ciphertext's bytes, never its length), so this is a
   * notice-GLOBAL outcome: either every recipient's entry is NotEncodable, or none is. Surfaced as a
   * typed per-recipient outcome rather than thrown, so an oversize notice is a liveness gap the
   * caller reads off the report, not an exception escaping the codec.
   */
  data class NotEncodable(val plaintextBytes: Int, val ceilingBytes: Int) : NotifyOutcome
}

/**
 * The relay-backed [Notifier]. Two PHASES, deliberately separated:
 *
 *   1. CRYPTO, with NO deadline: every recipient's conversation key, encryption, and event
 *      signature are computed up front. This is where the cost lives — a point multiplication and a
 *      fresh BIP-340 signature per recipient — and it is charged against NO timeout.
 *   2. I/O, where [timeout] bounds only the socket: each encoded event is published, and the
 *      timeout it is given covers only that publish's send + OK-await.
 *
 * Separating them is what keeps this clear of the #45 defect — where `authenticate()` charges a cold
 * native load and an entropy draw against its OWN deadline, so a caller's timeout can expire on work
 * that never touched the wire. Here the signing and entropy are done before any deadline starts, so
 * the timeout means exactly "how long to wait for the relay", the only thing a caller can sensibly
 * bound.
 *
 * The lead key is taken as [leadSecretKeyHex] — the same String-hex posture [signEvent] and
 * `RelayConfig` use — and VALIDATED at construction (see the init block): a malformed lead key is a
 * deploy-time config error, refused loudly here rather than left to abort the fan-out's crypto phase
 * mid-flight and notify no custodian. That validity check is orthogonal to hardening the key to a
 * clearable type, which is #42's job (filed against the whole surface at once); this notifier does
 * not invent a second STORAGE posture for it.
 *
 * Publishes SEQUENTIALLY. For 2a.4's recipient sets (1-of-1, a few custodians at most) that is
 * simplest and correct; the crypto phase is already isolated, so concurrency, if ever wanted, is a
 * change to phase 2 alone.
 */
class RelayNotifier(
  private val leadSecretKeyHex: String,
  private val publisher: EventPublisher,
  private val now: () -> Long = { Instant.now().epochSecond },
  private val auxRandHex: () -> String = ::freshNotifierAuxRandHex,
) : Notifier {
  init {
    // Refuse a malformed lead key here, at the config boundary. Left unchecked it would reach the
    // eager per-recipient crypto phase (Nip44 ECDH, then signEvent) and throw from inside it,
    // aborting the whole fan-out so NO custodian is notified. Refusing at construction is what makes
    // notifyGateOpen's contract true: with the lead key known-good and every RecipientKey already a
    // validated point, the only input notify can reject is an empty recipient set.
    require(Bip340.isValidSecretKey(leadSecretKeyHex)) {
      "leadSecretKeyHex must be a valid secp256k1 secret key (32 bytes naming a scalar in [1, n-1])"
    }
  }

  override fun notifyGateOpen(
    notice: GateOpenNotice,
    recipients: Set<RecipientKey>,
    timeout: Duration,
  ): NotifyReport {
    require(recipients.isNotEmpty()) {
      "a gate-open notice needs at least one recipient — a gate opened with nobody to notify"
    }
    // Phase 1 — crypto, off the deadline: encode EVERY recipient before any publish. associateWith
    // is eager, so all conversation keys, encryptions, and signatures complete here, in the set's
    // iteration order, before phase 2 touches the wire.
    val encodings: Map<RecipientKey, NoticeEncoding> =
      recipients.associateWith { recipient ->
        encodeGateOpenNotice(leadSecretKeyHex, recipient, notice, now(), auxRandHex())
      }
    // Phase 2 — I/O: publish each encoded event; [timeout] bounds only this socket step.
    val outcomes: Map<RecipientKey, NotifyOutcome> =
      encodings.mapValues { (_, encoding) ->
        when (encoding) {
          is NoticeEncoding.TooLarge ->
            NotifyOutcome.NotEncodable(encoding.plaintextBytes, encoding.ceilingBytes)
          is NoticeEncoding.Encoded ->
            when (val result = publisher.publish(encoding.event, timeout)) {
              PublishResult.Accepted -> NotifyOutcome.Delivered
              is PublishResult.Rejected -> NotifyOutcome.Rejected(result.message)
              is PublishResult.Failed -> NotifyOutcome.Failed(result.detail)
            }
        }
      }
    return NotifyReport(outcomes)
  }
}

/** One CSPRNG for the notifier's aux-randomness. SecureRandom is thread-safe; one shared instance is
 * the documented, contention-free way to use it, as `Nip44` and `RelayConnection` do. */
private val notifierSecureRandom = SecureRandom()

/** A fresh 32-byte BIP-340 aux-rand, hex — drawn once per signed event, like `RelayConnection`'s
 * own. Kept off any per-publish deadline: this is phase-1 crypto (see [RelayNotifier]). */
private fun freshNotifierAuxRandHex(): String {
  val bytes = ByteArray(32)
  notifierSecureRandom.nextBytes(bytes)
  return bytes.joinToString("") { "%02x".format(it) }
}
