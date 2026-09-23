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
 * What that pairwise shape shows the relay: one gate-open publishes N gift wraps in a burst, each
 * signed by its own single-use key and `p`-tagged with one recipient's key. No event pubkey links a
 * wrap to the lead, but every wrap arrives on the publishing connection, which names the lead if it
 * authenticated (NIP-42). So the relay can learn which recipient keys the lead notifies, and how many
 * per gate: the custodian set's CARDINALITY. Both are inherent to per-recipient gift-wrap delivery,
 * not defects in this codec; [RecipientKey] says which key a deployment lists, so that what the relay
 * learns is a notification key rather than an approval identity.
 *
 * Mechanism, not policy — WHICH custodians and WHICH relay live in coach (§REPO_SEAM).
 */
interface Notifier {
  /**
   * Gift-wrap [notice] to each of [recipients] and publish. [timeout] bounds EACH publish's socket
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
   * The notice was too large to wrap inline: its serialized rumor is [plaintextBytes], over
   * [ceilingBytes]. Nothing was published. The rumor differs between recipients only in the key its
   * `p` tag carries, always 64 hex characters, and every recipient's rumor carries the fan-out's one
   * notice time, so its size is the same for all of them. That makes this a notice-GLOBAL outcome:
   * either every recipient's entry is NotEncodable, or none is. Surfaced as a typed per-recipient
   * outcome rather than thrown, so an oversize notice is a liveness gap the caller reads off the
   * report, not an exception escaping the codec.
   */
  data class NotEncodable(val plaintextBytes: Int, val ceilingBytes: Int) : NotifyOutcome
}

/**
 * The relay-backed [Notifier]. Two PHASES, deliberately separated:
 *
 *   1. CRYPTO, with NO deadline: every recipient's gift wrap is built up front. This is where the
 *      cost lives — per recipient, two key agreements, two encryptions, and two BIP-340 signatures
 *      (the lead's on the seal, a single-use key's on the wrap), plus drawing that single-use key —
 *      and it is charged against NO timeout.
 *   2. I/O, where [timeout] bounds only the socket: each encoded event is published, and the
 *      timeout it is given covers only that publish's send + OK-await.
 *
 * Separating them is what keeps this clear of the #45 defect — where `authenticate()` charges a cold
 * native load and an entropy draw against its OWN deadline, so a caller's timeout can expire on work
 * that never touched the wire. Here the signing and entropy are done before any deadline starts, so
 * the timeout means exactly "how long to wait for the relay", the only thing a caller can sensibly
 * bound.
 *
 * The lead key is held as a clearable [SecretKeyHex] (#42), the same posture `RelayConfig` takes: the
 * notifier OWNS the holder it is given and zeroes it on [close], and yields the decoded bytes only for
 * the span of each signing call ([SecretKeyHex.useKeyBytes]), never as a long-lived String. Because
 * the notifier clears the holder, the caller must give it a DEDICATED [SecretKeyHex] — mint a fresh
 * one (its `ofHex` copies defensively), never share the instance handed to a `RelayConfig`, or one
 * [close] would zero the other's key (the hazard `RelayConfig`'s "not a data class" note names).
 *
 * The key is also VALIDATED at construction (see the init block): a malformed lead key is a
 * deploy-time config error, refused loudly here rather than left to abort the fan-out's crypto phase
 * mid-flight and notify no custodian. This is a deliberate divergence from `RelayConfig`, which
 * validates only structurally and lets the native reject a bad scalar at authenticate() time: the
 * notifier's fan-out has a liveness stake a single authenticate lacks — a scalar that slipped through
 * would throw from inside the eager per-recipient crypto phase and sink delivery to EVERY custodian,
 * not just fail one call.
 *
 * One gate-open has one notice time: [now] is read once per [notifyGateOpen], and every recipient's
 * rumor and wrap carry it. Each seal is dated that time minus its own [sealBackdateSeconds] draw —
 * [encodeGateOpenNotice] says why only the seal is backdated. Each recipient also draws two aux
 * values from [auxRandHex], one per signature. All of these draws are phase-1 work.
 *
 * Publishes SEQUENTIALLY. For 2a.4's recipient sets (1-of-1, a few custodians at most) that is
 * simplest and correct; the crypto phase is already isolated, so concurrency, if ever wanted, is a
 * change to phase 2 alone.
 */
class RelayNotifier(
  private val leadSecretKey: SecretKeyHex,
  private val publisher: EventPublisher,
  private val now: () -> Long = { Instant.now().epochSecond },
  private val auxRandHex: () -> String = ::freshNotifierAuxRandHex,
  private val sealBackdateSeconds: () -> Long = ::freshSealBackdateSeconds,
) : Notifier {
  init {
    // Refuse a malformed lead key here, at the config boundary. Left unchecked it would reach the
    // eager per-recipient crypto phase (Nip44 ECDH, then signEvent) and throw from inside it,
    // aborting the whole fan-out so NO custodian is notified. Refusing at construction is what makes
    // notifyGateOpen's contract true: with the lead key known-good and every RecipientKey already a
    // validated point, the only input notify can reject is an empty recipient set. useKeyBytes yields
    // the decoded bytes for the check and zeroes them in its finally before this returns — a throw
    // here (require failing) does not leave the decoded key resident.
    require(leadSecretKey.useKeyBytes { Bip340.isValidSecretKeyBytes(it) }) {
      "leadSecretKey must be a valid secp256k1 secret key (32 bytes naming a scalar in [1, n-1])"
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
    // is eager, so all key agreements, encryptions, and signatures complete here, in the set's
    // iteration order, before phase 2 touches the wire. The held key is decoded to bytes per recipient
    // (useKeyBytes zeroes each transient copy on the way out) and the HELD holder survives the whole
    // fan-out — it is cleared only by close(), never per notice, so recipient N+1 still signs after N.
    val createdAt = now()
    val encodings: Map<RecipientKey, NoticeEncoding> =
      recipients.associateWith { recipient ->
        leadSecretKey.useKeyBytes { keyBytes ->
          encodeGateOpenNotice(
            leadKeyBytes = keyBytes,
            recipient = recipient,
            notice = notice,
            createdAt = createdAt,
            sealCreatedAt = createdAt - sealBackdateSeconds(),
            sealAuxRandHex = auxRandHex(),
            wrapAuxRandHex = auxRandHex(),
          )
        }
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

  /**
   * Zero the held lead key. The clearable holder exists precisely so the plaintext key does not
   * outlive the notifier; [SecretKeyHex.clear] is idempotent, so a repeated close is harmless — no
   * `closed` flag is needed, there being no socket to close exactly once (unlike `RelayConnection`).
   * A notify after close fails closed: [SecretKeyHex.useKeyBytes] decodes the zeroed hex and throws,
   * rather than signing a zeroed key. A bare `close()` mirrors `RelayConnection`, which implements no
   * `Closeable`/`AutoCloseable` either.
   *
   * Nothing forces this call: a `RelayNotifier` is not `AutoCloseable`, so whatever owns its lifecycle
   * (coach's step-5 wiring) must invoke [close] at end-of-life. Until it does, the held key is retained,
   * not zeroed — no worse than the prior String-typed field, but the hardening stays inert until wired.
   */
  fun close() = leadSecretKey.clear()
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

/** How far back a seal may be dated: NIP-17's "up to two days in the past". */
private const val SEAL_BACKDATE_WINDOW_SECONDS = 2 * 24 * 60 * 60

/** A fresh seal backdate in seconds, uniform over [0, two days). Drawn once per wrap, in phase 1. */
private fun freshSealBackdateSeconds(): Long =
  notifierSecureRandom.nextInt(SEAL_BACKDATE_WINDOW_SECONDS).toLong()
