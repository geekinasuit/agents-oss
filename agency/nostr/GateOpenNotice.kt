package com.geekinasuit.agency.nostr

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * A gate-open notice (A4-6): what the lead tells the operator the moment a gate opens, so the
 * operator authorizes something they can READ rather than a digest they cannot resolve. It carries
 * the [payloadDigest] an approval must bind to, the substrate-issued single-use [nonce] the
 * approval must commit to, and the [artifact] behind the digest (inline). [encodeGateOpenNotice]
 * encrypts it to the operator before it ever reaches a relay — a readable notice is the security
 * property that lets a human decline a spurious gate a prompt-hijacked mind opened, rather than
 * rubber-stamp a hash.
 *
 * SUBSTRATE-NEUTRAL by construction: every field is an auth-layer or opaque value — no nostr type,
 * npub, kind, or relay URL appears here — so the notice's SHAPE does not bind it to nostr even
 * though the encoder carries it over one. The [nonce] is CARRIED, never minted here: the substrate
 * issues it (`Authorization.freshNonceHex`), because the surface that notifies must not also mint
 * what an approval authorizes against.
 */
data class GateOpenNotice(
  val gateId: String,
  val payloadDigest: String,
  val nonce: String,
  val artifact: String,
) {
  init {
    require(gateId.isNotBlank()) { "gateId must be non-blank" }
    require(payloadDigest.isNotBlank()) { "payloadDigest must be non-blank" }
    require(nonce.isNotBlank()) { "nonce must be non-blank" }
    // The artifact is the whole point of A4-6 — the thing the operator reads instead of
    // blind-signing a digest — so a blank one is a caller bug, refused at construction.
    require(artifact.isNotBlank()) { "artifact must be non-blank — a notice with nothing to read defeats A4-6" }
  }
}

/**
 * A recipient custodian's x-only public key: 32 bytes, validated as a real secp256k1 curve point
 * and NORMALIZED to lowercase hex at construction, so two spellings of one key are one value and a
 * [Set] holds each custodian exactly once. Constructed only through [of] — the constructor is
 * private, so no other path can seat a non-canonical spelling and silently defeat that dedup, nor
 * an off-curve key that would later throw inside the notifier's crypto phase.
 *
 * This is the allow-list's byte-distinctness discipline applied to a NOTIFICATION target set — but
 * the reason to DEDUP here is the mirror image of `AllowList`'s reason to REFUSE. There, two
 * principals sharing key bytes collapse quorum distinctness (one keyholder clearing two leaves), a
 * security failure worth refusing. Here the recipients are co-custodians of ONE gate, so a repeat
 * is mere redundancy — the same person listed twice — and the right behaviour is to notify them
 * once, not to error.
 */
class RecipientKey private constructor(val hex: String) {
  override fun equals(other: Any?): Boolean = other is RecipientKey && other.hex == hex

  override fun hashCode(): Int = hex.hashCode()

  override fun toString(): String = "RecipientKey($hex)"

  companion object {
    private val HEX = Regex("[0-9a-fA-F]{64}")

    /** Validate [raw] as a 32-byte x-only pubkey — correct hex shape AND a real curve point — and
     * normalize to lowercase, or throw. A malformed recipient key is a coach-config bug, loud like
     * the rest of this module's configured-key validation (`RelayConfig`, `Nip44.conversationKey`),
     * not hostile traffic to fold closed. Validating the POINT here, at the config boundary, is what
     * keeps an off-curve key from reaching the fan-out's crypto phase and aborting delivery to every
     * custodian — the valid ones included — with an exception `notifyGateOpen` does not promise. */
    fun of(raw: String): RecipientKey {
      require(HEX.matches(raw)) {
        "a recipient key must be 64 hex characters (a 32-byte x-only pubkey), was ${raw.length} chars"
      }
      val normalized = raw.lowercase()
      require(Bip340.isXonlyPubkey(normalized)) {
        "recipient key is 64 hex characters but not a valid secp256k1 x-only public key " +
          "(off-curve or beyond the field prime)"
      }
      return RecipientKey(normalized)
    }
  }
}

/**
 * The result of encoding a notice for ONE recipient: a signed, encrypted event ready to publish, or
 * a typed refusal because the notice is too large to encrypt inline. A refusal, never a throw — see
 * [encodeGateOpenNotice].
 */
sealed interface NoticeEncoding {
  /** The lead-signed, NIP-44-encrypted [event], ready for the relay. */
  data class Encoded(val event: NostrEvent) : NoticeEncoding

  /**
   * The serialized notice is [plaintextBytes] UTF-8 bytes, over NIP-44 v2's [ceilingBytes] hard
   * ceiling (its 16-bit length prefix). The artifact is too big to ride inline; A4-6's escape hatch
   * is to encrypt it as a separate event and reference it, a path 2a.4 defers (see the ticket named
   * in the PR). Reported so the caller surfaces a per-recipient liveness gap rather than the codec
   * throwing from underneath.
   */
  data class TooLarge(val plaintextBytes: Int, val ceilingBytes: Int) : NoticeEncoding
}

/**
 * The regular event kind the gate-open notice is published under. REGULAR (NIP-01: `1000 ≤ n <
 * 10000`) is the load-bearing choice — a regular event is STORED by the relay and every copy
 * retained, so an operator whose client was offline when the gate opened fetches the notice on
 * reconnect. An EPHEMERAL kind (`20000..29999`) is dropped by the relay the instant no subscriber
 * is live, which for a notice meant to reach a phone that may be asleep is silent data loss. 3400
 * is an unallocated value in the `2023..4549` band (checked against the NIP kind registry); coach
 * writes the operator client's subscription filter against this constant at step 5 — the one
 * cross-component value the slice fixes, called out in the PR body for that reason.
 */
const val GATE_OPEN_NOTICE_KIND = 3400

/** NIP-44 v2's hard plaintext ceiling: its length prefix is 16-bit, so 65535 UTF-8 bytes is the
 * format's cap, not a policy knob. Checked on the SERIALIZED notice before encrypting so an
 * oversize notice is a typed [NoticeEncoding.TooLarge], never a thrown exception from inside
 * [Nip44.encrypt]. */
private const val NIP44_PLAINTEXT_CEILING_BYTES = 65535

/**
 * Encode [notice] as a lead-signed, NIP-44-encrypted, regular-kind nostr event addressed to a
 * SINGLE [recipient] (A4-6: NIP-44 encrypts to exactly one recipient, so notification is pairwise —
 * [RelayNotifier] loops this over a recipient set). Mechanism, not policy: [leadKeyBytes] and
 * which recipients exist are coach-side (§REPO_SEAM); this function just builds the carrier.
 *
 * NO recipient tag is attached. A cleartext `#p` tag would tell the relay which custodians a gate
 * has — a residual A4-6 did not ratify (its accepted residuals are only that a gate opened, when,
 * and its rough size, plus ciphertext-at-rest). The operator's client instead subscribes by
 * [GATE_OPEN_NOTICE_KIND] and trial-decrypts: [Nip44.decrypt] is total, so a notice addressed to
 * another custodian folds to null, and this one never discloses the recipient set in clear.
 *
 * REFUSES rather than throws when the notice is too large: the plaintext is serialized and its
 * UTF-8 length checked against [NIP44_PLAINTEXT_CEILING_BYTES] BEFORE [Nip44.encrypt] is called, so
 * an oversize artifact returns [NoticeEncoding.TooLarge] and the caller records a per-recipient
 * liveness gap, never an exception surfacing from the codec.
 *
 * [createdAt] and [auxRandHex] are caller-supplied for the same reason [signEvent] takes them —
 * production draws them fresh per event, a test pins them for determinism. Per A4-3 [createdAt] is
 * carried, never read as a clock.
 *
 * [leadKeyBytes] is the lead secret key as raw bytes — the seam is bytes, not a #42 `SecretKeyHex`,
 * because this codec is in `:nostr` and `SecretKeyHex` is in `:relay` (which depends on `:nostr`), so
 * taking the holder here would cycle the build. The caller owns the array: encode reads it and neither
 * retains nor zeroes it, so a clearable-key caller ([RelayNotifier]) passes `SecretKeyHex.useKeyBytes`
 * bytes and lets that zero them. A malformed key is a deploy error and throws loudly out of the native
 * (as [signEvent] treats its key), never a fold-closed null; [RelayNotifier] refuses one at
 * construction, so it never reaches here mid-fan-out.
 */
fun encodeGateOpenNotice(
  leadKeyBytes: ByteArray,
  recipient: RecipientKey,
  notice: GateOpenNotice,
  createdAt: Long,
  auxRandHex: String,
): NoticeEncoding {
  val plaintext = noticePlaintext(notice)
  val plaintextBytes = plaintext.toByteArray(Charsets.UTF_8).size
  if (plaintextBytes > NIP44_PLAINTEXT_CEILING_BYTES) {
    return NoticeEncoding.TooLarge(plaintextBytes, NIP44_PLAINTEXT_CEILING_BYTES)
  }
  val conversationKey =
    Nip44.conversationKey(leadKeyBytes, Hex.decode(recipient.hex))
  val ciphertext = Nip44.encrypt(plaintext, conversationKey)
  val event =
    signEvent(
      secretKey = leadKeyBytes,
      createdAt = createdAt,
      kind = GATE_OPEN_NOTICE_KIND,
      tags = emptyList(),
      content = ciphertext,
      auxRandHex = auxRandHex,
    )
  return NoticeEncoding.Encoded(event)
}

/**
 * The notice plaintext: a compact JSON object of the notice's fields. A JSON OBJECT (not the
 * positional array [com.geekinasuit.agency.shared.auth.committedPreimage] uses) because this is not
 * a signed preimage — the enclosing event's id and signature cover its integrity, so the plaintext
 * needs stable field NAMES for the operator's client (step 6) to read, not positional canonicality.
 */
private fun noticePlaintext(notice: GateOpenNotice): String =
  buildJsonObject {
      put("gateId", notice.gateId)
      put("payloadDigest", notice.payloadDigest)
      put("nonce", notice.nonce)
      put("artifact", notice.artifact)
    }
    .toString()
