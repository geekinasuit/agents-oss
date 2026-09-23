package com.geekinasuit.agency.nostr

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
 *
 * The key is NOT hidden from the relay: the gift wrap that carries a notice names its recipient in a
 * cleartext `p` tag (see [Nip59]), so the relay sees which key each notice is for. A deployment that
 * must not show the relay a custodian's long-lived identity lists a key the custodian holds for
 * notifications alone, never the key they approve with.
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
 * The result of encoding a notice for ONE recipient: a gift wrap ready to publish, or a typed refusal
 * because the notice is too large to wrap inline. A refusal, never a throw — see
 * [encodeGateOpenNotice].
 */
sealed interface NoticeEncoding {
  /** The kind-1059 gift wrap carrying the notice, ready for the relay. A single-use key signs it; the
   * lead's signature is on the seal inside, which only the recipient can open. */
  data class Encoded(val event: NostrEvent) : NoticeEncoding

  /**
   * The notice's serialized rumor is [plaintextBytes] UTF-8 bytes, over the [ceilingBytes] a gift
   * wrap can carry ([Nip59.RUMOR_CEILING_BYTES]). The artifact is too big to ride inline; A4-6's
   * escape hatch is to encrypt it as a separate event and reference it, a path 2a.4 defers. Reported
   * so the caller surfaces a per-recipient liveness gap rather than the codec throwing from
   * underneath.
   */
  data class TooLarge(val plaintextBytes: Int, val ceilingBytes: Int) : NoticeEncoding
}

/**
 * The kind of the RUMOR a gate-open notice travels as: NIP-17's kind-14 chat message, so a client
 * that reads NIP-17 direct messages can show the notice as a message from the lead. The event a relay
 * stores is the gift wrap around it ([Nip59.GIFT_WRAP_KIND]), a regular kind, so an operator whose
 * client was offline when the gate opened fetches the notice on reconnect.
 *
 * Such a client has two limits. It looks for the notice only on the relays it reads for the
 * recipient key, which NIP-17 clients take from that key's kind-10050 list, so the relay a
 * deployment publishes to must be on that list. And it renders the content, which is the artifact,
 * by its own rules: a client that fetches link previews, images, or embeds for links in the text
 * tells whoever wrote those links the reader's address and when they read it, and the artifact's
 * author may be hostile. A reader built for these notices shows the artifact as inert text (see
 * [encodeGateOpenNotice]).
 *
 * The notice's fields ride in the rumor's tags and its content is the artifact itself, so giving the
 * notice a kind of its own, with a reader built for it, changes this constant and the subject line —
 * not the tags a reader parses.
 */
const val GATE_OPEN_NOTICE_RUMOR_KIND = 14

/**
 * Encode [notice] as a NIP-59 gift wrap addressed to a SINGLE [recipient] (A4-6: NIP-44 encrypts to
 * exactly one recipient, so notification is pairwise — [RelayNotifier] loops this over a recipient
 * set). Mechanism, not policy: [leadKeyBytes] and which recipients exist are coach-side
 * (§REPO_SEAM); this function just builds the carrier.
 *
 * THE RUMOR is what the recipient reads once the wrap is opened ([Nip59.unwrap]). It is authored by
 * the lead key, dated [createdAt], of kind [GATE_OPEN_NOTICE_RUMOR_KIND], and its content is
 * [GateOpenNotice.artifact], verbatim. Its tags, in this order:
 *  - `["p", <recipient>]`, the receiver, as NIP-17 names one;
 *  - `["subject", "Approval requested: gate <gateId>"]`, the title a message client shows;
 *  - `["agency-gate-id", <gateId>]`, `["agency-payload-digest", <payloadDigest>]`, and
 *    `["agency-nonce", <nonce>]`: the fields an approval binds to, named so that none collides with a
 *    tag a NIP defines (`nonce` is NIP-13's proof-of-work tag).
 *
 * A READER must check what [Nip59.unwrap] cannot. Unwrap authenticates the rumor's author as the
 * seal's signer, but anyone can wrap a well-formed rumor to the operator, so a reader requires the
 * rumor's kind to be [GATE_OPEN_NOTICE_RUMOR_KIND] and its pubkey to be the lead's. It requires
 * exactly one of each `agency-` tag, and treats a rumor missing one or repeating one as no notice.
 * One gate-open can then arrive more than once: the same rumor in another wrap, or, when the lead
 * re-announces after a restart, a new rumor with a later date and so a new [Rumor.id]. Every copy
 * carries the same `agency-nonce`, which is single-use and bound to one gate and one digest, so a
 * reader deduplicates on that nonce, among notices that passed the checks above, and not on the
 * rumor's id or the wrap's. It shows the artifact as inert text and fetches nothing it names.
 *
 * A reader can check the content against [GateOpenNotice.payloadDigest]: the lead's digest is the
 * SHA-256 of the artifact's bytes in lowercase hex, so hashing the content's UTF-8 bytes reproduces
 * it, but only when those are the bytes that were hashed. Text decoded from bytes that were not
 * valid UTF-8 does not encode back to them, so for such an artifact the check fails: it refuses an
 * honest gate, rather than passing a different artifact.
 *
 * THE WRAP is what the relay stores and serves: kind [Nip59.GIFT_WRAP_KIND], signed by a single-use
 * key, with the one tag `["p", <recipient>]`. So the relay learns which key each notice is for (see
 * [RecipientKey] on which key to list), but not what the notice says, nor — from the event itself —
 * that the lead sent it; [Nip59] lists what the publishing connection shows.
 *
 * TIMESTAMPS are caller-supplied and never read as a clock (A4-3). [createdAt] is the notice time: it
 * dates the rumor, and the wrap. NIP-17 asks that the seal and the wrap both be dated up to two days
 * in the past, so that grouping wraps by `created_at` reveals nothing. But a relay may refuse any
 * event dated earlier than a lower limit it sets — NIP-11's `limitation.created_at_lower_limit` —
 * and under a limit shorter than two days, a wrap backdated as NIP-17 asks is refused: a notice
 * that never reaches the operator. So the wrap carries the notice time. Only the seal is backdated
 * (the caller passes [sealCreatedAt] already backdated): it travels encrypted, so no relay checks
 * its date. That follows NIP-59 at no cost to delivery, though it hides the notice time only from
 * someone shown the seal who cannot open it. The cost of the un-backdated wrap is that every wrap
 * of one gate-open can carry the same public date, so any reader the relay serves them to can group
 * them from the stored events — as a live subscriber can by when they arrive, and the relay by the
 * connection they arrive on. [sealAuxRandHex] and [wrapAuxRandHex] are the two signatures' aux
 * randomness: production draws them fresh, a test pins them.
 *
 * REFUSES rather than throws when the notice is too large: [Nip59.wrap] checks the serialized rumor
 * against [Nip59.RUMOR_CEILING_BYTES] before encrypting anything, and an oversize notice returns
 * [NoticeEncoding.TooLarge], so the caller records a per-recipient liveness gap, never an exception
 * surfacing from the codec.
 *
 * [leadKeyBytes] is the lead secret key as raw bytes — the seam is bytes, not a #42 `SecretKeyHex`,
 * because this codec is in `:nostr` and `SecretKeyHex` is in `:relay` (which depends on `:nostr`), so
 * taking the holder here would cycle the build. The caller owns the array: encode reads it and neither
 * retains nor zeroes it, so a clearable-key caller ([RelayNotifier]) passes `SecretKeyHex.useKeyBytes`
 * bytes and lets that zero them. The rumor's author is derived from this same key, so the seal always
 * signs a rumor its signer wrote. A malformed key is a deploy error and throws loudly out of the native
 * (as [signEvent] treats its key), never a fold-closed null; [RelayNotifier] refuses one at
 * construction, so it never reaches here mid-fan-out.
 */
fun encodeGateOpenNotice(
  leadKeyBytes: ByteArray,
  recipient: RecipientKey,
  notice: GateOpenNotice,
  createdAt: Long,
  sealCreatedAt: Long,
  sealAuxRandHex: String,
  wrapAuxRandHex: String,
): NoticeEncoding {
  val rumor =
    Rumor(
      pubkey = Bip340.xonlyPubkeyFromKeyBytes(leadKeyBytes),
      createdAt = createdAt,
      kind = GATE_OPEN_NOTICE_RUMOR_KIND,
      tags = noticeTags(recipient, notice),
      content = notice.artifact,
    )
  val encoding =
    Nip59.wrap(
      senderKey = leadKeyBytes,
      recipient = recipient,
      rumor = rumor,
      sealCreatedAt = sealCreatedAt,
      wrapCreatedAt = createdAt,
      sealAuxRandHex = sealAuxRandHex,
      wrapAuxRandHex = wrapAuxRandHex,
    )
  return when (encoding) {
    is GiftWrapEncoding.Wrapped -> NoticeEncoding.Encoded(encoding.event)
    is GiftWrapEncoding.TooLarge ->
      NoticeEncoding.TooLarge(encoding.rumorBytes, encoding.ceilingBytes)
  }
}

/** The rumor's tags, in the order [encodeGateOpenNotice] documents. */
private fun noticeTags(recipient: RecipientKey, notice: GateOpenNotice): List<List<String>> =
  listOf(
    listOf("p", recipient.hex),
    listOf("subject", noticeSubject(notice)),
    listOf("agency-gate-id", notice.gateId),
    listOf("agency-payload-digest", notice.payloadDigest),
    listOf("agency-nonce", notice.nonce),
  )

/** The notice's title for a message client (the `subject` tag NIP-17 reads as a conversation's
 * title). A reader parses the `agency-` tags, never this line, so its wording can change freely. */
private fun noticeSubject(notice: GateOpenNotice): String =
  "Approval requested: gate ${notice.gateId}"
