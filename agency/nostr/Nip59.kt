package com.geekinasuit.agency.nostr

import com.geekinasuit.agency.shared.json.jsonMayNestDeeperThan
import java.security.SecureRandom

/**
 * A NIP-59 rumor: a nostr event that is never signed. NIP-59 seals a rumor rather than a signed event
 * so that a rumor leaked on its own proves nothing about who wrote it — only the seal around it is
 * signed. That deniability does not hold against the recipient, who can prove the authorship to anyone
 * by disclosing the seal and the conversation key that opens it. The [id] is COMPUTED from the fields,
 * never supplied, so it cannot disagree with them, and a rumor that would have no id (a string holding
 * an unpaired surrogate, see [Nip01.eventId]) cannot be constructed. The check runs on the lists
 * the caller passes, which the rumor keeps rather than copies, so a caller must not change [tags]
 * after construction: a tag changed to hold an unpaired surrogate leaves the rumor with no id, and
 * [id], `serialize()` and [Nip59.wrap] then throw. A rumor has no `sig`, so it is not a
 * [NostrEvent] and cannot be handed to [eventMessage] and published bare.
 */
data class Rumor(
  val pubkey: String,
  val createdAt: Long,
  val kind: Int,
  val tags: List<List<String>>,
  val content: String,
) {
  init {
    require(kind in 0..65535) { "a NIP-01 kind is 0..65535, was $kind" }
    require(idStringsHaveUtf8Encoding(pubkey, tags, content)) {
      "a rumor string holds an unpaired surrogate: it has no UTF-8 encoding, so the rumor has no NIP-01 id"
    }
  }

  /** The NIP-01 event id of the fields. */
  val id: String
    get() = Nip01.eventId(pubkey, createdAt, kind, tags, content)
}

/**
 * The result of wrapping a rumor for ONE recipient: the gift wrap, ready to publish, or a typed
 * refusal because the rumor is too large to encrypt twice. A refusal, never a throw — see
 * [Nip59.wrap].
 */
sealed interface GiftWrapEncoding {
  /** The kind-1059 gift wrap, signed by a single-use key and addressed to the recipient. */
  data class Wrapped(val event: NostrEvent) : GiftWrapEncoding

  /** The serialized rumor is [rumorBytes] UTF-8 bytes, over the [ceilingBytes] a gift wrap can carry
   * ([Nip59.RUMOR_CEILING_BYTES]). */
  data class TooLarge(val rumorBytes: Int, val ceilingBytes: Int) : GiftWrapEncoding
}

/**
 * NIP-59 gift wrap: a rumor sealed by its author, then wrapped by a single-use key, so the event a
 * relay stores names its recipient but not its sender.
 *
 * THREE LAYERS, each hiding the one inside it:
 *  - the RUMOR ([Rumor]) is the content, unsigned;
 *  - the SEAL (kind [SEAL_KIND]) is the rumor NIP-44-encrypted to the recipient and SIGNED BY THE
 *    SENDER. It is the only layer that authenticates who sent the rumor. Only the recipient can open
 *    it, but the proof is transferable: the recipient can show it to anyone by disclosing the seal and
 *    the conversation key. NIP-59 requires its tags to be empty, so it carries nothing in clear;
 *  - the GIFT WRAP (kind [GIFT_WRAP_KIND]) is the seal's JSON NIP-44-encrypted to the recipient and
 *    signed by a key drawn for this wrap alone, so its signature ties it to no other event. It is the
 *    only layer a relay sees.
 *
 * DISCLOSURE — what a relay still learns:
 *  - the RECIPIENT, from a cleartext `p` tag. NIP-59 says a wrap SHOULD carry what routes it to its
 *    recipient, the `p` tag included, and relays route and gate reads by that tag, so [wrap] always
 *    adds one. A deployment that must not show the relay a long-lived identity addresses a key it
 *    dedicates to this purpose;
 *  - the wrap's `created_at`, and the length of its content, which bounds the rumor's size to within
 *    NIP-44's padding;
 *  - whatever the PUBLISHING CONNECTION shows. The single-use key hides the sender only from readers
 *    of the event: the relay that accepts it also sees the connection that sent it — its network
 *    address, the identity it authenticated as (NIP-42) if any, and when it arrived — so wraps one
 *    sender publishes can be linked to each other and to that sender there.
 *
 * Every reader the relay serves the wrap to learns the first two as well. NIP-59 recommends that a
 * relay serve a gift wrap only to the pubkey its `p` tag names, behind NIP-42 AUTH, but that is the
 * relay's policy and nothing here can check it: a relay that does not follow it serves the wrap to any
 * subscriber.
 *
 * TWO TRUST BOUNDARIES, as in [Nip44]. [wrap] consumes our own rumor: a local bug (a rumor the sender
 * key did not author) throws, and an oversize rumor is a typed [GiftWrapEncoding.TooLarge], checked
 * before anything is encrypted. [unwrap] consumes hostile relay events — anyone can address a wrap to
 * the recipient — so it is TOTAL over the event and folds every defect to `null`.
 *
 * TIMESTAMPS are caller-supplied and never read as a clock (A4-3). NIP-59 suggests backdating both
 * the seal's and the wrap's `created_at` by a random amount to blur timing; that policy is the
 * caller's. The seal's timestamp travels encrypted, so no relay ever checks it; the wrap's is public,
 * and a relay may refuse an event dated earlier than a lower limit it sets (NIP-11 advertises it as
 * `limitation.created_at_lower_limit`), so a backdated wrap can be refused where a seal cannot.
 */
object Nip59 {
  /** The seal's kind (NIP-59). */
  const val SEAL_KIND = 13

  /** The gift wrap's kind (NIP-59). A REGULAR kind (NIP-01: `1000 ≤ n < 10000`), so a relay stores
   * it and a recipient that was offline when it was published fetches it later. */
  const val GIFT_WRAP_KIND = 1059

  /**
   * The largest serialized rumor, in UTF-8 bytes, that a gift wrap can carry. The rumor is encrypted
   * into the seal and the seal's JSON into the wrap, and NIP-44 caps every plaintext at 65,535 bytes;
   * the seal's JSON is the larger of the two. Above 32 KiB NIP-44 pads a plaintext up to a multiple of
   * 8,192 bytes, so a rumor of 40,960 bytes or fewer yields a seal JSON of about 55 KB, while one byte
   * more pads to 49,152 and yields about 66 KB — over the cap whatever the seal's timestamp.
   * `Nip59Test` measures both sides of that boundary.
   */
  const val RUMOR_CEILING_BYTES = 40_960

  // The deepest any field of a NIP-01 event nests: the object, its tags array, one tag. Decrypted
  // plaintext that nests deeper cannot be a well-formed seal or rumor, so unwrap refuses it before
  // the parser — which recurses once per level — can spend the stack on it.
  private const val MAX_EVENT_JSON_DEPTH = 3

  // NIP-01 spells a pubkey as 64 lowercase hex characters. Hex.decode also reads other spellings of
  // the same bytes (uppercase, and anything else digitToInt accepts as a hex digit), so a signature
  // verifies under any of them; unwrap admits only this one, so the pubkey it returns is canonical.
  private val CANONICAL_PUBKEY = Regex("[0-9a-f]{64}")

  // One CSPRNG for the single-use wrap keys; SecureRandom is thread-safe, as in Nip44.
  private val secureRandom = SecureRandom()

  /**
   * Seal [rumor] as [senderKey] and gift-wrap it to [recipient]. NIP-44 encrypts to exactly one
   * recipient, so a caller notifying several wraps once per recipient.
   *
   * REFUSES rather than throws when the rumor is too large: its UTF-8 size is checked against
   * [RUMOR_CEILING_BYTES] before anything is encrypted. THROWS [IllegalArgumentException] if [rumor]'s
   * pubkey is not [senderKey]'s: the recipient's impersonation check would refuse the result, so it
   * is a local bug, not a wrap to send.
   *
   * [senderKey] is raw bytes the caller owns; wrap reads it and neither retains nor zeroes it (as
   * [encodeGateOpenNotice] treats its key). The wrap key is drawn fresh from a CSPRNG on every call
   * and zeroed after use, as are the conversation keys derived here; no caller can supply or reuse
   * one. The zeroing is best-effort hygiene, not a guarantee that no key material remains in memory:
   * [Nip44.conversationKey]'s own intermediates, from which a conversation key can be re-derived, are
   * not zeroed. The timestamps and the two aux-randomness values are caller-supplied for the reason
   * [signEvent] takes them: production draws them fresh, a test pins them.
   */
  fun wrap(
    senderKey: ByteArray,
    recipient: RecipientKey,
    rumor: Rumor,
    sealCreatedAt: Long,
    wrapCreatedAt: Long,
    sealAuxRandHex: String,
    wrapAuxRandHex: String,
  ): GiftWrapEncoding {
    require(rumor.pubkey == Bip340.xonlyPubkeyFromKeyBytes(senderKey)) {
      "the rumor's pubkey must be the sender key's: a recipient refuses a rumor its seal's signer did not author"
    }
    val rumorJson = rumor.serialize()
    val rumorBytes = rumorJson.toByteArray(Charsets.UTF_8).size
    if (rumorBytes > RUMOR_CEILING_BYTES) {
      return GiftWrapEncoding.TooLarge(rumorBytes, RUMOR_CEILING_BYTES)
    }
    val recipientPubkey = Hex.decode(recipient.hex)
    val seal =
      signEvent(
        secretKey = senderKey,
        createdAt = sealCreatedAt,
        kind = SEAL_KIND,
        tags = emptyList(),
        content = encrypt(rumorJson, senderKey, recipientPubkey),
        auxRandHex = sealAuxRandHex,
      )
    val sealJson = seal.serialize()
    val wrap =
      freshWrapKey().zeroedAfter { wrapKey ->
        signEvent(
          secretKey = wrapKey,
          createdAt = wrapCreatedAt,
          kind = GIFT_WRAP_KIND,
          tags = listOf(listOf("p", recipient.hex)),
          content = encrypt(sealJson, wrapKey, recipientPubkey),
          auxRandHex = wrapAuxRandHex,
        )
      }
    return GiftWrapEncoding.Wrapped(wrap)
  }

  /**
   * Open a gift wrap encrypted to [recipientKey]'s pubkey and return its rumor, or `null` if it is not
   * a well-formed wrap for this recipient. TOTAL over [wrap]: a wrong kind, a bad signature on either
   * layer, a payload that does not decrypt, plaintext that is not an event, a seal carrying tags or
   * spelling its pubkey other than as NIP-01's lowercase hex, a rumor whose claimed id is not its own,
   * and a rumor whose author is not the seal's signer (NIP-17's impersonation check) all fold to
   * `null`, never a throw.
   *
   * The returned rumor's [Rumor.pubkey] is AUTHENTICATED: it equals the seal's signer, whose signature
   * was verified, in the canonical spelling — so it string-equals any canonical spelling of that key.
   * Nothing else about the rumor is — its timestamp, kind, tags, and content are whatever that signer
   * chose to send.
   *
   * Nothing in the wrap's own envelope is authenticated either: its signature proves only possession
   * of a single-use key, whose holder chose the wrap's `created_at` and tags. So unwrap checks neither,
   * the `p` tag included. The recipient is bound by the encryption instead: a wrap encrypted to any
   * other key does not decrypt under [recipientKey]. It follows that anyone holding a seal to this
   * recipient can wrap it again, and unwrap returns the same rumor each time, so a caller that
   * deduplicates must key on the rumor's [Rumor.id], never on the wrap's.
   *
   * Each layer's signature is verified BEFORE its pubkey enters the key agreement, so a malformed or
   * off-curve pubkey fails verification and never reaches [Nip44.conversationKey], which throws on
   * one. Each decrypted plaintext is depth-checked BEFORE it is parsed: it crossed the transport as
   * base64 inside the event's content, so the transport's own nesting bound never saw its structure.
   * [recipientKey] is ours, so a malformed one throws.
   */
  fun unwrap(recipientKey: ByteArray, wrap: NostrEvent): Rumor? {
    require(Bip340.isValidSecretKeyBytes(recipientKey)) {
      "the recipient key must be a valid secp256k1 secret key: 32 bytes naming a scalar in [1, n-1]"
    }
    if (wrap.kind != GIFT_WRAP_KIND || !wrap.verify()) return null
    val seal = decryptAndParse(recipientKey, wrap.pubkey, wrap.content, ::parseEvent) ?: return null
    if (seal.kind != SEAL_KIND || seal.tags.isNotEmpty()) return null
    if (!CANONICAL_PUBKEY.matches(seal.pubkey) || !seal.verify()) return null
    val rumor = decryptAndParse(recipientKey, seal.pubkey, seal.content, ::parseRumor) ?: return null
    return rumor.takeIf { it.pubkey == seal.pubkey }
  }

  /** NIP-44-encrypt [plaintext] from [ourKey] to [theirPubkey], zeroing the conversation key after. */
  private fun encrypt(plaintext: String, ourKey: ByteArray, theirPubkey: ByteArray): String =
    Nip44.conversationKey(ourKey, theirPubkey).zeroedAfter { Nip44.encrypt(plaintext, it) }

  /** Decrypt [payload] from [senderPubkeyHex] to [recipientKey] and [parse] it — or `null` if it does
   * not decrypt, nests deeper than any event field, or does not parse. [senderPubkeyHex] must already
   * have passed signature verification; that is what makes it safe to decode and agree a key with. */
  private fun <T> decryptAndParse(
    recipientKey: ByteArray,
    senderPubkeyHex: String,
    payload: String,
    parse: (String) -> T?,
  ): T? {
    val plaintext =
      Nip44.conversationKey(recipientKey, Hex.decode(senderPubkeyHex)).zeroedAfter {
        Nip44.decrypt(payload, it)
      } ?: return null
    if (jsonMayNestDeeperThan(plaintext, MAX_EVENT_JSON_DEPTH)) return null
    return parse(plaintext)
  }

  private fun freshWrapKey(): ByteArray {
    val key = ByteArray(32)
    // 32 uniformly random bytes fall outside [1, n-1] with probability about 2^-128; redraw rather
    // than reduce, so the key stays uniform.
    do {
      secureRandom.nextBytes(key)
    } while (!Bip340.isValidSecretKeyBytes(key))
    return key
  }
}

/** Runs [block] on this key material, then zeroes it — whether [block] returns or throws. */
private inline fun <T> ByteArray.zeroedAfter(block: (ByteArray) -> T): T =
  try {
    block(this)
  } finally {
    fill(0)
  }
