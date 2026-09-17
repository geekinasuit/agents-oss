package com.geekinasuit.agency.nostr

import java.security.MessageDigest

/**
 * A nostr event (NIP-01). This is the TRANSPORT layer of the 3-way ceremony — it answers WHO
 * SAID THIS (the event's own [id] + [sig]), never WHETHER THIS SHOULD RELEASE. The
 * authorization layer is separate: an approval's own detached signature over its committed
 * preimage, re-verified by the fold against the allow-list, which never sees a nostr type.
 *
 * [createdAt] is CARRIED — it is part of the id preimage, so the codec must serialize it — but
 * it is NEVER READ as a clock. Nothing in this module orders, deduplicates, or expires on it; a
 * hostile relay setting it to anything at all changes only the id it helps compute, and the
 * journal stays the source of truth for time (A4-3). It is a `Long` of unix seconds solely
 * because NIP-01 puts a number in that position of the preimage.
 */
data class NostrEvent(
  val id: String,
  val pubkey: String,
  val createdAt: Long,
  val kind: Int,
  val tags: List<List<String>>,
  val content: String,
  val sig: String,
)

/**
 * The NIP-01 serialization and id. The id is `sha256` of the canonical preimage
 * `[0,pubkey,created_at,kind,tags,content]` — a compact UTF-8 JSON array, no whitespace, with
 * exactly the escapes NIP-01 mandates and no others. The serialization is built BY HAND rather
 * than delegated to a JSON library on purpose: NIP-01 forbids escaping any character outside its
 * list (a library that `\u`-escapes an incidental control character would compute a different id
 * for the same event), and the id is the thing every other implementation must agree with byte
 * for byte.
 */
object Nip01 {
  /** The canonical preimage the [eventId] hashes. Exposed so a test can pin it against a
   * hand-written literal — the serialization is checked against an external transcription, not
   * against the hash it feeds. */
  fun preimage(
    pubkey: String,
    createdAt: Long,
    kind: Int,
    tags: List<List<String>>,
    content: String,
  ): String {
    val sb = StringBuilder()
    sb.append("[0,")
    appendString(sb, pubkey)
    sb.append(',').append(createdAt).append(',').append(kind).append(',')
    appendTags(sb, tags)
    sb.append(',')
    appendString(sb, content)
    sb.append(']')
    return sb.toString()
  }

  /** The event id: lowercase hex of `sha256(preimage)`. */
  fun eventId(
    pubkey: String,
    createdAt: Long,
    kind: Int,
    tags: List<List<String>>,
    content: String,
  ): String =
    Hex.encode(
      MessageDigest.getInstance("SHA-256")
        .digest(preimage(pubkey, createdAt, kind, tags, content).toByteArray(Charsets.UTF_8))
    )

  private fun appendTags(sb: StringBuilder, tags: List<List<String>>) {
    sb.append('[')
    for ((i, tag) in tags.withIndex()) {
      if (i > 0) sb.append(',')
      sb.append('[')
      for ((j, element) in tag.withIndex()) {
        if (j > 0) sb.append(',')
        appendString(sb, element)
      }
      sb.append(']')
    }
    sb.append(']')
  }

  /** Append a JSON string with NIP-01 escaping: backslash, double-quote, and the five named C0
   * controls (0x0A \n, 0x0D \r, 0x09 \t, 0x08 \b, 0x0C \f). Every other character — including
   * other control characters and all non-ASCII — is emitted verbatim as UTF-8, because NIP-01
   * says no other character is escaped. Form feed is matched by code point because Kotlin has no
   * `\f` char escape. */
  private fun appendString(sb: StringBuilder, s: String) {
    sb.append('"')
    for (c in s) {
      when {
        c == '\\' -> sb.append("\\\\")
        c == '"' -> sb.append("\\\"")
        c == '\n' -> sb.append("\\n")
        c == '\r' -> sb.append("\\r")
        c == '\t' -> sb.append("\\t")
        c == '\b' -> sb.append("\\b")
        c.code == 0x0C -> sb.append("\\f")
        else -> sb.append(c)
      }
    }
    sb.append('"')
  }
}

/**
 * Sign a new event: derive the x-only pubkey from [secretKeyHex], compute the NIP-01 id over the
 * fields, and sign that id. [auxRandHex] is the 32 bytes of BIP-340 aux randomness (a caller
 * supplies it so tests are deterministic; production supplies fresh randomness).
 */
fun signEvent(
  secretKeyHex: String,
  createdAt: Long,
  kind: Int,
  tags: List<List<String>>,
  content: String,
  auxRandHex: String,
): NostrEvent = signEvent(Hex.decode(secretKeyHex), createdAt, kind, tags, content, auxRandHex)

/**
 * [signEvent] over key bytes the caller already holds — the clearable-key path (a #42 [SecretKeyHex]
 * yields its bytes just for the signing call). Produces the identical event to the hex overload for
 * the same key; only the secret key's representation differs.
 */
fun signEvent(
  secretKey: ByteArray,
  createdAt: Long,
  kind: Int,
  tags: List<List<String>>,
  content: String,
  auxRandHex: String,
): NostrEvent {
  val pubkey = Bip340.xonlyPubkeyFromKeyBytes(secretKey)
  val id = Nip01.eventId(pubkey, createdAt, kind, tags, content)
  val sig = Bip340.signWithKeyBytes(id, secretKey, auxRandHex)
  return NostrEvent(id, pubkey, createdAt, kind, tags, content, sig)
}

/**
 * Verify an event as it arrives from an untrusted relay: recompute the id from the fields and
 * refuse if the claimed [NostrEvent.id] does not match (a relay cannot pin a different id to the
 * same content), then verify the [NostrEvent.sig] over that id under [NostrEvent.pubkey]. Total —
 * any malformed field folds to `false`. Proves WHO signed; it does not and must not decide
 * whether a release is authorized.
 */
fun NostrEvent.verify(): Boolean {
  val recomputed = Nip01.eventId(pubkey, createdAt, kind, tags, content)
  if (recomputed != id) return false
  return Bip340.verify(sig, id, pubkey)
}
