package com.geekinasuit.agency.nostr

import fr.acinq.secp256k1.Secp256k1

/**
 * The BIP-340 schnorr primitive, over the libsecp256k1 bindings the step-0 probe validated
 * against the spec's own vectors (agency/crypto). It exposes two kinds of operation, both minimal
 * by intent. The fixed-32 SIGN/VERIFY path — `schnorrsig_sign32` and its verify — serves the two
 * callers that need signatures: the nostr event codec (a 32-byte NIP-01 id) and
 * [Bip340ApprovalVerifier] (a 32-byte authorization digest); nostr never signs a variable-length
 * message, so no other signing surface exists. And two VALIDITY predicates, [isXonlyPubkey] and
 * [isValidSecretKey], let a config boundary (`RecipientKey.of`, `RelayNotifier`'s init) refuse a
 * malformed public or secret key up front rather than let it throw out of the crypto phase later.
 *
 * [verifyBytes] is TOTAL: a malformed key, signature, or message folds to `false`, never a
 * throw out of the native layer. Fail-closed is the only safe default for a verifier — a
 * verification that cannot run is not a pass — and it matches how the probe treats a native
 * refusal (return or throw are both "refused").
 */
object Bip340 {
  private val secp = Secp256k1.get()

  /** The x-only (32-byte) public key for a secret key, as lowercase hex. `pubkeyCreate` returns
   * a 65-byte uncompressed point; BIP-340 names a key by its 32-byte x coordinate alone. */
  fun xonlyPubkeyHex(secretKeyHex: String): String {
    val full = secp.pubkeyCreate(Hex.decode(secretKeyHex))
    return Hex.encode(full.copyOfRange(1, 33))
  }

  /** Sign a 32-byte message (hex) with a secret key (hex) and 32 bytes of aux randomness (hex),
   * returning the 64-byte signature as lowercase hex. Callers pass the event id or a digest as
   * the message; supplying aux randomness is the caller's choice so tests can be deterministic. */
  fun signHex(msg32Hex: String, secretKeyHex: String, auxRandHex: String): String =
    Hex.encode(secp.signSchnorr(Hex.decode(msg32Hex), Hex.decode(secretKeyHex), Hex.decode(auxRandHex)))

  /** Verify a signature (hex) over a 32-byte message (hex) under an x-only public key (hex).
   * Total: any decode or native failure returns `false`. */
  fun verify(sigHex: String, msg32Hex: String, pubkeyXonlyHex: String): Boolean =
    try {
      verifyBytes(Hex.decode(sigHex), Hex.decode(msg32Hex), Hex.decode(pubkeyXonlyHex))
    } catch (_: Exception) {
      false
    }

  /** Verify over raw bytes — the entry the approval verifier uses, since its message is a
   * freshly computed digest, not hex. Total: a native refusal (return or throw) is `false`. */
  fun verifyBytes(sig: ByteArray, msg32: ByteArray, pubkeyXonly: ByteArray): Boolean =
    try {
      secp.verifySchnorr(sig, msg32, pubkeyXonly)
    } catch (_: Exception) {
      false
    }

  /** True iff [xonlyHex] is a valid secp256k1 x-only public key — 32 bytes naming a real point on
   * the curve, not merely 64 hex characters. NIP-44 and the nostr codec lift an x-only key to its
   * even-y point (`0x02 || x`); a hex value off the curve or beyond the field prime cannot be
   * lifted, so every ECDH or verify against it fails. Total: any decode or native failure is
   * `false`, so a caller can treat it as a pure validity predicate. */
  fun isXonlyPubkey(xonlyHex: String): Boolean =
    try {
      val x = Hex.decode(xonlyHex)
      if (x.size != 32) {
        false
      } else {
        val compressed = ByteArray(33)
        compressed[0] = 0x02
        x.copyInto(compressed, destinationOffset = 1)
        secp.pubkeyParse(compressed)
        true
      }
    } catch (_: Exception) {
      false
    }

  /** True iff [secretKeyHex] is a valid secp256k1 secret key — 32 bytes naming a scalar in
   * [1, n-1], not merely 64 hex characters. That range is exactly what EVERY native consumer of a
   * secret key on this surface requires: `pubkeyCreate` (an event's pubkey field, via
   * [xonlyPubkeyHex]), `signSchnorr` (its signature, via [signHex]), and `pubKeyTweakMul` — the
   * scalar in NIP-44's ECDH ([Nip44.sharedPointX]). All three accept a scalar iff it lies in
   * [1, n-1] and reject it otherwise, so a key this predicate admits cannot throw out of any of
   * them, and one it rejects would throw out of all of them. Checked with `pubkeyCreate` because
   * that is libsecp256k1's canonical range gate; total — any decode or native failure is `false`,
   * so a caller can treat it as a pure validity predicate, the mirror of [isXonlyPubkey] for a
   * public key. */
  fun isValidSecretKey(secretKeyHex: String): Boolean =
    try {
      val k = Hex.decode(secretKeyHex)
      if (k.size != 32) {
        false
      } else {
        secp.pubkeyCreate(k)
        true
      }
    } catch (_: Exception) {
      false
    }
}

/** Lowercase-hex codec, internal to this module. [decode] throws on odd length or a non-hex
 * digit; every caller that must stay total wraps it (see [Bip340.verify]). */
internal object Hex {
  fun decode(s: String): ByteArray {
    require(s.length % 2 == 0) { "odd-length hex string" }
    return ByteArray(s.length / 2) { i ->
      ((s[i * 2].digitToInt(16) shl 4) or s[i * 2 + 1].digitToInt(16)).toByte()
    }
  }

  fun encode(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}
