package com.geekinasuit.agency.nostr

import fr.acinq.secp256k1.Secp256k1

/**
 * The BIP-340 schnorr primitive, over the libsecp256k1 bindings the step-0 probe validated
 * against the spec's own vectors (agency/crypto). Two callers in this module: the nostr event
 * codec signs/verifies a 32-byte event id (NIP-01), and [Bip340ApprovalVerifier] verifies an
 * authorization signature over a 32-byte digest. Both are the fixed-32 path — `schnorrsig_sign32`
 * and its verify — which is the whole requirement here (nostr signs a 32-byte id, never a
 * variable-length message), so this wrapper deliberately exposes nothing else.
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
