package com.geekinasuit.agency.nostr

/**
 * A clearable holder for a 64-character hex secret key.
 *
 * The lead's Nostr secret key must not sit in a long-lived immutable [String]: a [String] cannot be
 * overwritten and lives on the heap at the garbage collector's discretion, so the plaintext key
 * stays resident for as long as the holding object is reachable. This type holds the hex as a
 * mutable [CharArray] that [clear] overwrites, and yields the decoded key bytes only for the span of
 * a signing call — [useKeyBytes] zeroes that working [ByteArray] before it returns. It never renders
 * the key: [toString] is redacted, the same posture RelayConfig takes.
 *
 * Structural validation only (64 hex characters). That the key names a valid secp256k1 scalar is
 * proven by the native at signing time and classified there, so construction stays native-free.
 *
 * The JVM cannot guarantee no plaintext copy ever exists — interning, the JIT, and array copies are
 * outside our control. This narrows the exposure to a clearable working set; it does not erase the
 * key absolutely.
 */
class SecretKeyHex private constructor(
  // Mutable, and internal so a friend test can observe that clear()/useKeyBytes zeroed it — module
  // visibility, not print visibility: the redacted toString is what keeps the key out of logs.
  internal val hexChars: CharArray,
) {
  /**
   * Decode the key to a fresh [ByteArray], run [block] with it, and zero that array before
   * returning — whether [block] returns or throws. The bytes exist only for the call; [block] must
   * not retain the array.
   */
  fun <T> useKeyBytes(block: (ByteArray) -> T): T {
    val bytes = decodeHex(hexChars)
    try {
      return block(bytes)
    } finally {
      bytes.fill(0)
    }
  }

  /**
   * Overwrite the held hex with NUL. Idempotent; a holder cleared while a connection is still open
   * fails its next sign closed (decode rejects the zeroed chars) rather than signing a zeroed key.
   */
  fun clear() {
    hexChars.fill(Char(0))
  }

  override fun toString(): String = "SecretKeyHex(<redacted>)"

  companion object {
    /**
     * Wrap a defensive copy of [hex] (64 hex characters). The caller keeps ownership of [hex] and
     * may clear its own array; this holder holds an independent copy.
     */
    fun ofHex(hex: CharArray): SecretKeyHex {
      require(hex.size == 64 && hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
        "secret key must be 64 hex characters (a 32-byte secret key)"
      }
      return SecretKeyHex(hex.copyOf())
    }

    /**
     * Convenience for a caller that already holds the key as a [String]. That [String] is the
     * caller's to manage — this only copies its characters into a clearable holder; a caller that
     * wants no [String] in play at all should assemble a [CharArray] and call [ofHex].
     */
    fun ofHexString(hex: String): SecretKeyHex = ofHex(hex.toCharArray())

    // Hex decode over a CharArray, deliberately NOT Bip340's internal Hex: that decodes a String and
    // is internal to the codec module, so reusing it would force the key back through a String and
    // widen the codec's API. Two nibbles per byte, no String on the path.
    private fun decodeHex(chars: CharArray): ByteArray {
      val out = ByteArray(chars.size / 2)
      for (i in out.indices) {
        out[i] = ((nibble(chars[i * 2]) shl 4) or nibble(chars[i * 2 + 1])).toByte()
      }
      return out
    }

    private fun nibble(c: Char): Int =
      when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw IllegalArgumentException("secret key must be 64 hex characters (a 32-byte secret key)")
      }
  }
}
