package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.nostr.Bip340
import com.geekinasuit.agency.nostr.SecretKeyHex
import java.io.File

/**
 * Read the secp256k1 secret key a file holds as 64 hex characters, ASCII whitespace around it
 * ignored, into a clearable holder. Read as bytes, not a String, so the key's text is only in arrays
 * this zeroes. Throws [IllegalArgumentException] for a key that is not 64 hex characters or not a
 * secp256k1 scalar (zero, or not below the curve order), clearing what it built first; and the
 * [java.io.IOException] of a file it cannot read. The message never holds the key.
 */
internal fun readSecretKeyFile(path: String): SecretKeyHex {
  val raw = File(path).readBytes()
  var start = 0
  var end = raw.size
  while (start < end && raw[start].isAsciiSpace()) start++
  while (end > start && raw[end - 1].isAsciiSpace()) end--
  val chars = CharArray(end - start) { raw[start + it].toInt().toChar() }
  try {
    val key = SecretKeyHex.ofHex(chars)
    if (!key.useKeyBytes { Bip340.isValidSecretKeyBytes(it) }) {
      key.clear()
      throw IllegalArgumentException(
        "the key is 64 hex characters but not a secp256k1 secret key (zero, or not below the curve order)"
      )
    }
    return key
  } finally {
    raw.fill(0)
    chars.fill(Char(0))
  }
}

private fun Byte.isAsciiSpace(): Boolean =
  this == ' '.code.toByte() || this == '\t'.code.toByte() || this == '\n'.code.toByte() || this == '\r'.code.toByte()

/**
 * Flags as `--name value` pairs, each from [allowed] and at most once; [IllegalArgumentException]
 * otherwise.
 */
internal fun flagsOf(args: List<String>, allowed: Set<String>): Map<String, String> {
  require(args.size % 2 == 0) { "each flag needs a value" }
  val flags = mutableMapOf<String, String>()
  for ((flag, value) in args.chunked(2)) {
    require(flag in allowed) { "'$flag' is not a flag of this command" }
    require(flags.put(flag, value) == null) { "'$flag' is given twice" }
  }
  return flags
}

internal fun Map<String, String>.required(flag: String): String =
  this[flag] ?: throw IllegalArgumentException("missing $flag")
