package com.geekinasuit.agency.shared.text

import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * The UTF-8 encoding of [s], or `null` if [s] holds an unpaired surrogate and so has none. Encoded
 * strictly, because `String.toByteArray` would write `?` for the surrogate, and two different strings
 * would then encode to the same bytes. A fresh encoder per call: a CharsetEncoder is not thread-safe.
 */
fun utf8OrNull(s: String): ByteArray? =
  try {
    val encoded =
      Charsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .encode(CharBuffer.wrap(s))
    ByteArray(encoded.remaining()).also { encoded.get(it) }
  } catch (_: CharacterCodingException) {
    null
  }

/** Whether [s] has a UTF-8 encoding, that is, holds no unpaired surrogate ([utf8OrNull]). */
fun hasUtf8Encoding(s: String): Boolean = utf8OrNull(s) != null
