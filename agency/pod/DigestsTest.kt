package com.geekinasuit.agency.pod

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DigestsTest {

  @Test
  fun aStringDigestIsTheDigestOfItsUtf8Bytes() {
    val text = "caf" + Char(0xE9) + String(Character.toChars(0x1F600))
    assertEquals(sha256HexBytes(text.toByteArray(Charsets.UTF_8)), sha256Hex(text))
  }

  @Test
  fun aStringHoldingAnUnpairedSurrogateHasNoDigest() {
    // The lenient encoding would give it the digest of "a?b".
    val refused =
      try {
        sha256Hex("a" + Char(0xD800) + "b")
        null
      } catch (e: IllegalArgumentException) {
        e
      }
    assertTrue("an unpaired surrogate is refused", refused != null)
  }
}
