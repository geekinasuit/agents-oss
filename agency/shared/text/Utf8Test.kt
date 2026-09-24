package com.geekinasuit.agency.shared.text

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Utf8Test {

  // A high surrogate, which opens a pair, and a low one, which closes it.
  private val high = Char(0xD800)
  private val low = Char(0xDC00)

  @Test
  fun textWithoutAnUnpairedSurrogateEncodesAsTheLenientEncoderDoes() {
    val texts =
      listOf("", "abc", "caf" + Char(0xE9), String(Character.toChars(0x1F600)), high.toString() + low)
    for (s in texts) {
      assertArrayEquals(s, s.toByteArray(Charsets.UTF_8), utf8OrNull(s))
      assertTrue(s, hasUtf8Encoding(s))
    }
  }

  @Test
  fun textHoldingAnUnpairedSurrogateHasNoEncoding() {
    // A lone high, a lone low, a low before a high (not a pair), and a high at the very end.
    val texts = listOf("a" + high + "b", "a" + low + "b", low.toString() + high, "x" + high)
    for (s in texts) {
      assertNull(utf8OrNull(s))
      assertFalse(hasUtf8Encoding(s))
    }
  }
}
