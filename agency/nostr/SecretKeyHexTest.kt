package com.geekinasuit.agency.nostr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The clearable secret-key holder (#42): structural validation, the defensive copy, that
 * useKeyBytes decodes the hex and zeroes its working ByteArray, and that clear() zeroes the backing
 * CharArray. Native-free; a friend of :relay (associates) so it can read the backing array directly
 * rather than through a method that could lie.
 */
class SecretKeyHexTest {
  private val validHex = "0000000000000000000000000000000000000000000000000000000000000003"

  @Test
  fun `ofHex accepts 64 hex characters and decodes to 32 bytes`() {
    SecretKeyHex.ofHex(validHex.toCharArray()).useKeyBytes { assertEquals(32, it.size) }
  }

  @Test
  fun `ofHex rejects a too-short key`() {
    try {
      SecretKeyHex.ofHex("abcd".toCharArray())
      throw AssertionError("expected an IllegalArgumentException for a short key")
    } catch (e: IllegalArgumentException) {
      assertTrue(e.message!!.contains("64 hex"))
    }
  }

  @Test
  fun `ofHex rejects a non-hex character`() {
    try {
      SecretKeyHex.ofHex("g".repeat(64).toCharArray())
      throw AssertionError("expected an IllegalArgumentException for a non-hex key")
    } catch (e: IllegalArgumentException) {
      assertTrue(e.message!!.contains("64 hex"))
    }
  }

  @Test
  fun `useKeyBytes decodes the high then the low nibble of each byte`() {
    // "abcd" repeated: byte 0 = 0xAB, byte 1 = 0xCD — a nibble swap would flip these.
    SecretKeyHex.ofHex("abcd".repeat(16).toCharArray()).useKeyBytes {
      assertEquals(0xAB.toByte(), it[0])
      assertEquals(0xCD.toByte(), it[1])
    }
  }

  @Test
  fun `ofHex holds a defensive copy, so clearing the caller's array leaves the holder intact`() {
    val caller = validHex.toCharArray()
    val key = SecretKeyHex.ofHex(caller)
    caller.fill(Char(0))
    key.useKeyBytes { assertEquals(32, it.size) }
  }

  @Test
  fun `useKeyBytes zeroes its working array after the block returns`() {
    // A key with every byte non-zero, so an un-zeroed array is unmistakably different from a zeroed one.
    var captured: ByteArray? = null
    SecretKeyHex.ofHex("abcd".repeat(16).toCharArray()).useKeyBytes { captured = it }
    assertTrue("the decoded working key must be zeroed after use", captured!!.all { it == 0.toByte() })
  }

  @Test
  fun `useKeyBytes zeroes its working array even when the block throws`() {
    var captured: ByteArray? = null
    try {
      SecretKeyHex.ofHex("abcd".repeat(16).toCharArray()).useKeyBytes {
        captured = it
        throw RuntimeException("boom")
      }
      throw AssertionError("expected the block's exception to propagate")
    } catch (e: RuntimeException) {
      assertEquals("boom", e.message)
    }
    assertTrue(
      "the decoded working key must be zeroed even when the block throws",
      captured!!.all { it == 0.toByte() },
    )
  }

  @Test
  fun `clear zeroes the backing hex`() {
    val key = SecretKeyHex.ofHex(validHex.toCharArray())
    key.clear()
    assertTrue("clear() must overwrite every backing hex character", key.hexChars.all { it == Char(0) })
  }

  @Test
  fun `toString does not reveal the key`() {
    val rendered = SecretKeyHex.ofHex("deadbeef".repeat(8).toCharArray()).toString()
    assertFalse("toString must not contain key material", rendered.contains("deadbeef"))
    assertTrue("toString should mark the key redacted", rendered.contains("redacted"))
  }
}
