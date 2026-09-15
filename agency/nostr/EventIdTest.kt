package com.geekinasuit.agency.nostr

import java.security.MessageDigest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonArray
import kotlinx.serialization.json.buildJsonArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * The load-bearing test for the codec: the event id is checked against a preimage this codec did
 * NOT produce, so the wire format is pinned to something external, not to itself.
 *
 * Two independent oracles, because a self-serialized round-trip proves only internal
 * consistency:
 *  - a DIFFERENT serializer (kotlinx-serialization) builds the `[0,pubkey,created_at,kind,tags,
 *    content]` array for the common + escaped + non-ASCII path, where JSON escaping and NIP-01
 *    escaping agree; the id must equal `sha256` of THAT.
 *  - a hand-written literal for the one place NIP-01 and a JSON library DIVERGE: a raw C0 control
 *    character that is not one of NIP-01's five named escapes must be emitted verbatim (a JSON
 *    library would escape it to a backslash-u sequence). This is what proves the codec implements
 *    NIP-01's "no other character is escaped" rule rather than delegating to a JSON encoder.
 */
class EventIdTest {
  private fun sha256Hex(s: String): String =
    MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8)).joinToString("") {
      "%02x".format(it)
    }

  /** An independent NIP-01 preimage via kotlinx-serialization — a different code path than
   * [Nip01.preimage]. Valid only where JSON and NIP-01 escaping coincide (all five named escapes,
   * backslash, quote, and any non-ASCII), which is every character in the events below. */
  private fun independentPreimage(
    pubkey: String,
    createdAt: Long,
    kind: Int,
    tags: List<List<String>>,
    content: String,
  ): String {
    val arr =
      buildJsonArray {
        add(0)
        add(pubkey)
        add(createdAt)
        add(kind)
        addJsonArray { tags.forEach { tag -> addJsonArray { tag.forEach { add(it) } } } }
        add(content)
      }
    return Json.encodeToString(JsonArray.serializer(), arr)
  }

  @Test
  fun `event id equals sha256 of an independently serialized preimage`() {
    val pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    val createdAt = 1700000000L
    val kind = 1
    val tags = listOf(listOf("e", "3da9790a7f30"), listOf("p", pubkey))
    // Exercises the escaper: an embedded quote, a newline, a tab, and a non-ASCII code point.
    val content = "say \"hi\"\n\t— café ☕"

    val independent = independentPreimage(pubkey, createdAt, kind, tags, content)
    // The codec's own serialization must be byte-for-byte the independent one on this path.
    assertEquals(independent, Nip01.preimage(pubkey, createdAt, kind, tags, content))
    // And the id must be the hash of that external preimage, not of the codec's own output.
    assertEquals(sha256Hex(independent), Nip01.eventId(pubkey, createdAt, kind, tags, content))
  }

  @Test
  fun `NIP-01 escapes only its five named C0 controls, leaving other controls raw`() {
    // 0x01 is a control character NIP-01 does NOT name, so it must be emitted verbatim, where a
    // JSON library would escape it to a backslash-u sequence. Char(1) builds the byte so this
    // source stays free of a raw control character.
    val ctrl = 1.toChar()
    val content = "a${ctrl}b"
    val expected = "[0,\"pk\",1,1,[],\"a${ctrl}b\"]"
    assertEquals(expected, Nip01.preimage("pk", 1L, 1, emptyList(), content))
    assertEquals(sha256Hex(expected), Nip01.eventId("pk", 1L, 1, emptyList(), content))
  }

  @Test
  fun `the five named C0 controls escape to their short forms`() {
    // backspace 0x08, tab 0x09, newline 0x0A, form feed 0x0C, carriage return 0x0D.
    val ff = 0x0C.toChar()
    val content = "\b\t\n${ff}\r"
    val expected = "[0,\"pk\",1,1,[],\"\\b\\t\\n\\f\\r\"]"
    assertEquals(expected, Nip01.preimage("pk", 1L, 1, emptyList(), content))
  }

  @Test
  fun `changing any field changes the id`() {
    val base = Nip01.eventId("pk", 1L, 1, listOf(listOf("e", "x")), "hi")
    assertNotEquals(base, Nip01.eventId("pk2", 1L, 1, listOf(listOf("e", "x")), "hi"))
    assertNotEquals(base, Nip01.eventId("pk", 2L, 1, listOf(listOf("e", "x")), "hi"))
    assertNotEquals(base, Nip01.eventId("pk", 1L, 2, listOf(listOf("e", "x")), "hi"))
    assertNotEquals(base, Nip01.eventId("pk", 1L, 1, listOf(listOf("e", "y")), "hi"))
    assertNotEquals(base, Nip01.eventId("pk", 1L, 1, listOf(listOf("e", "x")), "ho"))
  }
}
