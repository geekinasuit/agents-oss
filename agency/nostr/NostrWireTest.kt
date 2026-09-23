package com.geekinasuit.agency.nostr

import kotlin.random.Random
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The wire codec, native-free: serialization key-order and escaping, TOTAL parsing over hostile
 * relay input, and the relay-message envelopes. No signing here — parsing structures bytes and
 * makes no trust decision, so these events are plain literals with placeholder hex; the
 * signature-bearing cells live in [NostrWireSignTest].
 */
class NostrWireTest {
  private val event =
    NostrEvent(
      id = "a".repeat(64),
      pubkey = "b".repeat(64),
      createdAt = 1700000000L,
      kind = 1,
      tags = listOf(listOf("e", "c".repeat(64)), listOf("p", "d".repeat(64))),
      content = "hello world",
      sig = "f".repeat(128),
    )

  // ---- serialize ----

  @Test
  fun `serialize emits the seven fields in canonical order with numbers unquoted`() {
    val simple = NostrEvent("id1", "pk1", 5L, 1, emptyList(), "hi", "sig1")
    assertEquals(
      """{"id":"id1","pubkey":"pk1","created_at":5,"kind":1,"tags":[],"content":"hi","sig":"sig1"}""",
      simple.serialize(),
    )
  }

  @Test
  fun `serialize round-trips content with quotes, backslash, named escapes, and non-ASCII`() {
    val tricky = event.copy(content = "a\"b\\c\td\neé z")
    assertEquals(tricky, parseEvent(tricky.serialize()))
  }

  @Test
  fun `serialize round-trips C0 controls that JSON escapes but NIP-01 emits raw`() {
    // 0x01 and 0x1F are NOT among NIP-01's five named escapes, so the wire object escapes them
    // numerically while the id-preimage in Nip01 emits the raw byte — the one case where the
    // two escapings diverge. Round-tripping proves the wire codec restores the raw byte, so a
    // later verify() recomputes the same preimage. The end-to-end signing guard is in
    // NostrWireSignTest; the preimage side alone is EventIdTest's.
    val controls = event.copy(content = "x" + 1.toChar() + "y" + 0x1F.toChar() + "z")
    assertEquals(controls, parseEvent(controls.serialize()))
  }

  // ---- parseEvent: round-trip ----

  @Test
  fun `parseEvent round-trips a serialized event`() {
    assertEquals(event, parseEvent(event.serialize()))
  }

  @Test
  fun `parseEvent accepts a conformant object and reads every field`() {
    val json =
      """{"id":"aa","pubkey":"bb","created_at":1700000000,"kind":1,"tags":[["e","x"]],""" +
        """"content":"hi","sig":"cc"}"""
    assertEquals(
      NostrEvent("aa", "bb", 1700000000L, 1, listOf(listOf("e", "x")), "hi", "cc"),
      parseEvent(json),
    )
  }

  @Test
  fun `parseEvent accepts empty tags and empty content`() {
    val json =
      """{"id":"aa","pubkey":"bb","created_at":1,"kind":0,"tags":[],"content":"","sig":"cc"}"""
    assertEquals(NostrEvent("aa", "bb", 1L, 0, emptyList(), "", "cc"), parseEvent(json))
  }

  @Test
  fun `parseEvent accepts the maximum kind`() {
    val json =
      """{"id":"aa","pubkey":"bb","created_at":1,"kind":65535,"tags":[],"content":"","sig":"cc"}"""
    assertEquals(65535, parseEvent(json)?.kind)
  }

  // ---- parseEvent: totality over hostile input (all null, never throw) ----

  @Test
  fun `parseEvent rejects non-JSON`() {
    assertNull(parseEvent("not json {"))
    assertNull(parseEvent(""))
    assertNull(parseEvent("{"))
  }

  @Test
  fun `parseEvent rejects JSON that is not an object`() {
    assertNull(parseEvent("[1,2,3]"))
    assertNull(parseEvent("\"a string\""))
    assertNull(parseEvent("123"))
    assertNull(parseEvent("null"))
  }

  @Test
  fun `parseEvent rejects a missing field`() {
    // Every field present but sig.
    val json =
      """{"id":"aa","pubkey":"bb","created_at":1,"kind":1,"tags":[],"content":"hi"}"""
    assertNull(parseEvent(json))
  }

  @Test
  fun `parseEvent rejects created_at that is not an integer`() {
    val quoted =
      """{"id":"aa","pubkey":"bb","created_at":"1700000000","kind":1,"tags":[],"content":"","sig":"cc"}"""
    val float =
      """{"id":"aa","pubkey":"bb","created_at":1700000000.5,"kind":1,"tags":[],"content":"","sig":"cc"}"""
    assertNull(parseEvent(quoted))
    assertNull(parseEvent(float))
  }

  @Test
  fun `parseEvent rejects kind that is not an in-range integer`() {
    fun withKind(kind: String) =
      """{"id":"aa","pubkey":"bb","created_at":1,"kind":$kind,"tags":[],"content":"","sig":"cc"}"""
    assertNull(parseEvent(withKind("\"1\"")))
    assertNull(parseEvent(withKind("65536")))
    assertNull(parseEvent(withKind("-1")))
    assertNull(parseEvent(withKind("1.0")))
  }

  @Test
  fun `parseEvent rejects a string field given the wrong JSON type`() {
    val idNumber =
      """{"id":123,"pubkey":"bb","created_at":1,"kind":1,"tags":[],"content":"","sig":"cc"}"""
    assertNull(parseEvent(idNumber))
  }

  @Test
  fun `parseEvent rejects malformed tags`() {
    fun withTags(tags: String) =
      """{"id":"aa","pubkey":"bb","created_at":1,"kind":1,"tags":$tags,"content":"","sig":"cc"}"""
    assertNull(parseEvent(withTags("\"x\""))) // not an array
    assertNull(parseEvent(withTags("[\"x\"]"))) // element not an array
    assertNull(parseEvent(withTags("[[1]]"))) // tag item not a string
    assertNull(parseEvent(withTags("[[\"e\"],null]"))) // a null tag
  }

  @Test
  fun `jsonMayNestDeeperThan counts only structural brackets`() {
    assertFalse(jsonMayNestDeeperThan("""[[[0]]]""", 3))
    assertTrue(jsonMayNestDeeperThan("""[[[[0]]]]""", 3))
    assertTrue("braces nest like brackets", jsonMayNestDeeperThan("""{"a":{"b":{"c":{}}}}""", 3))
    assertFalse("brackets in a string are content", jsonMayNestDeeperThan("""["[[[["]""", 3))
    assertFalse("an escaped quote does not end the string", jsonMayNestDeeperThan("""["\"[[[["]""", 3))
    assertTrue(
      "an escaped backslash does not escape the quote after it",
      jsonMayNestDeeperThan("""["\\",[[[0]]]]""", 3),
    )
    assertTrue("a stray closer does not bank depth", jsonMayNestDeeperThan("""]]]],[[[[0]]]]""", 3))
  }

  @Test
  fun `jsonMayNestDeeperThan refuses a value after a closer`() {
    // In valid JSON only whitespace, a comma, or another closer can follow a closer, and the scan
    // refuses anything else: kotlinx's array reader keeps reading after a `]` when a value follows
    // it, so the parser nests this text one level per `[1]` although its brackets never nest past one.
    assertTrue(jsonMayNestDeeperThan("[1]".repeat(5), 3))
    assertTrue("after a brace too", jsonMayNestDeeperThan("""[{}{}]""", 3))
    assertTrue("a string is a value", jsonMayNestDeeperThan("""["NOTICE"]"x"]""", 3))
    // JSON's four whitespace characters are all kotlinx skips; it reads U+00A0 as a value, which
    // lets the array continue past the comma after it.
    assertTrue("U+00A0 is not JSON whitespace", jsonMayNestDeeperThan("[0]$NBSP,[0]", 3))
    assertFalse(
      "whitespace, a comma, or another closer may follow a closer",
      jsonMayNestDeeperThan("[[0] \t\r\n,{}]\n", 2),
    )
  }

  // ---- jsonMayNestDeeperThan against the parser it guards ----
  //
  // The scan promises something about kotlinx's parser, so these cells measure that parser rather
  // than restate what it is believed to do: readerDepth reports the most array and object levels
  // kotlinx's tree reader holds open at once while it parses a text. It parses as NostrWire does,
  // with Json.parseToJsonElement on the default configuration; should NostrWire's parses change,
  // readerDepth must change with them.

  @Test
  fun `the reader-depth probe sees the parser's levels`() {
    // The probe counts kotlinx's reader frames by name. Were they renamed, every depth would read
    // zero and the property cells below would pass without checking anything; these fail instead.
    assertEquals(3, readerDepth("[[["))
    assertEquals(2, readerDepth("""{"a":{"""))
    assertEquals(2, readerDepth("""[[0],{}]"""))
    // The array continuation the scan refuses. Should an upgrade stop kotlinx continuing, this fails
    // too, and the scan's closer rule is worth revisiting.
    assertEquals(2, readerDepth("[1][1]"))
  }

  @Test
  fun `the scan never admits text at a depth the parser exceeds`() {
    val random = Random(SEED)
    val texts = HAND_PICKED + List(20_000) { soup(random) } + List(2_000) { validJson(random, levels = 4).first }
    for (text in texts) {
      val admitted = admittedDepth(text) ?: continue
      val reached = readerDepth(text)
      assertTrue("the parser nests ${visible(text)} $reached deep; the scan admits it at $admitted", reached <= admitted)
    }
  }

  @Test
  fun `the scan admits valid JSON at exactly its depth`() {
    val random = Random(SEED)
    repeat(2_000) {
      val (text, depth) = validJson(random, levels = 4)
      assertEquals("generator check: ${visible(text)}", depth, treeDepth(Json.parseToJsonElement(text)))
      assertEquals(visible(text), depth, admittedDepth(text))
    }
  }

  /** The shallowest depth [jsonMayNestDeeperThan] admits [text] at, or null if it refuses the text at
   * every depth (a text of n characters nests at most n deep). */
  private fun admittedDepth(text: String): Int? = (0..text.length).firstOrNull { !jsonMayNestDeeperThan(text, it) }

  /** The most levels kotlinx's tree reader holds open at once while parsing [text]. Each prefix is
   * parsed alone: the reader either finishes it, returning a tree as deep as the reader went, or stops
   * at the prefix's end with an exception whose stack still holds the levels open there. Every level
   * the reader opens is still open at the end of the prefix that stops just past its opener, so the
   * deepest prefix shows the deepest point. */
  private fun readerDepth(text: String): Int =
    (1..text.length).maxOfOrNull { levelsOpenAtEnd(text.substring(0, it)) } ?: 0

  private fun levelsOpenAtEnd(prefix: String): Int =
    try {
      treeDepth(Json.parseToJsonElement(prefix))
    } catch (e: Exception) {
      e.stackTrace.count { it.className == READER_CLASS && it.methodName in READER_LEVEL_METHODS }
    }

  private fun treeDepth(element: JsonElement): Int =
    when (element) {
      is JsonArray -> 1 + (element.maxOfOrNull(::treeDepth) ?: 0)
      is JsonObject -> 1 + (element.values.maxOfOrNull(::treeDepth) ?: 0)
      else -> 0
    }

  /** One to twelve fragments of [SOUP]: mostly malformed text, which is where the scan and the parser
   * can disagree. */
  private fun soup(random: Random): String =
    buildString { repeat(1 + random.nextInt(12)) { append(SOUP[random.nextInt(SOUP.size)]) } }

  /** A random valid JSON value up to [levels] deep, with JSON whitespace scattered between its tokens,
   * and the depth it nests to. Object keys are distinct, so the parsed tree keeps every member. */
  private fun validJson(random: Random, levels: Int): Pair<String, Int> {
    fun ws() = String(CharArray(random.nextInt(3)) { " \t\r\n"[random.nextInt(4)] })
    if (levels == 0 || random.nextInt(4) == 0) return ws() + SCALARS[random.nextInt(SCALARS.size)] + ws() to 0
    val members = List(random.nextInt(4)) { validJson(random, levels - 1) }
    val depth = 1 + (members.maxOfOrNull { it.second } ?: 0)
    val text =
      if (random.nextBoolean()) {
        members.joinToString(",", "[", ws() + "]") { it.first }
      } else {
        members.withIndex().joinToString(",", "{", ws() + "}") { (i, m) -> ws() + "\"k$i\"" + ws() + ":" + m.first }
      }
    return ws() + text + ws() to depth
  }

  /** [text] quoted, with every character outside printable ASCII spelled as its code point. */
  private fun visible(text: String): String =
    text.map { if (it in ' '..'~') it.toString() else "<U+%04X>".format(it.code) }.joinToString("", "'", "'")

  // ---- parseRelayMessage: the inbound envelopes ----

  @Test
  fun `parseRelayMessage reads an EVENT`() {
    val obj =
      """{"id":"aa","pubkey":"bb","created_at":1,"kind":1,"tags":[],"content":"hi","sig":"cc"}"""
    assertEquals(
      RelayMessage.Event("sub1", NostrEvent("aa", "bb", 1L, 1, emptyList(), "hi", "cc")),
      parseRelayMessage("""["EVENT","sub1",$obj]"""),
    )
  }

  @Test
  fun `parseRelayMessage reads OK with a real boolean`() {
    assertEquals(
      RelayMessage.Ok("evid", true, "accepted"),
      parseRelayMessage("""["OK","evid",true,"accepted"]"""),
    )
    assertEquals(
      RelayMessage.Ok("evid", false, "blocked: spam"),
      parseRelayMessage("""["OK","evid",false,"blocked: spam"]"""),
    )
  }

  @Test
  fun `parseRelayMessage reads EOSE, CLOSED, NOTICE, and an AUTH challenge`() {
    assertEquals(RelayMessage.Eose("sub1"), parseRelayMessage("""["EOSE","sub1"]"""))
    assertEquals(
      RelayMessage.Closed("sub1", "auth-required: nope"),
      parseRelayMessage("""["CLOSED","sub1","auth-required: nope"]"""),
    )
    assertEquals(RelayMessage.Notice("be nice"), parseRelayMessage("""["NOTICE","be nice"]"""))
    assertEquals(
      RelayMessage.Auth("challenge-string"),
      parseRelayMessage("""["AUTH","challenge-string"]"""),
    )
  }

  @Test
  fun `parseRelayMessage rejects an OK whose accepted flag is a quoted string`() {
    assertNull(parseRelayMessage("""["OK","evid","true","msg"]"""))
  }

  @Test
  fun `parseRelayMessage rejects an AUTH carrying an object instead of a challenge string`() {
    // The object form is the client-to-relay response (built by authMessage), never a valid
    // inbound message.
    val obj =
      """{"id":"aa","pubkey":"bb","created_at":1,"kind":22242,"tags":[],"content":"","sig":"cc"}"""
    assertNull(parseRelayMessage("""["AUTH",$obj]"""))
  }

  @Test
  fun `parseRelayMessage rejects an EVENT carrying a malformed event`() {
    // Inner event missing sig.
    val badObj = """{"id":"aa","pubkey":"bb","created_at":1,"kind":1,"tags":[],"content":"hi"}"""
    assertNull(parseRelayMessage("""["EVENT","sub1",$badObj]"""))
    assertNull(parseRelayMessage("""["EVENT","sub1","not-an-object"]"""))
  }

  @Test
  fun `parseRelayMessage rejects wrong arity, unknown types, and non-arrays`() {
    assertNull(parseRelayMessage("""["EVENT","sub1"]""")) // EVENT needs 3
    assertNull(parseRelayMessage("""["OK","evid",true]""")) // OK needs 4
    assertNull(parseRelayMessage("""["EOSE"]""")) // EOSE needs 2
    assertNull(parseRelayMessage("""["EOSE","a","b"]""")) // EOSE needs exactly 2
    assertNull(parseRelayMessage("""["UNKNOWN","x"]""")) // unknown type
    assertNull(parseRelayMessage("""[]""")) // empty
    assertNull(parseRelayMessage("""[1,"x"]""")) // type not a string
    assertNull(parseRelayMessage("""{"not":"an array"}""")) // not an array
    assertNull(parseRelayMessage("not json")) // not JSON at all
  }

  // ---- outbound framing ----

  @Test
  fun `eventMessage frames an EVENT publish the receiver can parse back`() {
    val arr = Json.parseToJsonElement(eventMessage(event)).jsonArray
    assertEquals(2, arr.size)
    assertEquals("EVENT", arr[0].jsonPrimitive.content)
    assertEquals(event, parseEvent(arr[1].toString()))
  }

  @Test
  fun `authMessage frames an AUTH response the receiver can parse back`() {
    val arr = Json.parseToJsonElement(authMessage(event)).jsonArray
    assertEquals(2, arr.size)
    assertEquals("AUTH", arr[0].jsonPrimitive.content)
    assertEquals(event, parseEvent(arr[1].toString()))
  }

  // ---- outbound subscription control: REQ / CLOSE / NostrFilter ----

  @Test
  fun `reqMessage frames a REQ with the subscription id and a filter`() {
    assertEquals(
      """["REQ","sub-1",{"kinds":[30078]}]""",
      reqMessage("sub-1", listOf(NostrFilter(kinds = listOf(30078)))),
    )
  }

  @Test
  fun `reqMessage carries multiple filters in order`() {
    assertEquals(
      """["REQ","s",{"kinds":[1]},{"#e":["evid"]}]""",
      reqMessage(
        "s",
        listOf(NostrFilter(kinds = listOf(1)), NostrFilter(tags = mapOf('e' to listOf("evid")))),
      ),
    )
  }

  @Test
  fun `closeMessage frames a CLOSE with the subscription id`() {
    assertEquals("""["CLOSE","sub-1"]""", closeMessage("sub-1"))
  }

  @Test
  fun `NostrFilter serializes kinds and single-letter tag filters in a fixed order`() {
    // #e and #p together pin the tag-key ordering (sorted by letter): #p is here to prove multi-key
    // determinism, NOT because a caller filters on it — the only tag with a caller in 2a.4 is #e.
    val filter =
      NostrFilter(
        kinds = listOf(1, 30078),
        tags = mapOf('e' to listOf("evid"), 'p' to listOf("pk")),
      )
    assertEquals(
      """["REQ","s",{"kinds":[1,30078],"#e":["evid"],"#p":["pk"]}]""",
      reqMessage("s", listOf(filter)),
    )
  }

  @Test
  fun `an empty NostrFilter serializes to the match-all object`() {
    assertEquals("""["REQ","s",{}]""", reqMessage("s", listOf(NostrFilter())))
  }

  @Test
  fun `a NostrFilter omits an empty dimension rather than emitting match-none`() {
    // "kinds":[] means match NO kind in NIP-01 — the opposite of absent (match all). An empty
    // dimension must be omitted, so this filter carries only its #e tag.
    assertEquals(
      """["REQ","s",{"#e":["evid"]}]""",
      reqMessage("s", listOf(NostrFilter(kinds = emptyList(), tags = mapOf('e' to listOf("evid"))))),
    )
  }

  @Test
  fun `NostrFilter rejects a tag filter key that is not a single ASCII letter`() {
    // NIP-01 tag filters are #<single-letter>. A digit, punctuation, whitespace, or non-ASCII key
    // would serialize to a filter a relay CLOSEs with an opaque error; fail fast at construction.
    for (bad in listOf('1', '#', ' ', 'é')) {
      try {
        NostrFilter(tags = mapOf(bad to listOf("x")))
        throw AssertionError("expected IllegalArgumentException for tag key '$bad'")
      } catch (e: IllegalArgumentException) {
        assertTrue(e.message!!.contains("single ASCII letter"))
      }
    }
  }

  @Test
  fun `NostrFilter rejects a tag filter with no values`() {
    // A tag key with an empty value list would be OMITTED by the serializer and silently widen the
    // subscription to match-all (dropping the #e gate selector) — a fail-open. Reject at construction.
    try {
      NostrFilter(tags = mapOf('e' to emptyList()))
      throw AssertionError("expected IllegalArgumentException for an empty tag value list")
    } catch (e: IllegalArgumentException) {
      assertTrue(e.message!!.contains("at least one value"))
    }
  }

  @Test
  fun `NostrFilter snapshots the caller's collections, immune to mutation after construction`() {
    // init checks tag value lists are non-empty only at construction; a caller keeping its references
    // could later clear one into a match-none "#e":[], empty kinds to match-all, or graft on a tag the
    // filter never validated. So the filter snapshots its collections and cannot drift after it is built.
    val eValues = mutableListOf("evid")
    val tags = mutableMapOf('e' to eValues)
    val kinds = mutableListOf(1)
    val filter = NostrFilter(kinds = kinds, tags = tags)
    eValues.clear() // would leave #e a match-none
    tags['p'] = mutableListOf("pk") // would graft a #p the filter never validated
    kinds.clear() // would drop kinds to match-all
    assertEquals(
      """["REQ","s",{"kinds":[1],"#e":["evid"]}]""",
      reqMessage("s", listOf(filter)),
    )
  }

  private companion object {
    const val SEED = 20260923
    const val READER_CLASS = "kotlinx.serialization.json.internal.JsonTreeReader"
    val READER_LEVEL_METHODS = setOf("readArray", "readObject")

    // Whitespace to Unicode, but a value character to JSON and to kotlinx.
    val NBSP = Char(0xA0)
    val LINE_SEPARATOR = Char(0x2028)

    // Structure, a scalar, an object key, strings holding a bracket, an escaped quote, or an escaped
    // backslash, a lone quote and a lone backslash, JSON's four whitespace characters, and two that
    // Unicode counts as whitespace and JSON does not.
    val SOUP =
      listOf(
        "[", "]", "{", "}", ",", ":", "1", "\"k\":",
        "\"[\"", "\"\\\"\"", "\"\\\\\"", "\"", "\\",
        " ", "\t", "\r", "\n", "$NBSP", "$LINE_SEPARATOR",
      )

    // Shapes the soup seldom assembles by chance: each continues an array past a closer, hides
    // nesting behind a string, an escape, or non-JSON whitespace, or banks depth with stray closers.
    val HAND_PICKED =
      listOf(
        "[1][1][1]",
        "[[1][1]]",
        "[1]{\"k\":[1]{\"k\":[",
        "[\"NOTICE\"]\"x\"][[",
        "[1] [1]\t[1]",
        "[1]$NBSP,[1]$NBSP,[1]",
        "[1]$LINE_SEPARATOR,[1]$LINE_SEPARATOR,[1]",
        "[\"\\\\\",[[[",
        "[\"\\\"\",[[[",
        "]]]],[[[[",
      )

    val SCALARS = listOf("1", "-2.5e3", "true", "null", "\"s\"", "\"[{\\\"\\\\\"")
  }
}
