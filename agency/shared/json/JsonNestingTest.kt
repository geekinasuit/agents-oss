package com.geekinasuit.agency.shared.json

import kotlin.random.Random
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The JSON nesting scan: its structural rules by example, then its agreement with the parser it
 * guards — kotlinx's tree reader, measured over random text rather than described.
 */
class JsonNestingTest {

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
  // kotlinx's tree reader holds open at once while it parses a text. It parses the way the scan's
  // KDoc names, with Json.parseToJsonElement on the default configuration; a caller that parsed
  // differently would need readerDepth changed to match.

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
