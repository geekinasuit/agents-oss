package com.geekinasuit.agency.shared.text

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which strings have something for a person to read. Every character outside printable ASCII is
 * built from its code point, so this file holds no invisible characters of its own.
 */
class ReadableTextTest {

  private fun text(vararg codePoints: Int): String =
    buildString { codePoints.forEach { appendCodePoint(it) } }

  /** Checks every case and names all that fail, rather than stopping at the first. */
  private fun assertNothingToRead(cases: Map<String, String>) {
    val readable = cases.filterValues { hasReadableText(it) }.keys
    assertTrue(
      "counted as readable, though each has nothing to read: $readable",
      readable.isEmpty(),
    )
  }

  @Test
  fun blankTextHasNothingToRead() {
    assertNothingToRead(
      mapOf(
        "the empty string" to "",
        "spaces, a tab and line breaks" to " \t\r\n",
        "a no-break space" to text(0x00A0),
        "an ideographic space" to text(0x3000),
        "a line separator" to text(0x2028),
      )
    )
  }

  @Test
  fun controlCharactersHaveNothingToRead() {
    assertNothingToRead(
      mapOf(
        "NUL, BEL and DEL" to text(0x0000, 0x0007, 0x007F),
        "a next-line control (U+0085)" to text(0x0085),
      )
    )
  }

  @Test
  fun formatCharactersHaveNothingToRead() {
    assertNothingToRead(
      mapOf(
        "a zero-width space and a newline" to text(0x200B, 0x0A),
        "a byte order mark alone" to text(0xFEFF),
        "a soft hyphen, a word joiner and a right-to-left override" to text(0x00AD, 0x2060, 0x202E),
        "tag characters, outside the Basic Multilingual Plane" to text(0xE0001, 0xE0041, 0xE007F),
      )
    )
  }

  @Test
  fun marksWithoutABaseHaveNothingToRead() {
    assertNothingToRead(
      mapOf(
        "a combining acute accent" to text(0x0301),
        "variation selector 16" to text(0xFE0F),
        "variation selector 17, outside the Basic Multilingual Plane" to text(0xE0100),
        "a combining grapheme joiner" to text(0x034F),
        "a combining enclosing circle" to text(0x20DD),
      )
    )
  }

  @Test
  fun lettersAndSymbolsDrawnBlankHaveNothingToRead() {
    assertNothingToRead(
      mapOf(
        "the Hangul choseong filler" to text(0x115F),
        "the Hangul jungseong filler" to text(0x1160),
        "the Hangul filler" to text(0x3164),
        "the halfwidth Hangul filler" to text(0xFFA0),
        "the blank braille pattern" to text(0x2800),
      )
    )
  }

  @Test
  fun privateUseUnassignedAndUnpairedCodePointsHaveNothingToRead() {
    assertNothingToRead(
      mapOf(
        "a private-use character" to text(0xE000),
        "a private-use character outside the Basic Multilingual Plane" to text(0xF0000),
        "noncharacters" to text(0xFDD0, 0xFFFF),
        "an unpaired surrogate" to Char(0xD800).toString(),
      )
    )
  }

  @Test
  fun anyReadableCodePointIsSomethingToRead() {
    val cases =
      mapOf(
        "a letter" to "a",
        "a digit" to "7",
        "punctuation" to ".",
        "a currency symbol" to "$",
        "a replacement character" to text(0xFFFD),
        // One code point written as two surrogate chars, neither of which is readable alone.
        "an emoji alone, outside the Basic Multilingual Plane" to text(0x1F600),
        "a letter outside the Basic Multilingual Plane" to text(0x10400),
        "a letter with a combining accent" to text(0x61, 0x0301),
        "a letter among zero-width characters" to text(0x200B, 0x61, 0xFEFF),
        "a heading after blank lines" to "\n\n# Plan\n",
      )
    val unreadable = cases.filterValues { !hasReadableText(it) }.keys
    assertTrue(
      "counted as having nothing to read, though each is readable: $unreadable",
      unreadable.isEmpty(),
    )
  }
}
