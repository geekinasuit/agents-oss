package com.geekinasuit.agency.shared.text

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What [inert] shows as itself and what it escapes, checked for every code point against the display
 * rule restated here, independently of the code. Every character outside printable ASCII is built
 * from its code point, so this file holds no invisible characters of its own.
 */
class InertTextTest {

  private fun text(vararg codePoints: Int): String =
    buildString { codePoints.forEach { appendCodePoint(it) } }

  @Test
  fun theTranscribedIgnorableTableHasUnicodesCount() =
    assertEquals(4174, DEFAULT_IGNORABLE_15_0.sumOf { it.last - it.first + 1 })

  @Test
  fun everyCodePointIsShownAsItselfExactlyWhenItIsVisibleText() {
    for (cp in 0..Character.MAX_CODE_POINT) {
      val s = text(cp)
      val shown = inert(s)
      when {
        cp == '\\'.code -> assertEquals("\\\\", shown)
        Character.getType(cp) in VISIBLE_CATEGORIES && DEFAULT_IGNORABLE_15_0.none { cp in it } && cp !in GRAPHIC_BLANKS ->
          assertEquals("U+%04X is shown as itself".format(cp), s, shown)
        else -> {
          val escape = if (cp > 0xFFFF) "\\u{%x}".format(cp) else "\\u%04x".format(cp)
          assertEquals("U+%04X is escaped".format(cp), escape, shown)
        }
      }
    }
  }

  @Test
  fun theGraphicBlanksAreEscaped() =
    assertEquals("\\u2800\\u{13441}\\u{13442}\\u{1d159}", inert(text(0x2800, 0x13441, 0x13442, 0x1D159)))

  @Test
  fun aLetterOrSymbolIsReadableExactlyWhenItIsShownAsItself() {
    // The two rules read one table: among letters, numbers, punctuation and symbols, the ones with
    // nothing to read are the ones shown escaped. The backslash is the one exception, shown doubled.
    for (cp in 0..Character.MAX_CODE_POINT) {
      if (cp == '\\'.code || Character.getType(cp) !in READABLE_CATEGORIES) continue
      val s = text(cp)
      assertEquals("U+%04X".format(cp), hasReadableText(s), inert(s) == s)
    }
  }

  @Test
  fun keepLinesKeepsNewlineAndTabOnly() {
    val s = "a\nb\tc\rd" + text(0x2028) + "e"
    assertEquals("a\\u000ab\\u0009c\\u000dd\\u2028e", inert(s))
    assertEquals("a\nb\tc\\u000dd\\u2028e", inert(s, keepLines = true))
  }

  @Test
  fun anEscapeInTheTextCannotPassForOneThisMade() =
    assertTrue(inert("\\u202e").startsWith("\\\\u"))

  private companion object {
    // The display rule, restated independently of the code: letters, marks, numbers, punctuation,
    // symbols and the space separator are visible text...
    val VISIBLE_CATEGORIES: Set<Int> =
      listOf(
          Character.UPPERCASE_LETTER, Character.LOWERCASE_LETTER, Character.TITLECASE_LETTER,
          Character.MODIFIER_LETTER, Character.OTHER_LETTER, Character.NON_SPACING_MARK,
          Character.COMBINING_SPACING_MARK, Character.ENCLOSING_MARK, Character.DECIMAL_DIGIT_NUMBER,
          Character.LETTER_NUMBER, Character.OTHER_NUMBER, Character.CONNECTOR_PUNCTUATION,
          Character.DASH_PUNCTUATION, Character.START_PUNCTUATION, Character.END_PUNCTUATION,
          Character.INITIAL_QUOTE_PUNCTUATION, Character.FINAL_QUOTE_PUNCTUATION,
          Character.OTHER_PUNCTUATION, Character.MATH_SYMBOL, Character.CURRENCY_SYMBOL,
          Character.MODIFIER_SYMBOL, Character.OTHER_SYMBOL, Character.SPACE_SEPARATOR,
        )
        .map { it.toInt() }
        .toSet()

    // ...unless Unicode 15.0's DerivedCoreProperties.txt lists them as Default_Ignorable_Code_Point,
    // transcribed line for line (Total code points: 4174)...
    val DEFAULT_IGNORABLE_15_0: List<IntRange> =
      listOf(
        0x00AD..0x00AD, 0x034F..0x034F, 0x061C..0x061C, 0x115F..0x1160, 0x17B4..0x17B5,
        0x180B..0x180D, 0x180E..0x180E, 0x180F..0x180F, 0x200B..0x200F, 0x202A..0x202E,
        0x2060..0x2064, 0x2065..0x2065, 0x2066..0x206F, 0x3164..0x3164, 0xFE00..0xFE0F,
        0xFEFF..0xFEFF, 0xFFA0..0xFFA0, 0xFFF0..0xFFF8, 0x1BCA0..0x1BCA3, 0x1D173..0x1D17A,
        0xE0000..0xE0000, 0xE0001..0xE0001, 0xE0002..0xE001F, 0xE0020..0xE007F, 0xE0080..0xE00FF,
        0xE0100..0xE01EF, 0xE01F0..0xE0FFF,
      )

    // ...or the standard names or describes them as blank: BRAILLE PATTERN BLANK, EGYPTIAN
    // HIEROGLYPH FULL BLANK and HALF BLANK, MUSICAL SYMBOL NULL NOTEHEAD.
    val GRAPHIC_BLANKS: Set<Int> = setOf(0x2800, 0x13441, 0x13442, 0x1D159)

    // The categories hasReadableText counts: letters, numbers, punctuation and symbols.
    val READABLE_CATEGORIES: Set<Int> =
      (VISIBLE_CATEGORIES -
          listOf(Character.NON_SPACING_MARK, Character.COMBINING_SPACING_MARK, Character.ENCLOSING_MARK, Character.SPACE_SEPARATOR)
            .map { it.toInt() }
            .toSet())
  }
}
