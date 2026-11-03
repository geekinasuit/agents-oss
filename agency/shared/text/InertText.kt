package com.geekinasuit.agency.shared.text

/**
 * [text] made inert for a terminal, so text from another party can neither drive the terminal nor
 * reorder or hide what a person reads. A code point is shown as itself only when it is a letter,
 * mark, number, punctuation mark, symbol or space separator and does not show nothing
 * ([showsNothing]). Every other code point — controls, format characters, line and paragraph
 * separators, surrogates, private use, unassigned, default ignorables, graphic blanks — is shown as
 * an escape: \uXXXX, or \u{XXXXX} above U+FFFF. A backslash is shown as \\, so an escape in the text
 * cannot pass for one this made. With [keepLines], newline and tab are kept.
 *
 * It walks code points, so a character outside the Basic Multilingual Plane is judged whole. A code
 * point the running JDK's Unicode tables do not know is unassigned, so it is escaped.
 */
fun inert(text: String, keepLines: Boolean = false): String = buildString {
  text.codePoints().forEach { cp ->
    when {
      cp == '\\'.code -> append("\\\\")
      keepLines && (cp == '\n'.code || cp == '\t'.code) -> appendCodePoint(cp)
      Character.getType(cp) in SHOWN_CATEGORIES && !showsNothing(cp) -> appendCodePoint(cp)
      cp > 0xFFFF -> append("\\u{%x}".format(cp))
      else -> append("\\u%04x".format(cp))
    }
  }
}

/** The general categories [inert] shows as themselves: letters, marks, numbers, punctuation,
 * symbols, and the space separator. */
private val SHOWN_CATEGORIES: Set<Int> =
  setOf(
      Character.UPPERCASE_LETTER, Character.LOWERCASE_LETTER, Character.TITLECASE_LETTER,
      Character.MODIFIER_LETTER, Character.OTHER_LETTER,
      Character.NON_SPACING_MARK, Character.COMBINING_SPACING_MARK, Character.ENCLOSING_MARK,
      Character.DECIMAL_DIGIT_NUMBER, Character.LETTER_NUMBER, Character.OTHER_NUMBER,
      Character.CONNECTOR_PUNCTUATION, Character.DASH_PUNCTUATION, Character.START_PUNCTUATION,
      Character.END_PUNCTUATION, Character.INITIAL_QUOTE_PUNCTUATION, Character.FINAL_QUOTE_PUNCTUATION,
      Character.OTHER_PUNCTUATION,
      Character.MATH_SYMBOL, Character.CURRENCY_SYMBOL, Character.MODIFIER_SYMBOL, Character.OTHER_SYMBOL,
      Character.SPACE_SEPARATOR,
    )
    .map { it.toInt() }
    .toSet()
