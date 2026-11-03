package com.geekinasuit.agency.shared.text

/**
 * Whether [text] has something for a person to read: at least one code point that is a letter,
 * number, punctuation mark, or symbol, other than the few of those that show nothing
 * ([showsNothing]): the Hangul fillers, and the graphic characters the standard names or describes
 * as blank. The rest of what [showsNothing] lists is outside these categories.
 *
 * No other code point is text to read, alone or in any combination: separators and whitespace;
 * control and format characters, zero-width ones such as U+200B and U+FEFF among them; marks, which
 * modify a base character and without one show at most a floating accent or a dotted circle;
 * private-use and unassigned code points, which a font draws as nothing or as a placeholder box;
 * and an unpaired surrogate. Text made only of those shows a reader nothing, or nothing they can
 * read. Each code point's general category comes from the running JDK's Unicode tables, so a
 * character added in a later Unicode version counts as unassigned: text made only of such
 * characters has nothing to read here, though a current font may draw them.
 *
 * The check walks code points, not chars: a character outside the Basic Multilingual Plane is two
 * surrogate chars, and neither is readable alone.
 */
fun hasReadableText(text: String): Boolean =
  text.codePoints().anyMatch {
    Character.getType(it) in READABLE_CATEGORIES && !showsNothing(it)
  }

/** The general categories of letters, numbers, punctuation marks, and symbols. */
private val READABLE_CATEGORIES: Set<Int> =
  setOf(
      Character.UPPERCASE_LETTER,
      Character.LOWERCASE_LETTER,
      Character.TITLECASE_LETTER,
      Character.MODIFIER_LETTER,
      Character.OTHER_LETTER,
      Character.DECIMAL_DIGIT_NUMBER,
      Character.LETTER_NUMBER,
      Character.OTHER_NUMBER,
      Character.CONNECTOR_PUNCTUATION,
      Character.DASH_PUNCTUATION,
      Character.START_PUNCTUATION,
      Character.END_PUNCTUATION,
      Character.INITIAL_QUOTE_PUNCTUATION,
      Character.FINAL_QUOTE_PUNCTUATION,
      Character.OTHER_PUNCTUATION,
      Character.MATH_SYMBOL,
      Character.CURRENCY_SYMBOL,
      Character.MODIFIER_SYMBOL,
      Character.OTHER_SYMBOL,
    )
    .map { it.toInt() }
    .toSet()
