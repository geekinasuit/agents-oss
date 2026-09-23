package com.geekinasuit.agency.shared.text

/**
 * Whether [text] has something for a person to read: at least one code point that is a letter,
 * number, punctuation mark, or symbol, other than the few that show nothing to read
 * ([DRAWN_BLANK]).
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
  text.codePoints().anyMatch { Character.getType(it) in READABLE_CATEGORIES && it !in DRAWN_BLANK }

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

/**
 * Code points in those categories that show a reader nothing to read. The four Hangul fillers
 * (U+115F, U+1160, U+3164, U+FFA0) are the only letters, numbers, punctuation marks, or symbols
 * that Unicode lists as default-ignorable, which a renderer shows as nothing unless it supports
 * them. The rest are graphic characters that the standard names or describes as blank, which that
 * list does not include: U+2800 BRAILLE PATTERN BLANK, a braille cell with no dots raised;
 * U+13441 EGYPTIAN HIEROGLYPH FULL BLANK and U+13442 EGYPTIAN HIEROGLYPH HALF BLANK; and U+1D159
 * MUSICAL SYMBOL NULL NOTEHEAD, which has no appearance of its own. Outside music rendering the
 * standard asks only for a placeholder for it, such as a dotted box, which is no more to read than
 * the box drawn for a private-use code point.
 */
private val DRAWN_BLANK: Set<Int> =
  setOf(0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x13441, 0x13442, 0x1D159)
