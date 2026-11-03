package com.geekinasuit.agency.shared.text

/**
 * Whether [cp] shows a reader nothing, whatever its general category: a default-ignorable code
 * point, or a graphic character the standard names or describes as blank. [hasReadableText] does
 * not count it as text to read, and [inert] shows it as an escape, so both rules read this one table.
 */
internal fun showsNothing(cp: Int): Boolean = DEFAULT_IGNORABLE.any { cp in it } || cp in GRAPHIC_BLANKS

/**
 * Default_Ignorable_Code_Point, per DerivedCoreProperties.txt of Unicode 15.0 (the version JDK 21
 * implements): code points a renderer shows as nothing unless it supports them. Among them are the
 * four Hangul fillers (U+115F, U+1160, U+3164, U+FFA0), the only letters in the list.
 */
private val DEFAULT_IGNORABLE: List<IntRange> =
  listOf(
    0x00AD..0x00AD,
    0x034F..0x034F,
    0x061C..0x061C,
    0x115F..0x1160,
    0x17B4..0x17B5,
    0x180B..0x180F,
    0x200B..0x200F,
    0x202A..0x202E,
    0x2060..0x206F,
    0x3164..0x3164,
    0xFE00..0xFE0F,
    0xFEFF..0xFEFF,
    0xFFA0..0xFFA0,
    0xFFF0..0xFFF8,
    0x1BCA0..0x1BCA3,
    0x1D173..0x1D17A,
    0xE0000..0xE0FFF,
  )

/**
 * Graphic characters that the standard names or describes as blank, which the default-ignorable list
 * does not include: U+2800 BRAILLE PATTERN BLANK, a braille cell with no dots raised; U+13441
 * EGYPTIAN HIEROGLYPH FULL BLANK and U+13442 EGYPTIAN HIEROGLYPH HALF BLANK; and U+1D159 MUSICAL
 * SYMBOL NULL NOTEHEAD, which has no appearance of its own. Outside music rendering the standard asks
 * only for a placeholder for it, such as a dotted box, which is no more to read than the box drawn
 * for a private-use code point.
 */
private val GRAPHIC_BLANKS: Set<Int> = setOf(0x2800, 0x13441, 0x13442, 0x1D159)
