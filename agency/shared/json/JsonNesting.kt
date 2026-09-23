package com.geekinasuit.agency.shared.json

/**
 * False only when parsing [text] cannot open more than [maxDepth] levels of JSON arrays and objects at
 * once — the check untrusted text must pass BEFORE it reaches kotlinx's tree parser, because the parser
 * recurses once per level and deep enough nesting overflows the stack. The overflow is a
 * StackOverflowError, which a total parse's `catch (Exception)` does not see, so no catch around the
 * parse stands in for this check. True refuses the text, and may refuse text that would not have nested
 * that deep.
 *
 * STRING-AWARE: it tracks JSON string literals, escapes included, and counts only STRUCTURAL `[` and
 * `{`. A bracket inside a string is content the parser reads without recursing, not nesting, which is
 * what lets a wide-but-shallow message (thousands of sibling tags) pass while a deep one is refused.
 *
 * NOTHING BUT WHITESPACE, A COMMA, OR ANOTHER CLOSER MAY FOLLOW A CLOSER: anything else after a
 * structural `]` or `}` refuses the text, whatever its depth. Valid JSON never has anything else
 * there, but kotlinx's array reader keeps reading after a `]` when a value follows it, so the parser
 * nests `[1][1][1]` three levels deep while its brackets nest one. Whitespace means JSON's four
 * characters only, which are all kotlinx skips: it reads any other character — U+00A0 included — as
 * the start of a value, one that continues the array just the same.
 *
 * With that rule, every closer the parser consumes ends the array or object it is reading, so up to
 * the point where malformed input stops the parser, the scan's depth is the parser's. Past that point
 * the scan may count on, which can only refuse more. The parser it agrees with is kotlinx's default
 * `Json` — `Json.parseToJsonElement` with no configuration — and `JsonNestingTest` checks the scan
 * against that parser. The default is not strict JSON — it reads `[abc]` and `[01]`, for example —
 * but a parse through a configured `Json` (comments allowed, lenient mode), or a kotlinx that read
 * arrays differently, would need the scan and that test revisited. A closer at depth zero is ignored,
 * never banked, so stray closers cannot pre-pay for the nesting that follows them.
 *
 * Iterative, so the check cannot overflow the stack it protects.
 */
fun jsonMayNestDeeperThan(text: String, maxDepth: Int): Boolean {
  var depth = 0
  var inString = false
  var escaped = false
  var afterCloser = false
  for (c in text) {
    when {
      escaped -> escaped = false
      inString ->
        when (c) {
          '\\' -> escaped = true
          '"' -> inString = false
        }
      c == ' ' || c == '\t' || c == '\n' || c == '\r' -> {}
      c == ']' || c == '}' -> {
        if (depth > 0) depth--
        afterCloser = true
      }
      afterCloser && c != ',' -> return true
      else -> {
        afterCloser = false
        if (c == '"') inString = true
        if ((c == '[' || c == '{') && ++depth > maxDepth) return true
      }
    }
  }
  return false
}
