package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.requireContract
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * How the lead's folds read a journal entry's payload fields. A file that reads payloads imports
 * the readers it uses by name, rather than every file in the package seeing them.
 */
internal object PayloadReaders {
  /** Required payload field. JsonNull IS a JsonPrimitive whose content is the string
   * "null", so without the explicit check a null-valued field on a known kind would fold
   * onward as a working four-character string (a mint of the guessable nonce "null")
   * instead of failing CLASSIFIED as the payload-contract drift it is. Non-string scalars
   * are refused for the same reason — a numeric 123 must not fold onward as the string
   * "123" — matching the strict readers the shared auth codec sets the doctrine with. */
  fun JsonObject.str(k: String): String {
    val el = this[k]
    requireContract(el != null) { "payload field '$k' is missing" }
    requireContract(el !is kotlinx.serialization.json.JsonNull) { "payload field '$k' is null" }
    requireContract(el is JsonPrimitive && el.isString) { "payload field '$k' must be a JSON string" }
    return el.content
  }

  /** Optional payload field: absent and JsonNull both read as "no value" — an optional
   * field explicitly set to null must not become the string "null". Deliberately tolerant
   * of non-string scalars, unlike [str]: on the release path a coerced number can only
   * miss (an unminted nonce, a mismatched digest — both fold stale, visibly), and the
   * cost accrual's malformed-means-zero contract sits on this reader. */
  fun JsonObject.strOrNull(k: String): String? {
    val el = this[k] ?: return null
    if (el is kotlinx.serialization.json.JsonNull) return null
    requireContract(el is JsonPrimitive) { "payload field '$k' must be a JSON scalar" }
    return el.content
  }

  /** The field's value if it is a JSON string, else null: absent, null, a number, a boolean, an object
   * or an array all read as no value, so a malformed field never fails the fold. */
  fun JsonObject.jsonStringOrNull(k: String): String? =
    (this[k] as? JsonPrimitive)?.takeIf { it.isString }?.content

  /** Whether a notify marker says its announce will be sent again: only a JSON `true` in `retry`
   * does. Absent, null, a string, or any other value reads as final, the outcome that sends nothing
   * again, so a malformed field can cost a retry but never cause one. */
  fun JsonObject.marksRetry(): Boolean = marksTrue("retry")

  /** Whether the field [k] holds a JSON `true`; any other value, or none, reads as false. */
  fun JsonObject.marksTrue(k: String): Boolean {
    val el = this[k] as? kotlinx.serialization.json.JsonPrimitive ?: return false
    return !el.isString && el.content == "true"
  }
}
