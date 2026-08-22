package com.geekinasuit.agency.shared.auth

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The one required-field reader both codecs in this module share ([quorumFromJson] and
 * [ApprovalEvidence.fromJson] previously carried private near-twins). [voice] names the
 * refusing codec so every refusal still speaks in its own file's voice.
 *
 * Refusals, each loud: missing key; JsonNull (which IS a JsonPrimitive whose content is
 * the string "null" — letting it through builds a record named "null" instead of
 * refusing); structured-where-scalar (an object or array where a string belongs), which
 * would otherwise surface as kotlinx's own exception text rather than this module's; and
 * a non-string scalar (`"principalId": 123` names a principal nobody wrote — this
 * module's own writers emit strings here, so hostile-data readers parse strictly).
 */
internal fun JsonObject.req(k: String, voice: String): String {
  val el = this[k] ?: throw IllegalArgumentException("$voice is missing '$k'")
  require(el !is JsonNull) { "$voice '$k' is null — null is a refusal, not a value" }
  val prim =
    el as? JsonPrimitive
      ?: throw IllegalArgumentException("$voice '$k' is not a scalar value")
  require(prim.isString) { "$voice '$k' must be a JSON string, got '${prim.content}'" }
  return prim.content
}

/**
 * Required integer field. Stricter than `req(...).toIntOrNull()`: a string-typed number
 * (`"threshold": "5"`) is refused as well — this module's own writers emit JSON numbers,
 * so a string here is a hand-authored or foreign document, and hostile-data readers parse
 * strictly rather than leniently.
 */
internal fun JsonObject.reqInt(k: String, voice: String): Int {
  val el = this[k] ?: throw IllegalArgumentException("$voice is missing '$k'")
  require(el !is JsonNull) { "$voice '$k' is null — null is a refusal, not a value" }
  val prim =
    el as? JsonPrimitive
      ?: throw IllegalArgumentException("$voice '$k' is not a scalar value")
  require(!prim.isString) { "$voice '$k' must be a JSON number, got a string" }
  return prim.content.toIntOrNull()
    ?: throw IllegalArgumentException("$voice '$k' ('${prim.content}') is not an integer")
}
