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
 *
 * A refusal names the field and the check, never the value. The value is text the
 * document's writer chose, and a caller may keep a refusal's message with its own records.
 * [reqInt] and [optStr] refuse the same way.
 */
internal fun JsonObject.req(k: String, voice: String): String {
  val el = this[k] ?: throw IllegalArgumentException("$voice is missing '$k'")
  require(el !is JsonNull) { "$voice '$k' is null — null is a refusal, not a value" }
  val prim =
    el as? JsonPrimitive
      ?: throw IllegalArgumentException("$voice '$k' is not a scalar value")
  require(prim.isString) { "$voice '$k' must be a JSON string" }
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
    ?: throw IllegalArgumentException("$voice '$k' is not an integer in Int range")
}

/**
 * Optional string field: an ABSENT key reads as null — the one relaxation, so a record
 * written before this field existed still parses. A PRESENT key is held to [req]'s full
 * strictness (JsonNull, structured-where-scalar, and non-string scalars all refused): a
 * field someone bothered to write is data, parsed as strictly as a required one, and an
 * explicit `"k": null` stays a refusal, not a way to spell absence.
 */
internal fun JsonObject.optStr(k: String, voice: String): String? =
  if (this[k] == null) null else req(k, voice)
