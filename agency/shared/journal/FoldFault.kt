package com.geekinasuit.agency.shared.journal

import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/**
 * A fold's refusal of an entry whose payload breaks its kind's contract: a field missing, of the
 * wrong type or out of range, or a payload that is not a JSON object. The message is text the
 * fold's code writes, naming the field and the check, and it never quotes the payload.
 * [foldFaultMessage] shows this exception's message and no other's.
 */
class PayloadContractException(message: String) : IllegalArgumentException(message)

/** [require], throwing a [PayloadContractException]. [lazyMessage] must not quote the payload. */
@OptIn(ExperimentalContracts::class)
inline fun requireContract(value: Boolean, lazyMessage: () -> String) {
  contract { returns() implies value }
  if (!value) throw PayloadContractException(lazyMessage())
}

/**
 * [payloadJson] as a JSON object. A payload that does not parse, or parses to anything but an
 * object, is refused with a [PayloadContractException]. The parser's exception is not attached as
 * the cause: its message quotes the input.
 */
fun payloadObject(payloadJson: String): JsonObject {
  val element =
    try {
      Json.parseToJsonElement(payloadJson)
    } catch (_: IllegalArgumentException) {
      throw PayloadContractException("payload is not valid JSON")
    }
  return element as? JsonObject ?: throw PayloadContractException("payload is not a JSON object")
}

/** The shared [fold]'s failure on one entry, with the message [foldFaultMessage] gives. */
class JournalFoldException(seq: Long, kind: String, cause: Throwable) :
  RuntimeException(foldFaultMessage("journal fold", seq, kind, cause), cause)

/**
 * The message for [fold]'s failure on the entry at [seq] of [kind], caused by [cause]:
 * `<fold> failed at seq=<seq> kind='<kind>': <reason>`.
 *
 * A fold fault's message can be journaled: the lead records the message of a fault that stops its
 * loop as an escalation reason. So the message names the entry by its seq and kind and carries no
 * other text from it. A payload is text its writer chose, and an exception's message may quote it:
 * the parser's quotes its input, and a number conversion's quotes the text it could not convert.
 * The reason is therefore [cause]'s message only when [cause] is a [PayloadContractException],
 * whose message is text the fold's code wrote; for any other exception it is the exception's class
 * name. The kind column is as free-form as the payload, so the kind is shown in quotes only when it
 * is at most 64 characters from `[A-Za-z0-9._-]`, as every kind the code writes is. Any other kind
 * is shown by its length alone.
 */
fun foldFaultMessage(fold: String, seq: Long, kind: String, cause: Throwable): String {
  val shownKind =
    if (kind.length <= MAX_SHOWN_KIND_LENGTH && SHOWN_KIND.matches(kind)) "'$kind'"
    else "(${kind.length} chars, not shown)"
  val reason = if (cause is PayloadContractException) cause.message else cause.javaClass.name
  return "$fold failed at seq=$seq kind=$shownKind: $reason"
}

private val SHOWN_KIND = Regex("[A-Za-z0-9._-]+")
private const val MAX_SHOWN_KIND_LENGTH = 64
