package com.geekinasuit.agency.nostr

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonArray
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

// The nostr wire format: the JSON event object a relay carries, and the relay-message envelopes it
// travels in (NIP-01, plus the NIP-42 AUTH envelope). This is the shape a NostrEvent takes on the
// socket; the socket itself — dialing, subscribing, the auth challenge-response FLOW — is the
// transport, step 3b, not here. This file is still pure and hermetic: it turns a NostrEvent into
// bytes and hostile bytes back into a NostrEvent, and makes no network call.
//
// TWO ESCAPINGS, KEPT APART. The id-preimage in Nip01 is hand-serialized with NIP-01's own escaping
// because the id must agree byte-for-byte with every other implementation. The wire OBJECT here is
// ordinary JSON: its key order is not id-significant and its string escaping only has to be valid
// JSON, because the receiver PARSES it and RECOMPUTES the id-preimage with Nip01's escaping. So the
// object codec is delegated to a vetted JSON library (kotlinx), while the id-preimage stays
// hand-rolled — hand-rolling a parser for hostile relay input would be the liability, not the
// discipline.
//
// PARSING NEVER TRUSTS (A4-3 / A4-7: listening never authorizes). parseEvent and parseRelayMessage
// are TOTAL — any malformed input folds to null, never throws — and they only STRUCTURE bytes into
// typed values. They do not verify the signature and do not trust the supplied id; a parsed event
// is DATA. The trust decision stays in verify(), which recomputes the id from the fields and checks
// the signature, and the authorization decision stays in the fold, which never sees a type from
// this file. created_at is carried, never read as a clock (see NostrEvent).
//
// NOT HERE (step 3b, with the socket that gives them a consumer): the REQ/CLOSE subscription
// envelopes and the filter object they carry — specifying a filter with no subscription to
// constrain it would be shape without a caller. This file frames the envelopes that carry an EVENT
// (publish + the inbound feed) and the AUTH envelope, which is all the wire format the transport
// needs to stand up first.
//
// DoS: total-over-hostile-input means Exceptions fold to null; it does NOT mean an Error is caught.
// Pathologically nested JSON can exhaust the stack as the parser recurses, and that Error
// propagates by design, as it does through the rest of this module. A byte cap on the inbound frame
// does NOT bound nesting depth — each level costs as little as one byte, so a frame under any
// realistic size limit still nests far deeper than the stack allows — so the transport must bound
// the nesting depth of an inbound frame (agents-oss #38), separately from the byte-size cap
// (agents-oss #36), before it reaches this codec; this codec assumes a depth-bounded string.

/** Serialize an event to its canonical wire object: the seven NIP-01 fields in a fixed key order,
 * with ordinary JSON escaping. Key order is not id-significant (only [Nip01]'s preimage array is),
 * but a fixed order keeps the output deterministic. */
fun NostrEvent.serialize(): String = toJsonObject().toString()

/** Parse a wire event object from untrusted relay text. TOTAL: returns `null` on any malformed
 * input rather than throwing. Structures only — does NOT verify the signature and does NOT trust
 * the supplied id (that is [verify]'s job). */
fun parseEvent(text: String): NostrEvent? {
  val element =
    try {
      Json.parseToJsonElement(text)
    } catch (_: SerializationException) {
      // The one call here that can throw on hostile input; everything below is null-safe by
      // construction. Narrower than Nip44.decrypt's broad catch on purpose — there the whole body
      // runs hostile bytes through throwing crypto primitives, here exactly one call parses them.
      return null
    }
  return parseEventObject(element)
}

/** A relay-to-client message (NIP-01, plus the NIP-42 AUTH challenge). The client-to-relay side is
 * built by [eventMessage] / [authMessage]; the REQ/CLOSE subscription control is step 3b. */
sealed interface RelayMessage {
  /** `["EVENT", <subscription-id>, <event>]` — an event delivered on a subscription. */
  data class Event(val subscriptionId: String, val event: NostrEvent) : RelayMessage

  /** `["OK", <event-id>, <accepted>, <message>]` — a relay's verdict on a published event. */
  data class Ok(val eventId: String, val accepted: Boolean, val message: String) : RelayMessage

  /** `["EOSE", <subscription-id>]` — end of stored events for a subscription. */
  data class Eose(val subscriptionId: String) : RelayMessage

  /** `["CLOSED", <subscription-id>, <message>]` — a subscription the relay refused or dropped. */
  data class Closed(val subscriptionId: String, val message: String) : RelayMessage

  /** `["NOTICE", <message>]` — a human-readable relay notice. */
  data class Notice(val message: String) : RelayMessage

  /** `["AUTH", <challenge>]` — a NIP-42 auth challenge. The client's response is an AUTH event
   * wrapped by [authMessage]; deciding whether to answer is the transport's job (3b). */
  data class Auth(val challenge: String) : RelayMessage
}

/** Parse a relay-to-client message from untrusted relay text. TOTAL: `null` on any malformed
 * input, an unknown message type, or wrong arity — never throws. */
fun parseRelayMessage(text: String): RelayMessage? {
  val element =
    try {
      Json.parseToJsonElement(text)
    } catch (_: SerializationException) {
      return null
    }
  val arr = element as? JsonArray ?: return null
  return when (arr.firstOrNull()?.stringValue()) {
    "EVENT" -> {
      if (arr.size != 3) return null
      val subscriptionId = arr[1].stringValue() ?: return null
      val event = parseEventObject(arr[2]) ?: return null
      RelayMessage.Event(subscriptionId, event)
    }
    "OK" -> {
      if (arr.size != 4) return null
      val eventId = arr[1].stringValue() ?: return null
      val accepted = arr[2].booleanValue() ?: return null
      val message = arr[3].stringValue() ?: return null
      RelayMessage.Ok(eventId, accepted, message)
    }
    "EOSE" -> {
      if (arr.size != 2) return null
      RelayMessage.Eose(arr[1].stringValue() ?: return null)
    }
    "CLOSED" -> {
      if (arr.size != 3) return null
      val subscriptionId = arr[1].stringValue() ?: return null
      val message = arr[2].stringValue() ?: return null
      RelayMessage.Closed(subscriptionId, message)
    }
    "NOTICE" -> {
      if (arr.size != 2) return null
      RelayMessage.Notice(arr[1].stringValue() ?: return null)
    }
    "AUTH" -> {
      if (arr.size != 2) return null
      RelayMessage.Auth(arr[1].stringValue() ?: return null)
    }
    else -> null
  }
}

/** The client-to-relay publish envelope: `["EVENT", <event>]`. */
fun eventMessage(event: NostrEvent): String =
  buildJsonArray {
    add("EVENT")
    add(event.toJsonObject())
  }
    .toString()

/** The client-to-relay NIP-42 auth envelope: `["AUTH", <event>]`, carrying a kind-22242 event
 * built by [buildAuthEvent]. */
fun authMessage(event: NostrEvent): String =
  buildJsonArray {
    add("AUTH")
    add(event.toJsonObject())
  }
    .toString()

/**
 * Build a NIP-42 auth event (kind 22242) answering a relay's [challenge] for [relayUrl]. The
 * [relayUrl] is a parameter, not a constant — this module is mechanism, and which relay is
 * configuration that lives outside oss (§REPO_SEAM). `content` is empty by NIP-42 convention; the
 * `relay` and `challenge` tags carry the binding the relay checks. Signed exactly like any other
 * event, so a relay verifies it with the same [verify].
 */
fun buildAuthEvent(
  secretKeyHex: String,
  relayUrl: String,
  challenge: String,
  createdAt: Long,
  auxRandHex: String,
): NostrEvent =
  signEvent(
    secretKeyHex = secretKeyHex,
    createdAt = createdAt,
    kind = 22242,
    tags = listOf(listOf("relay", relayUrl), listOf("challenge", challenge)),
    content = "",
    auxRandHex = auxRandHex,
  )

/** The seven fields as a JSON object in canonical key order. */
private fun NostrEvent.toJsonObject(): JsonObject =
  buildJsonObject {
    put("id", id)
    put("pubkey", pubkey)
    put("created_at", createdAt)
    put("kind", kind)
    putJsonArray("tags") {
      for (tag in tags) {
        addJsonArray {
          for (element in tag) add(element)
        }
      }
    }
    put("content", content)
    put("sig", sig)
  }

/** Structure a parsed JSON element into a [NostrEvent], or `null` if it is not a conformant event
 * object. Every field must be present and of the NIP-01 type; a missing field, a wrong type, a
 * `created_at` that is not an integer, or a `kind` outside 0..65535 all fold to `null`. */
private fun parseEventObject(element: JsonElement): NostrEvent? {
  val obj = element as? JsonObject ?: return null
  val id = obj["id"]?.stringValue() ?: return null
  val pubkey = obj["pubkey"]?.stringValue() ?: return null
  val createdAt = obj["created_at"]?.longValue() ?: return null
  val kind = obj["kind"]?.intValue()?.takeIf { it in 0..65535 } ?: return null
  val tags = obj["tags"]?.let { tagsValue(it) } ?: return null
  val content = obj["content"]?.stringValue() ?: return null
  val sig = obj["sig"]?.stringValue() ?: return null
  return NostrEvent(id, pubkey, createdAt, kind, tags, content, sig)
}

/** A tags value: an array of arrays of strings, or `null` if any element has the wrong shape. */
private fun tagsValue(element: JsonElement): List<List<String>>? {
  val outer = element as? JsonArray ?: return null
  val tags = ArrayList<List<String>>(outer.size)
  for (tagElement in outer) {
    val tagArray = tagElement as? JsonArray ?: return null
    val tag = ArrayList<String>(tagArray.size)
    for (item in tagArray) tag.add(item.stringValue() ?: return null)
    tags.add(tag)
  }
  return tags
}

// Strict primitive accessors: a JSON string is a string and only a string; a JSON number is a
// number and only a number. A quoted number ("1700000000") is NOT accepted where an integer is
// required, and an unquoted token is NOT accepted where a string is required — a relay sending the
// wrong JSON type is sending a malformed event, and the codec folds it to null rather than
// coercing. None of these throw.

private fun JsonElement.stringValue(): String? =
  (this as? JsonPrimitive)?.takeIf { it.isString }?.content

private fun JsonElement.longValue(): Long? =
  (this as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull

private fun JsonElement.intValue(): Int? =
  (this as? JsonPrimitive)?.takeIf { !it.isString }?.intOrNull

private fun JsonElement.booleanValue(): Boolean? =
  (this as? JsonPrimitive)?.takeIf { !it.isString }?.booleanOrNull
