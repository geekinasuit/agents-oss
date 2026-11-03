package com.geekinasuit.agency.nostr

import com.geekinasuit.agency.shared.json.jsonMayNestDeeperThan
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * What an approval carrier delivers to the lead: the gate, nonce and payload digest it claims, and
 * the evidence object, passed through as JSON. SUBSTRATE-NEUTRAL like [GateOpenNotice]: it names no
 * nostr type, so the lead's accept boundary takes it as its own candidate.
 *
 * SHAPE ONLY. [decodeApproval] checks that the content has these four fields of the right JSON
 * types and nothing about whether the evidence is valid: an approval whose evidence is malformed or
 * forged is the accept boundary's to reject and record. A carrier that yields no [ApprovalCarrier] at
 * all leaves nothing to record.
 */
data class ApprovalCarrier(
  val gateId: String,
  val nonce: String,
  val payloadDigest: String,
  val evidence: JsonObject,
)

/**
 * The kind of the RUMOR an approval travels as, inside a gift wrap addressed to the lead. No NIP
 * defines it; it sits in NIP-01's regular range, chosen for this carrier alone, so no client reads an
 * approval as a chat message and the lead's decoder refuses every other kind. Relays store only the
 * gift wrap around it ([Nip59.GIFT_WRAP_KIND]).
 */
const val APPROVAL_RUMOR_KIND = 4901

/** The most characters a decoded approval rumor's content may hold. An approval row the accept
 * boundary journals is bounded at a few thousand characters, so this leaves room for any approval
 * [encodeApproval] writes from evidence in [com.geekinasuit.agency.shared.auth.ApprovalEvidence]'s
 * form. Longer content is refused unparsed, whatever it holds. */
const val MAX_APPROVAL_CONTENT_CHARS = 16_384

// The content object, and the evidence object inside it: an approval's fields are strings, so nothing
// nests deeper.
private const val MAX_APPROVAL_CONTENT_DEPTH = 2

/**
 * Encode [carrier] as a NIP-59 gift wrap from the approver to [lead]. The rumor is authored by
 * [approverKeyBytes], dated [createdAt], of kind [APPROVAL_RUMOR_KIND], tagged `["p", <lead>]`, and its
 * content is [carrier] as a JSON object (`gateId`, `nonce`, `payloadDigest`, `evidence`). The evidence's
 * `carrierArtifactId`, if any, is not kept: the lead sets it to the rumor's id on decode, an id the
 * approver cannot know while writing the content it is computed over.
 *
 * Timestamps and aux randomness are the caller's, as in [encodeGateOpenNotice]: only the seal should
 * be backdated. [approverKeyBytes] is the caller's and is neither kept nor zeroed. An oversize
 * approval is [GiftWrapEncoding.TooLarge], never a throw.
 */
fun encodeApproval(
  approverKeyBytes: ByteArray,
  lead: RecipientKey,
  carrier: ApprovalCarrier,
  createdAt: Long,
  sealCreatedAt: Long,
  sealAuxRandHex: String,
  wrapAuxRandHex: String,
): GiftWrapEncoding {
  val content = buildJsonObject {
    put("gateId", carrier.gateId)
    put("nonce", carrier.nonce)
    put("payloadDigest", carrier.payloadDigest)
    put("evidence", JsonObject(carrier.evidence - CARRIER_ARTIFACT_ID))
  }
  val rumor =
    Rumor(
      pubkey = Bip340.xonlyPubkeyFromKeyBytes(approverKeyBytes),
      createdAt = createdAt,
      kind = APPROVAL_RUMOR_KIND,
      tags = listOf(listOf("p", lead.hex)),
      content = content.toString(),
    )
  return Nip59.wrap(
    senderKey = approverKeyBytes,
    recipient = lead,
    rumor = rumor,
    sealCreatedAt = sealCreatedAt,
    wrapCreatedAt = createdAt,
    sealAuxRandHex = sealAuxRandHex,
    wrapAuxRandHex = wrapAuxRandHex,
  )
}

/**
 * The approval [rumor] carries, or null when it carries none: a kind other than
 * [APPROVAL_RUMOR_KIND], content longer than [MAX_APPROVAL_CONTENT_CHARS] or nested deeper than an
 * approval's fields, content that is not a JSON object, or one missing a string `gateId`, `nonce` or
 * `payloadDigest` or an object `evidence`. Total: never throws. Other keys are ignored.
 *
 * The evidence's `carrierArtifactId` is SET to [Rumor.id], replacing whatever the sender wrote: the
 * id names this carrier's artifact, and nothing in the approval's signature covers the field. The
 * same rumor in another gift wrap decodes the same; a new rumor (a new date) gets a new id, and the
 * accept boundary still finds it a duplicate on its principal, nonce and digest.
 *
 * The rumor's author is authenticated by [Nip59.unwrap], but it is not who approved: the signature
 * inside the evidence is. So this does not compare the two.
 */
fun decodeApproval(rumor: Rumor): ApprovalCarrier? {
  if (rumor.kind != APPROVAL_RUMOR_KIND) return null
  val content = rumor.content
  if (content.length > MAX_APPROVAL_CONTENT_CHARS) return null
  if (jsonMayNestDeeperThan(content, MAX_APPROVAL_CONTENT_DEPTH)) return null
  val obj =
    try {
      Json.parseToJsonElement(content) as? JsonObject
    } catch (_: Exception) {
      null
    } ?: return null
  val gateId = obj.stringOrNull("gateId") ?: return null
  val nonce = obj.stringOrNull("nonce") ?: return null
  val payloadDigest = obj.stringOrNull("payloadDigest") ?: return null
  val evidence = obj["evidence"] as? JsonObject ?: return null
  return ApprovalCarrier(gateId, nonce, payloadDigest, JsonObject(evidence + (CARRIER_ARTIFACT_ID to JsonPrimitive(rumor.id))))
}

private const val CARRIER_ARTIFACT_ID = "carrierArtifactId"

private fun JsonObject.stringOrNull(key: String): String? =
  (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
