package com.geekinasuit.agency.nostr

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The approval carrier: an approval sealed by its approver and gift-wrapped to the lead, opened with
 * the lead's key and decoded by shape alone. The refusal cells show what yields no approval at all;
 * the shape cells show that evidence the accept boundary must judge still gets through to it.
 */
class ApprovalCarrierTest {

  private fun hex(n: Int) = n.toString(16).padStart(64, '0')

  private fun bytes(hex: String) = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

  private val approverKey = hex(3)
  private val leadKey = hex(5)
  private val lead = RecipientKey.of(Bip340.xonlyPubkeyHex(leadKey))
  private val aux = "0".repeat(64)

  private val evidence = buildJsonObject {
    put("schemeId", "bip340")
    put("publicKey", Bip340.xonlyPubkeyHex(approverKey))
    put("signature", "sig")
    put("carrierArtifactId", "chosen-by-the-sender")
    put("gateId", "plan-approval:t1")
    put("payloadDigest", "d".repeat(64))
    put("nonce", "n".repeat(64))
    put("signedPreimage", "preimage")
  }
  private val carrier = ApprovalCarrier("plan-approval:t1", "n".repeat(64), "d".repeat(64), evidence)

  private fun wrapped(c: ApprovalCarrier = carrier, createdAt: Long = 1_700_000_000): NostrEvent {
    val encoding = encodeApproval(bytes(approverKey), lead, c, createdAt, createdAt - 60, aux, aux)
    return (encoding as GiftWrapEncoding.Wrapped).event
  }

  private fun opened(wrap: NostrEvent): Rumor = checkNotNull(Nip59.unwrap(bytes(leadKey), wrap))

  private fun rumor(content: String, kind: Int = APPROVAL_RUMOR_KIND) =
    Rumor(Bip340.xonlyPubkeyHex(approverKey), 1_700_000_000, kind, emptyList(), content)

  @Test
  fun anApprovalRoundTripsThroughTheGiftWrapToTheLead() {
    val wrap = wrapped()
    assertEquals(Nip59.GIFT_WRAP_KIND, wrap.kind)
    val rumor = opened(wrap)
    assertEquals("authored by the approver", Bip340.xonlyPubkeyHex(approverKey), rumor.pubkey)
    assertEquals(listOf(listOf("p", lead.hex)), rumor.tags)
    assertNull(
      "the encoder drops the sender's artifact id",
      kotlinx.serialization.json.Json.parseToJsonElement(rumor.content).let { it as JsonObject }["evidence"]
        .let { it as JsonObject }["carrierArtifactId"],
    )
    val decoded = checkNotNull(decodeApproval(rumor))
    assertEquals(carrier.gateId, decoded.gateId)
    assertEquals(carrier.nonce, decoded.nonce)
    assertEquals(carrier.payloadDigest, decoded.payloadDigest)
    assertEquals(JsonObject(evidence - "carrierArtifactId"), JsonObject(decoded.evidence - "carrierArtifactId"))
  }

  @Test
  fun theCarrierArtifactIdIsTheRumorsIdNotTheSenders() {
    val rumor = opened(wrapped())
    assertEquals(JsonPrimitive(rumor.id), decodeApproval(rumor)!!.evidence["carrierArtifactId"])
    // A new rumor (another date) has another id; the same rumor decodes to the same one.
    val later = opened(wrapped(createdAt = 1_700_000_100))
    assertNotEquals(rumor.id, later.id)
    assertEquals(decodeApproval(rumor), decodeApproval(rumor))
  }

  @Test
  fun aSendersOwnArtifactIdIsReplacedOnDecode() {
    // Built directly, not through encodeApproval, which would already have dropped it: a sender can
    // write any rumor, so the decoder must replace the field itself.
    val content = """{"gateId":"g","nonce":"n","payloadDigest":"d","evidence":{"carrierArtifactId":"${"p".repeat(3000)}"}}"""
    val r = rumor(content)
    assertEquals(JsonPrimitive(r.id), decodeApproval(r)!!.evidence["carrierArtifactId"])
  }

  @Test
  fun evidenceTheBoundaryMustJudgeStillDecodes() {
    // Shape only: an empty or nonsense evidence object is the accept boundary's to reject and record.
    for (e in listOf(JsonObject(emptyMap()), buildJsonObject { put("schemeId", 7) })) {
      val decoded = decodeApproval(opened(wrapped(carrier.copy(evidence = e))))
      assertNotNull("evidence $e", decoded)
    }
  }

  @Test
  fun otherKeysInTheContentAreIgnored() {
    val content = """{"gateId":"g","nonce":"n","payloadDigest":"d","evidence":{},"extra":"x"}"""
    assertEquals("g", decodeApproval(rumor(content))?.gateId)
  }

  @Test
  fun aRumorThatCarriesNoApprovalDecodesToNothing() {
    val ok = """{"gateId":"g","nonce":"n","payloadDigest":"d","evidence":{}}"""
    assertNotNull("control", decodeApproval(rumor(ok)))
    val refused =
      mapOf(
        "another kind" to rumor(ok, kind = GATE_OPEN_NOTICE_RUMOR_KIND),
        "not JSON" to rumor("approve"),
        "not an object" to rumor("""["g","n","d",{}]"""),
        "a number for gateId" to rumor("""{"gateId":1,"nonce":"n","payloadDigest":"d","evidence":{}}"""),
        "no nonce" to rumor("""{"gateId":"g","payloadDigest":"d","evidence":{}}"""),
        "evidence a string" to rumor("""{"gateId":"g","nonce":"n","payloadDigest":"d","evidence":"{}"}"""),
        "nested deeper than an approval" to rumor("""{"gateId":"g","nonce":"n","payloadDigest":"d","evidence":{"x":{}}}"""),
        "too long" to rumor("""{"gateId":"${"g".repeat(MAX_APPROVAL_CONTENT_CHARS)}","nonce":"n","payloadDigest":"d","evidence":{}}"""),
      )
    for ((why, r) in refused) assertNull(why, decodeApproval(r))
  }
}
