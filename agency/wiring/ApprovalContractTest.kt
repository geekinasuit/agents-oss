package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.nostr.APPROVAL_RUMOR_KIND
import com.geekinasuit.agency.nostr.ApprovalSigning
import com.geekinasuit.agency.nostr.Bip340
import com.geekinasuit.agency.nostr.Bip340ApprovalVerifier
import com.geekinasuit.agency.nostr.GATE_OPEN_NOTICE_RUMOR_KIND
import com.geekinasuit.agency.nostr.GateOpenNotice
import com.geekinasuit.agency.nostr.Nip59
import com.geekinasuit.agency.nostr.Rumor
import com.geekinasuit.agency.nostr.decodeApproval
import com.geekinasuit.agency.shared.auth.ApprovalEvidence
import com.geekinasuit.agency.shared.auth.committedPreimage
import com.geekinasuit.agency.shared.auth.parseCommitted
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The written contract for approvers, `agency/APPROVING.md`, against the code: the published vectors
 * in `testdata/approval-vectors.json` are what [SpecApprover] and the real signer both produce and
 * what the verifier accepts, and the document's escaping table is the encoder's on every UTF-16 unit
 * a string can carry. `ApprovalIngressTest` takes [SpecApprover]'s approval through a real lead.
 */
class ApprovalContractTest {
  private val vectors: List<JsonObject> by lazy {
    val srcdir = System.getenv("TEST_SRCDIR") ?: error("TEST_SRCDIR not set (not under bazel test)")
    val path = System.getenv("APPROVAL_VECTORS") ?: error("APPROVAL_VECTORS not set")
    Json.parseToJsonElement(File(srcdir, path).readText()).jsonArray.map { it.jsonObject }
  }

  private fun JsonObject.str(name: String) = getValue(name).jsonPrimitive.content

  private fun bytes(hex: String) = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

  @Test
  fun thereAreVectorsToCheck() {
    assertTrue(vectors.size >= 4)
  }

  @Test
  fun theVectorsExerciseEveryRowOfTheEscapingTable() {
    // Read from the gate ids, not the preimages: the domain tag puts a `/` in every preimage.
    val gateIds = vectors.joinToString { SpecApprover.jsonString(it.str("gateId")) }
    val escaped = listOf("\\\"", "\\\\", "\\b", "\\f", "\\n", "\\r", "\\t", "\\u0001", "\\u000b", "\\u001f")
    // Some encoders escape these by default, which the lead refuses.
    val raw = listOf("/", "<", ">", "&", "é", Char(0x7F).toString(), Char(0x2028).toString(), Char(0x2029).toString())
    for (spelling in escaped + raw) assertTrue(spelling, spelling in gateIds)
    assertTrue("a character above U+FFFF", String(Character.toChars(0x1F600)) in gateIds)
  }

  @Test
  fun theWireKindsAreTheDocuments() {
    assertEquals(14, GATE_OPEN_NOTICE_RUMOR_KIND)
    assertEquals(4901, APPROVAL_RUMOR_KIND)
    assertEquals(1059, Nip59.GIFT_WRAP_KIND)
  }

  @Test
  fun anApproverBuiltFromTheDocumentReproducesEveryVector() {
    for (v in vectors) {
      val publicKey = SpecApprover.publicKey(v.str("secretKey"))
      assertEquals(v.str("publicKey"), publicKey)
      val preimage = SpecApprover.preimage(publicKey, v.str("gateId"), v.str("payloadDigest"), v.str("nonce"))
      assertEquals(v.str("preimage"), preimage)
      assertEquals(v.str("preimageSha256"), SpecApprover.sha256Hex(preimage))
      assertEquals(v.str("signature"), SpecApprover.sign(v.str("preimageSha256"), v.str("secretKey"), v.str("auxRand")))
      assertEquals(
        v.str("rumorContent"),
        SpecApprover.rumorContent(v.str("secretKey"), v.str("gateId"), v.str("payloadDigest"), v.str("nonce"), v.str("auxRand")),
      )
    }
  }

  @Test
  fun theRealSignerProducesEveryVector() {
    for (v in vectors) {
      assertEquals(v.str("publicKey"), Bip340.xonlyPubkeyHex(v.str("secretKey")))
      assertEquals(v.str("preimage"), committedPreimage(v.str("publicKey"), v.str("gateId"), v.str("payloadDigest"), v.str("nonce")))
      // The real signer takes the notice's fields, whatever its artifact held.
      val notice = GateOpenNotice(v.str("gateId"), v.str("payloadDigest"), v.str("nonce"), "the artifact")
      val evidence = ApprovalSigning.sign(notice, bytes(v.str("secretKey")), v.str("auxRand")).evidence
      assertEquals(v.str("signature"), evidence.getValue("signature").jsonPrimitive.content)
      assertEquals(v.str("preimage"), evidence.getValue("signedPreimage").jsonPrimitive.content)
    }
  }

  @Test
  fun theVerifierAndDecoderAcceptEveryVector() {
    for (v in vectors) {
      assertNotNull(parseCommitted(v.str("preimage")))
      assertTrue(Bip340ApprovalVerifier.verifies("bip340", v.str("publicKey"), v.str("signature"), v.str("preimage")))
      val carrier = decodeApproval(Rumor(v.str("publicKey"), 1_700_000_000, APPROVAL_RUMOR_KIND, emptyList(), v.str("rumorContent")))
      assertEquals(v.str("gateId"), carrier?.gateId)
      // The vector leaves `carrierArtifactId` out: the lead fills it, so the evidence still parses.
      assertEquals(v.str("signature"), ApprovalEvidence.fromJson(checkNotNull(carrier).evidence).signature)
    }
  }

  @Test
  fun theDocumentsEscapingTableIsTheEncodersOnEveryUtf16Unit() {
    for (unit in 0..0xFFFF) {
      val c = unit.toChar()
      if (c.isSurrogate()) continue
      val field = "a${c}b"
      assertEquals("U+%04X".format(unit), committedPreimage("k", field, "d", "n"), SpecApprover.preimage("k", field, "d", "n"))
    }
    val astral = String(Character.toChars(0x1F600))
    assertEquals(committedPreimage("k", astral, "d", "n"), SpecApprover.preimage("k", astral, "d", "n"))
  }
}
