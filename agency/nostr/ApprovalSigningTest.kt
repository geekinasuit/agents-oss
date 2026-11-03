package com.geekinasuit.agency.nostr

import com.geekinasuit.agency.shared.auth.ApprovalEvidence
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The approver's side: a gate-open notice the lead sent opens and decodes to what the lead
 * announced, each reader check refuses a notice that breaks it, and an approval signed from a
 * notice verifies under the lead's verifier and is one the lead's decoder accepts.
 */
class ApprovalSigningTest {

  private fun hex(n: Int) = n.toString(16).padStart(64, '0')

  private fun bytes(hex: String) = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

  private fun sha256Hex(s: String) =
    MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

  private val leadSecret = hex(5)
  private val leadPub = Bip340.xonlyPubkeyHex(leadSecret)
  private val operatorSecret = hex(3)
  private val operator = RecipientKey.of(Bip340.xonlyPubkeyHex(operatorSecret))
  private val aux = "0".repeat(64)
  private val artifact = "Plan: add the reader.\nNothing else."
  private val notice = GateOpenNotice("plan-approval:t1", sha256Hex(artifact), "n".repeat(64), artifact)

  private fun rumor(tags: List<List<String>>, content: String = artifact, kind: Int = GATE_OPEN_NOTICE_RUMOR_KIND, author: String = leadPub) =
    Rumor(author, 1_700_000_000, kind, tags, content)

  private val goodTags =
    listOf(
      listOf("agency-gate-id", notice.gateId),
      listOf("agency-payload-digest", notice.payloadDigest),
      listOf("agency-nonce", notice.nonce),
    )

  @Test
  fun aNoticeTheLeadSentDecodesToWhatItAnnounced() {
    val encoding = encodeGateOpenNotice(bytes(leadSecret), operator, notice, 1_700_000_000, 1_699_999_000, aux, aux)
    val wrap = (encoding as NoticeEncoding.Encoded).event
    val opened = checkNotNull(Nip59.unwrap(bytes(operatorSecret), wrap))
    assertEquals(notice, ApprovalSigning.decodeNotice(opened, leadPub))
  }

  @Test
  fun aNoticeThatBreaksAReaderCheckDecodesToNothing() {
    assertEquals("control", notice, ApprovalSigning.decodeNotice(rumor(goodTags), leadPub))
    val refused =
      mapOf(
        "another author" to rumor(goodTags, author = Bip340.xonlyPubkeyHex(hex(9))),
        "another kind" to rumor(goodTags, kind = APPROVAL_RUMOR_KIND),
        "no nonce" to rumor(goodTags.dropLast(1)),
        "two nonces" to rumor(goodTags + listOf(listOf("agency-nonce", "m".repeat(64)))),
        "two gate ids" to rumor(goodTags + listOf(listOf("agency-gate-id", "commit-approval:t1"))),
        "two digests" to rumor(goodTags + listOf(listOf("agency-payload-digest", "0".repeat(64)))),
        "no gate id" to rumor(goodTags.drop(1)),
        "a nonce tag with an extra value" to rumor(goodTags.dropLast(1) + listOf(listOf("agency-nonce", notice.nonce, "x"))),
        "an artifact that is not the digest's" to rumor(goodTags, content = "$artifact (edited)"),
      )
    for ((why, r) in refused) assertNull(why, ApprovalSigning.decodeNotice(r, leadPub))
  }

  @Test
  fun anApprovalSignedFromANoticeVerifiesAndTheLeadCanDecodeIt() {
    val carrier = ApprovalSigning.sign(notice, bytes(operatorSecret), aux)
    assertEquals(notice.gateId, carrier.gateId)
    assertEquals(notice.nonce, carrier.nonce)
    assertEquals(notice.payloadDigest, carrier.payloadDigest)
    val evidence = ApprovalEvidence.fromJson(carrier.evidence)
    assertEquals(operator.hex, evidence.publicKey)
    assertTrue(
      "the signature verifies over the committed preimage",
      Bip340ApprovalVerifier.verifies(evidence.schemeId, evidence.publicKey, evidence.signature, evidence.signedPreimage!!),
    )
    assertTrue(carrierDecodes(carrier))
  }

  @Test
  fun anApprovalTheLeadCouldNotDecodeIsRefusedBeforeItIsSent() {
    val huge = GateOpenNotice("g".repeat(MAX_APPROVAL_CONTENT_CHARS), notice.payloadDigest, notice.nonce, artifact)
    assertThrows(IllegalArgumentException::class.java) { ApprovalSigning.sign(huge, bytes(operatorSecret), aux) }
  }
}
