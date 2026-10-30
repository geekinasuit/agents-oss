package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.auth.ApprovalEvidence
import com.geekinasuit.agency.shared.auth.ApprovalVerifier
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.committedPreimage
import com.geekinasuit.agency.shared.auth.oneOfOne
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * [classifyApproval]'s verdicts, one per cell. The fold's reason strings are pinned by the anomaly
 * cells in AuthFoldTest; these pin what the fold does not read: the duplicate's original seq, and
 * the claimed key a rejection is counted under.
 */
class ApprovalClassifierTest {

  @Test
  fun aVerifiedApprovalNotHeldYetIsNew() {
    val verdict = classifyApproval(emptyMap(), payload(), seq = 7, AUTH)
    assertEquals(ApprovalVerdict.VerifiedNew(GATE, VerifiedApproval("operator", NONCE, DIGEST, 7)), verdict)
  }

  @Test
  fun aVerifiedApprovalAlreadyHeldIsADuplicateNamingTheOriginalSeq() {
    val held = mapOf(GATE to listOf(VerifiedApproval("operator", NONCE, DIGEST, 3)))
    val verdict = classifyApproval(held, payload(), seq = 7, AUTH)
    assertEquals(
      ApprovalVerdict.VerifiedDuplicate(GATE, VerifiedApproval("operator", NONCE, DIGEST, 7), originalSeq = 3),
      verdict,
    )
  }

  @Test
  fun anApprovalHeldOnAnotherNonceIsNew() {
    val held = mapOf(GATE to listOf(VerifiedApproval("operator", "n-other", DIGEST, 3)))
    assertEquals(ApprovalVerdict.VerifiedNew::class, classifyApproval(held, payload(), seq = 7, AUTH)::class)
  }

  @Test
  fun aBadSignatureUnderAListedKeyIsCountedUnderThatKey() {
    val verdict = classifyApproval(emptyMap(), payload(), seq = 7, REJECTING)
    assertEquals(
      ApprovalVerdict.Rejected("has a signature that does not verify over its preimage", SchemeKey("test", OPERATOR_KEY)),
      verdict,
    )
  }

  @Test
  fun anUnlistedKeyIsCountedInTheUnlistedBucket() {
    val verdict = classifyApproval(emptyMap(), payload(publicKey = "pk-stranger"), seq = 7, AUTH)
    assertEquals(ApprovalVerdict.Rejected("is signed by a key not in the allow-list", null), verdict)
  }

  @Test
  fun evidenceWhoseCopiesDisagreeWithThePayloadIsCountedInTheUnlistedBucket() {
    val verdict = classifyApproval(emptyMap(), payload(flatGate = "$GATE-x"), seq = 7, AUTH)
    assertEquals(ApprovalVerdict.Rejected("payload gateId disagrees with the preimage", null), verdict)
  }

  @Test
  fun evidenceWhoseDigestCopyDisagreesIsCountedInTheUnlistedBucket() {
    val verdict = classifyApproval(emptyMap(), payload(flatDigest = "2".repeat(64)), seq = 7, AUTH)
    assertEquals(ApprovalVerdict.Rejected("payload payloadDigest disagrees with the preimage", null), verdict)
  }

  @Test
  fun evidenceWhoseNonceCopyDisagreesIsCountedInTheUnlistedBucket() {
    val verdict = classifyApproval(emptyMap(), payload(flatNonce = "n-other"), seq = 7, AUTH)
    assertEquals(ApprovalVerdict.Rejected("payload nonce disagrees with the preimage", null), verdict)
  }

  @Test
  fun aPayloadWithoutEvidenceIsCountedInTheUnlistedBucket() {
    val noEvidence = JsonObject(payload().filterKeys { it != "evidence" })
    assertEquals(
      ApprovalVerdict.Rejected("carries no evidence sub-object", null),
      classifyApproval(emptyMap(), noEvidence, seq = 7, AUTH),
    )
  }

  @Test
  fun aMalformedTopLevelFieldThrows() {
    val noGate = JsonObject(payload().filterKeys { it != "gateId" })
    assertThrows(Exception::class.java) { classifyApproval(emptyMap(), noGate, seq = 7, AUTH) }
  }

  private fun payload(
    flatGate: String = GATE,
    flatDigest: String = DIGEST,
    flatNonce: String = NONCE,
    publicKey: String = OPERATOR_KEY,
  ): JsonObject = buildJsonObject {
    put("gateId", flatGate)
    put("principalId", "operator")
    put("nonce", flatNonce)
    put("payloadDigest", flatDigest)
    put(
      "evidence",
      ApprovalEvidence(
          schemeId = "test",
          publicKey = publicKey,
          signature = "sig",
          carrierArtifactId = "carrier",
          gateId = GATE,
          payloadDigest = DIGEST,
          nonce = NONCE,
          signedPreimage = committedPreimage(publicKey, GATE, DIGEST, NONCE),
        )
        .toJson(),
    )
  }

  private companion object {
    const val GATE = "plan-approval:T1"
    const val NONCE = "n1"
    const val OPERATOR_KEY = "pk-operator"
    val DIGEST = "1".repeat(64)
    val AUTH = ceremonyAuth()
    val REJECTING = LeadAuth(AUTH.allowList, ApprovalVerifier { _, _, _, _ -> false }, oneOfOne("operator"))
  }
}
