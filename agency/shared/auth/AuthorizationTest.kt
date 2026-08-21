package com.geekinasuit.agency.shared.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Authorization vocabulary cells: allow-list resolution and its ambiguity refusals,
 * evidence codec fidelity and loud refusal of incomplete evidence, nonce shape.
 */
class AuthorizationTest {

  private val opKey = SchemeKey("scheme-a", "aa".repeat(32))
  private val opPhoneKey = SchemeKey("scheme-b", "bb".repeat(32))
  private val auditorKey = SchemeKey("scheme-a", "cc".repeat(32))

  private val operator = Principal("operator", "operator", listOf(opKey, opPhoneKey))
  private val auditor = Principal("auditor", "observer", listOf(auditorKey))

  @Test
  fun allowListResolvesKeysToPrincipals() {
    val list = AllowList(listOf(operator, auditor))
    assertEquals(operator, list.principalFor(opKey))
    assertEquals(operator, list.principalFor(opPhoneKey))
    assertEquals(auditor, list.principalFor(auditorKey))
    assertEquals(operator, list.byId("operator"))
    assertNull(list.principalFor(SchemeKey("scheme-a", "dd".repeat(32))))
    assertNull(list.byId("stranger"))
  }

  @Test
  fun sameKeyBytesUnderDifferentSchemesAreDifferentKeys() {
    // The scheme tag is part of key identity: a 32-byte value is not a key until a scheme
    // says how to verify with it.
    val list = AllowList(listOf(operator))
    assertNull(list.principalFor(SchemeKey("scheme-b", opKey.publicKey)))
  }

  @Test
  fun duplicateClaimsRefused() {
    assertThrows { AllowList(listOf(operator, Principal("operator", "other", listOf(auditorKey)))) }
    assertThrows { AllowList(listOf(operator, Principal("second", "observer", listOf(opKey)))) }
  }

  @Test
  fun principalShapeRefusals() {
    assertThrows { Principal("", "operator", listOf(opKey)) }
    assertThrows { Principal("operator", "", listOf(opKey)) }
    assertThrows { Principal("operator", "operator", emptyList()) }
    assertThrows { SchemeKey("", "aa") }
    assertThrows { SchemeKey("scheme-a", "") }
  }

  @Test
  fun crossPrincipalByteSharedKeysAreOneCustodianAndRefused() {
    // Two principals holding the same key BYTES under different scheme tags are one
    // custodian: under a quorum tree they would read as two leaves while one keyholder
    // clears both. Refused at the allow-list, the one place both claims are visible.
    assertThrows {
      AllowList(
        listOf(
          operator,
          Principal("backup", "operator", listOf(SchemeKey("scheme-c", opKey.publicKey))),
        )
      )
    }
    // The SAME principal registering the same bytes under two schemes is scheme
    // migration, not a custody collapse — admitted.
    AllowList(
      listOf(
        Principal(
          "operator",
          "operator",
          listOf(SchemeKey("s1", "aa".repeat(32)), SchemeKey("s2", "aa".repeat(32))),
        )
      )
    )
  }

  @Test
  fun keysAreSnapshottedSoCallerMutationCannotAlterAValidatedPrincipal() {
    val keys = mutableListOf(opKey)
    val p = Principal("operator", "operator", keys)
    keys.add(opKey) // would be the same key listed twice if the list aliased
    assertEquals(1, p.keys.size)
  }

  @Test
  fun principalListingTheSameKeyTwiceIsRefusedAsItsOwnMistake() {
    val message =
      try {
        Principal("operator", "operator", listOf(opKey, opKey))
        throw AssertionError("expected IllegalArgumentException")
      } catch (expected: IllegalArgumentException) {
        expected.message.orEmpty()
      }
    // The message names the actual mistake — one principal repeating its own key — rather
    // than accusing 'operator' of colliding with 'operator'.
    assertTrue("twice" in message)
    assertFalse("claimed by both" in message)
  }

  @Test
  fun evidenceCodecRoundTrips() {
    val evidence =
      ApprovalEvidence(
        schemeId = "scheme-a",
        publicKey = "aa".repeat(32),
        signature = "ff".repeat(64),
        carrierArtifactId = "evt-123",
        gateId = "gate-plan-t1",
        payloadDigest = "dd".repeat(32),
        nonce = "ee".repeat(32),
      )
    assertEquals(evidence, ApprovalEvidence.fromJson(evidence.toJson()))
  }

  @Test
  fun incompleteEvidenceRefused() {
    val json = kotlinx.serialization.json.buildJsonObject {
      put("schemeId", kotlinx.serialization.json.JsonPrimitive("scheme-a"))
      put("publicKey", kotlinx.serialization.json.JsonPrimitive("aa"))
      // signature and the binding fields absent
    }
    assertThrows { ApprovalEvidence.fromJson(json) }
    // A null-valued field is a different input from an absent one: JsonNull is a
    // JsonPrimitive whose content is the seven-character string "null", which would sail
    // through the non-blank init if the codec let it out.
    val nullValued = kotlinx.serialization.json.buildJsonObject {
      put("schemeId", kotlinx.serialization.json.JsonPrimitive("scheme-a"))
      put("publicKey", kotlinx.serialization.json.JsonNull)
      put("signature", kotlinx.serialization.json.JsonPrimitive("sig"))
      put("carrierArtifactId", kotlinx.serialization.json.JsonPrimitive("evt"))
      put("gateId", kotlinx.serialization.json.JsonPrimitive("gate"))
      put("payloadDigest", kotlinx.serialization.json.JsonPrimitive("digest"))
      put("nonce", kotlinx.serialization.json.JsonPrimitive("nn"))
    }
    assertThrows { ApprovalEvidence.fromJson(nullValued) }
    assertThrows {
      ApprovalEvidence("scheme-a", "aa", "sig", "evt", "gate", "digest", nonce = " ")
    }
  }

  @Test
  fun freshNonceIs32BytesHexAndNotRepeating() {
    val a = freshNonceHex()
    val b = freshNonceHex()
    assertEquals(64, a.length)
    assertTrue(a.all { it in "0123456789abcdef" })
    assertTrue(a != b)
  }

  private fun assertThrows(block: () -> Any) {
    try {
      block()
    } catch (expected: IllegalArgumentException) {
      return
    }
    throw AssertionError("expected IllegalArgumentException")
  }
}
