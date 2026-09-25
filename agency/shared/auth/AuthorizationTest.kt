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
  fun evidenceRoundTripsWithSignedPreimage() {
    val evidence =
      ApprovalEvidence(
        schemeId = "scheme-a",
        publicKey = "aa".repeat(32),
        signature = "ff".repeat(64),
        carrierArtifactId = "evt-123",
        gateId = "gate-plan-t1",
        payloadDigest = "dd".repeat(32),
        nonce = "ee".repeat(32),
        signedPreimage = "[0,\"${"aa".repeat(32)}\",1700000000,1,[],\"approve\"]",
      )
    val round = ApprovalEvidence.fromJson(evidence.toJson())
    assertEquals(evidence, round)
    assertEquals(evidence.signedPreimage, round.signedPreimage)
  }

  @Test
  fun legacyEvidenceWithoutSignedPreimageParsesToNull() {
    // A record journaled before the preimage field existed carries no 'signedPreimage' key.
    // It must still parse — these are immutable evidence entries — with the preimage null.
    // (The verifying layer treats a null preimage as unverifiable, never a pass; that
    // decision lives in the fold, not here.)
    assertNull(ApprovalEvidence.fromJson(evidenceJson()).signedPreimage)
  }

  @Test
  fun signedPreimageWhenPresentIsHeldToTheSameBarAsRequiredFields() {
    // Absence is the only relaxation. An explicit JSON null is a refusal — the codec's
    // stance on every other field — not a second way to spell absence.
    assertThrows {
      ApprovalEvidence.fromJson(evidenceJson("signedPreimage" to kotlinx.serialization.json.JsonNull))
    }
    // A present-but-blank preimage is refused at construction.
    assertThrows {
      ApprovalEvidence(
        "scheme-a", "aa", "sig", "evt", "gate", "digest", nonce = "nn", signedPreimage = " ")
    }
  }

  @Test
  fun evidenceFieldsRejectNonStringScalarsAndStructuredValues() {
    // fromJson parses SHAPE, not merely presence: a number or an object where a string
    // belongs is a foreign or hand-authored document, refused rather than coerced.
    assertThrows {
      ApprovalEvidence.fromJson(evidenceJson("publicKey" to kotlinx.serialization.json.JsonPrimitive(123)))
    }
    assertThrows {
      ApprovalEvidence.fromJson(
        evidenceJson(
          "gateId" to
            kotlinx.serialization.json.buildJsonObject {
              put("nested", kotlinx.serialization.json.JsonPrimitive("x"))
            }
        )
      )
    }
    // The optional preimage relaxes on absence, NOT on type: a number here is still refused.
    assertThrows {
      ApprovalEvidence.fromJson(evidenceJson("signedPreimage" to kotlinx.serialization.json.JsonPrimitive(7)))
    }
  }

  @Test
  fun aRefusedEvidenceFieldIsNamedButItsValueIsNot() {
    // The evidence is text its carrier chose, and a caller may keep a refusal's message, so the
    // message names the field and the check and leaves the value out.
    val message =
      try {
        ApprovalEvidence.fromJson(
          evidenceJson("publicKey" to kotlinx.serialization.json.JsonPrimitive(90210))
        )
        throw AssertionError("expected IllegalArgumentException")
      } catch (expected: IllegalArgumentException) {
        expected.message.orEmpty()
      }
    assertEquals("approval evidence 'publicKey' must be a JSON string", message)
  }

  @Test
  fun signedPreimageSurvivesAJsonTextRoundTripVerbatim() {
    // fromJson(toJson()) round-trips an in-memory object graph and never crosses the JSON
    // text boundary, so it cannot observe a string-escaping defect. That boundary is where
    // the preimage is most exposed: it is the one field whose value is structured text —
    // quotes and brackets — and the class KDoc promises it is journaled verbatim, which is a
    // text-out then text-in trip. Serialize to a string and parse it back, the way the
    // journal does, and assert the quote/bracket-laden value returns unchanged.
    val preimage = "[0,\"${"aa".repeat(32)}\",1700000000,1,[],\"approve\"]"
    val evidence =
      ApprovalEvidence(
        schemeId = "scheme-a",
        publicKey = "aa".repeat(32),
        signature = "ff".repeat(64),
        carrierArtifactId = "evt-123",
        gateId = "gate-plan-t1",
        payloadDigest = "dd".repeat(32),
        nonce = "ee".repeat(32),
        signedPreimage = preimage,
      )
    val round = textRoundTrip(evidence)
    assertEquals(evidence, round)
    assertEquals(preimage, round.signedPreimage)
  }

  @Test
  fun nullSignedPreimageIsOmittedFromJsonAndStaysNullAcrossText() {
    // A null preimage is omitted from the object entirely, not written as JSON null, so
    // absence stays distinguishable from a written value — and it parses back to null across
    // the text boundary, never to the seven-character string "null".
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
    assertFalse("signedPreimage" in evidence.toJson())
    assertNull(textRoundTrip(evidence).signedPreimage)
  }

  @Test
  fun freshNonceIs32BytesHexAndNotRepeating() {
    val a = freshNonceHex()
    val b = freshNonceHex()
    assertEquals(64, a.length)
    assertTrue(a.all { it in "0123456789abcdef" })
    assertTrue(a != b)
  }

  // A complete, well-formed evidence object in the legacy shape (no signedPreimage), with
  // the given fields overridden — for exercising fromJson's per-field refusals.
  private fun evidenceJson(
    vararg overrides: Pair<String, kotlinx.serialization.json.JsonElement>
  ): kotlinx.serialization.json.JsonObject {
    val base =
      linkedMapOf<String, kotlinx.serialization.json.JsonElement>(
        "schemeId" to kotlinx.serialization.json.JsonPrimitive("scheme-a"),
        "publicKey" to kotlinx.serialization.json.JsonPrimitive("aa".repeat(32)),
        "signature" to kotlinx.serialization.json.JsonPrimitive("ff".repeat(64)),
        "carrierArtifactId" to kotlinx.serialization.json.JsonPrimitive("evt-123"),
        "gateId" to kotlinx.serialization.json.JsonPrimitive("gate-plan-t1"),
        "payloadDigest" to kotlinx.serialization.json.JsonPrimitive("dd".repeat(32)),
        "nonce" to kotlinx.serialization.json.JsonPrimitive("ee".repeat(32)),
      )
    for ((k, v) in overrides) base[k] = v
    return kotlinx.serialization.json.JsonObject(base)
  }

  // A real serialize-to-text then parse-from-text trip, the way the journal persists a
  // record — distinct from fromJson(toJson()), which stays an in-memory object graph and so
  // cannot see a string-escaping defect. Mirrors QuorumTest's parseQuorum.
  private fun textRoundTrip(e: ApprovalEvidence): ApprovalEvidence =
    ApprovalEvidence.fromJson(
      kotlinx.serialization.json.Json.parseToJsonElement(e.toJson().toString())
        as kotlinx.serialization.json.JsonObject
    )

  private fun assertThrows(block: () -> Any) {
    try {
      block()
    } catch (expected: IllegalArgumentException) {
      return
    }
    throw AssertionError("expected IllegalArgumentException")
  }
}
