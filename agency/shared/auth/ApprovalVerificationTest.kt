package com.geekinasuit.agency.shared.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The verifying vocabulary in isolation: the canonical preimage form, its round-trip, and
 * the total, never-throwing parse that fails closed on anything else. The signature check
 * itself is a port ([ApprovalVerifier]) with a fail-closed default; the fold cells
 * ([com.geekinasuit.agency.lead.AuthFoldTest]) exercise verification end to end.
 */
class ApprovalVerificationTest {

  @Test
  fun committedPreimageIsAFixedPositionalStringArray() {
    // Asserted against a HAND-WRITTEN literal, not against parseCommitted or a second
    // committedPreimage call: an anchor that a re-serialization can be checked against is
    // only an anchor if the expected bytes were written independently of the codec.
    assertEquals(
      """["pk-1","g1","d1","n1"]""",
      committedPreimage(publicKey = "pk-1", gateId = "g1", payloadDigest = "d1", nonce = "n1"),
    )
  }

  @Test
  fun committedPreimageRoundTripsThroughParse() {
    val preimage = committedPreimage("pk-1", "g1", "d1", "n1")
    val committed = parseCommitted(preimage)
    assertEquals(CommittedApproval("pk-1", "g1", "d1", "n1"), committed)
  }

  @Test
  fun canonicalFormEscapesAndRoundTripsAwkwardBytes() {
    // A field carrying a quote and a backslash must serialize to escaped JSON and parse
    // back to the exact original — the canonicality the provenance argument rests on holds
    // for the awkward bytes too, not just the tidy ones.
    val weird = "p\"k\\1"
    val preimage = committedPreimage(weird, "g1", "d1", "n1")
    assertEquals(weird, parseCommitted(preimage)?.publicKey)
  }

  @Test
  fun parseRejectsNonArray() {
    assertNull(parseCommitted("{}"))
    assertNull(parseCommitted(""""just-a-string""""))
    assertNull(parseCommitted("42"))
  }

  @Test
  fun parseRejectsWrongArity() {
    assertNull(parseCommitted("""["pk","g1","d1"]"""))
    assertNull(parseCommitted("""["pk","g1","d1","n1","extra"]"""))
  }

  @Test
  fun parseRejectsNonStringElement() {
    assertNull(parseCommitted("""["pk","g1","d1",123]"""))
    assertNull(parseCommitted("""["pk","g1",["d1"],"n1"]"""))
  }

  @Test
  fun parseRejectsBlankField() {
    assertNull(parseCommitted("""["pk","g1","d1",""]"""))
  }

  @Test
  fun parseIsTotalOnGarbage() {
    // Never throws — a hostile or truncated preimage folds to "unverified", not a boot crash.
    assertNull(parseCommitted("not json{"))
    assertNull(parseCommitted(""))
  }

  @Test
  fun rejectingVerifierVerifiesNothing() {
    assertFalse(
      RejectingVerifier.verifies(
        schemeId = "test",
        publicKey = "pk-1",
        signature = "sig",
        preimage = committedPreimage("pk-1", "g1", "d1", "n1"),
      )
    )
  }
}
