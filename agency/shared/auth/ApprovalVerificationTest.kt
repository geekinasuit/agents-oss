package com.geekinasuit.agency.shared.auth

import com.geekinasuit.agency.shared.json.onSmallStack
import java.security.MessageDigest
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
    // only an anchor if the expected bytes were written independently of the codec. The
    // domain tag leads, encoded as a JSON string like every other field.
    assertEquals(
      """["agency/gate-approval/v1","pk-1","g1","d1","n1"]""",
      committedPreimage(publicKey = "pk-1", gateId = "g1", payloadDigest = "d1", nonce = "n1"),
    )
  }

  @Test
  fun committedPreimageBytesMatchThePinnedGoldenVector() {
    // The golden vector: the UTF-8 bytes of the preimage for a fixed input, and their sha256
    // (the message a bip340 approver actually signs). Both hex strings were computed outside
    // the codec (xxd and shasum over the hand-written literal above), so any future change to
    // the tag, the field order, or the encoding fails here before it can strand a signature.
    val preimage = committedPreimage("pk-1", "g1", "d1", "n1")
    val bytes = preimage.toByteArray(Charsets.UTF_8)
    assertEquals(
      "5b226167656e63792f676174652d617070726f76616c2f7631222c22706b2d31222c226731222c" +
        "226431222c226e31225d",
      hex(bytes),
    )
    assertEquals(
      "5eab71ebe4cd1b826c537cb91fab0d4eb2dd08e5c2733f5e3236f14ce5ae0db5",
      hex(MessageDigest.getInstance("SHA-256").digest(bytes)),
    )
  }

  @Test
  fun committedPreimageEscapingMatchesThePinnedGoldenVector() {
    // The ASCII vector above cannot see an escaping change, and parseCommitted refuses any
    // bytes that are not exactly what the encoder emits, so a change in how the encoder escapes
    // would silently refuse every stored approval with such a field. These fields pin it: a
    // non-ASCII letter (emitted raw), a quote and a backslash (short escapes), a slash (emitted
    // raw), and a newline (short escape). The literal and both hex strings were written and
    // computed outside the codec (xxd and shasum over the literal).
    val preimage = committedPreimage("pk-é", "g\"/1", "d\\1", "n\n1")
    assertEquals("""["agency/gate-approval/v1","pk-é","g\"/1","d\\1","n\n1"]""", preimage)
    val bytes = preimage.toByteArray(Charsets.UTF_8)
    assertEquals(
      "5b226167656e63792f676174652d617070726f76616c2f7631222c22706b2dc3a9222c22675c222f3122" +
        "2c22645c5c31222c226e5c6e31225d",
      hex(bytes),
    )
    assertEquals(
      "c4b7aecc61595ef8868ebedf240e830f07fde8d9e6eaec0b39838de0f2aa6ff3",
      hex(MessageDigest.getInstance("SHA-256").digest(bytes)),
    )
    assertEquals(CommittedApproval("pk-é", "g\"/1", "d\\1", "n\n1"), parseCommitted(preimage))
  }

  @Test
  fun theApprovalDomainTagIsPinned() {
    // Changing the constant invalidates every existing approval signature, so its value is
    // pinned here as well as inside the golden vector.
    assertEquals("agency/gate-approval/v1", APPROVAL_DOMAIN_TAG)
  }

  @Test
  fun parseRejectsAnUntaggedPreimage() {
    // The pre-tag shape: the same four committed fields with no domain tag. A signature over
    // these bytes was made for no stated purpose, so the fold must not read an approval out of
    // them — null here is what turns such a signature into "unverified".
    assertNull(parseCommitted("""["pk-1","g1","d1","n1"]"""))
  }

  @Test
  fun parseRejectsAPreimageUnderAnotherDomainTag() {
    // Right shape, wrong purpose: a later version of this structure, or another purpose's tag,
    // or the tag's own spelling varied. None binds a gate approval at v1.
    assertNull(parseCommitted("""["agency/gate-approval/v2","pk-1","g1","d1","n1"]"""))
    assertNull(parseCommitted("""["agency/authorization-spec/v1","pk-1","g1","d1","n1"]"""))
    assertNull(parseCommitted("""["AGENCY/GATE-APPROVAL/V1","pk-1","g1","d1","n1"]"""))
    assertNull(parseCommitted("""["agency/gate-approval/v1 ","pk-1","g1","d1","n1"]"""))
    assertNull(parseCommitted("""["","pk-1","g1","d1","n1"]"""))
  }

  @Test
  fun parseRejectsANonCanonicalSpellingOfTheSameFields() {
    // Each decodes to the same five strings as the canonical form, but is not its bytes: a
    // signature over one of these binds bytes no canonical signer emits.
    assertNull(parseCommitted("""[ "agency/gate-approval/v1", "pk-1", "g1", "d1", "n1" ]"""))
    // The tag's first letter as a JSON unicode escape (backslash, then u0061).
    val escapedA = Char(0x5C) + "u0061"
    assertNull(parseCommitted("""["${escapedA}gency/gate-approval/v1","pk-1","g1","d1","n1"]"""))
    assertNull(parseCommitted("""["agency\/gate-approval\/v1","pk-1","g1","d1","n1"]"""))
    assertNull(parseCommitted("\n" + committedPreimage("pk-1", "g1", "d1", "n1") + "\n"))
    // Positive control: the canonical bytes of those same fields parse.
    assertEquals(
      CommittedApproval("pk-1", "g1", "d1", "n1"),
      parseCommitted(committedPreimage("pk-1", "g1", "d1", "n1")),
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
    // Tagged, so each is refused for its arity alone.
    assertNull(parseCommitted("""["agency/gate-approval/v1","pk","g1","d1"]"""))
    assertNull(parseCommitted("""["agency/gate-approval/v1","pk","g1","d1","n1","extra"]"""))
    assertNull(parseCommitted("""["agency/gate-approval/v1"]"""))
  }

  @Test
  fun parseRejectsNonStringElement() {
    assertNull(parseCommitted("""["agency/gate-approval/v1","pk","g1","d1",123]"""))
    assertNull(parseCommitted("""["agency/gate-approval/v1","pk","g1",["d1"],"n1"]"""))
  }

  @Test
  fun parseRejectsBlankField() {
    assertNull(parseCommitted("""["agency/gate-approval/v1","pk","g1","d1",""]"""))
    assertNull(parseCommitted("""["agency/gate-approval/v1"," ","g1","d1","n1"]"""))
  }

  @Test
  fun parseIsTotalOnGarbage() {
    // Never throws — a hostile or truncated preimage folds to "unverified", not a boot crash.
    assertNull(parseCommitted("not json{"))
    assertNull(parseCommitted(""))
  }

  @Test
  fun parseRefusesADeeplyNestedPreimageBeforeTheParserCanOverflow() {
    // A preimage is untrusted text until a signature over it verifies, and a caller may parse it
    // first. Parsing this one would overflow this small stack, so a null here means parseCommitted
    // refused it before parsing.
    assertNull(onSmallStack { parseCommitted("[".repeat(60_000)) })
  }

  @Test
  fun parseRefusesAPreimageThatContinuesPastItsClosersBeforeTheParserCanOverflow() {
    // kotlinx keeps reading an array after its `]` when a value follows, so the parser nests this
    // preimage one level per `[1]` although its brackets never nest past one. Parsing it would
    // overflow this small stack.
    assertNull(onSmallStack { parseCommitted("[1]".repeat(20_000)) })
  }

  @Test
  fun bracketsQuotesAndBackslashesInsideAFieldAreContentNotNesting() {
    // The depth bound counts only structural brackets, so committed fields full of them still nest
    // one level and parse back exactly; a plain bracket count would refuse them.
    val committed = CommittedApproval("pk-[[[[", "g{{{1", "d\"]]}}", "n\\[\\\"[")
    val preimage =
      committedPreimage(committed.publicKey, committed.gateId, committed.payloadDigest, committed.nonce)
    assertEquals(committed, parseCommitted(preimage))
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

  private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}
