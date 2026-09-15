package com.geekinasuit.agency.shared.auth

import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SpecValidationTest {
  // A deterministic stand-in for a real signature scheme (schnorr lands at step 3): a signature
  // is "sig:" + sha256(schemeId | publicKey | preimage), so it binds to the exact signer AND
  // the exact bytes. DISCRIMINATING on purpose — a blanket-accept verifier would make "tampered
  // → refused" and the pin-is-external pair vacuous.
  private fun sha256(s: String): String =
    MessageDigest.getInstance("SHA-256")
      .digest(s.toByteArray(Charsets.UTF_8))
      .joinToString("") { "%02x".format(it) }

  private fun sign(key: SchemeKey, preimage: String): String =
    "sig:" + sha256("${key.schemeId}|${key.publicKey}|$preimage")

  private val testVerifier =
    ApprovalVerifier { schemeId, publicKey, signature, preimage ->
      signature == "sig:" + sha256("$schemeId|$publicKey|$preimage")
    }

  // R is the deployment root; X is a key the attacker plants INSIDE the spec; Y is an unrelated
  // pin. X and Y differ only so that flipping the pin is the only variable in cell 5.
  private val rootKey = SchemeKey("bip340", "root-pub")
  private val keyX = SchemeKey("bip340", "principal-x-pub")
  private val keyY = SchemeKey("bip340", "unrelated-y-pub")

  private val principals =
    listOf(
      Principal("council", "approver", listOf(SchemeKey("bip340", "council-pub"))),
      Principal("ops", "approver", listOf(SchemeKey("bip340", "ops-pub"))),
    )
  private val quorum: QuorumNode = oneOfOne("council")

  private fun signedBy(key: SchemeKey, preimage: String) =
    AuthorizationSpec(rootSignature = sign(key, preimage), specPreimage = preimage)

  private fun loaded(r: SpecLoadResult): SpecLoadResult.Loaded {
    assertTrue("expected Loaded, got $r", r is SpecLoadResult.Loaded)
    return r as SpecLoadResult.Loaded
  }

  private fun refused(r: SpecLoadResult): SpecLoadResult.Refused {
    assertTrue("expected Refused, got $r", r is SpecLoadResult.Refused)
    return r as SpecLoadResult.Refused
  }

  // The attacker's spec: it contains a principal whose key is X, and it is self-signed by X.
  // Built once, deterministically, so cells 5a/5b/6 all load byte-identical bytes and the ONLY
  // thing that varies between them is the pin (5a vs 5b) or the verifier (6).
  private val plantedPrincipals =
    listOf(
      Principal("planted", "approver", listOf(keyX)),
      Principal("ops", "approver", listOf(SchemeKey("bip340", "ops-pub"))),
    )
  private val plantedQuorum: QuorumNode = oneOfOne("planted")

  private fun specSelfSignedByX(): AuthorizationSpec =
    signedBy(keyX, authSpecPreimage(plantedPrincipals, plantedQuorum))

  // 1 — a valid root-signed spec loads, and the recovered allow-list + quorum are what was signed.
  @Test
  fun validRootSignedSpecLoads() {
    val preimage = authSpecPreimage(principals, quorum)
    val result = loaded(loadAuthorizationSpec(signedBy(rootKey, preimage), rootKey, testVerifier))
    assertEquals(
      "council",
      result.allowList.principalFor(SchemeKey("bip340", "council-pub"))?.principalId,
    )
    assertEquals("ops", result.allowList.principalFor(SchemeKey("bip340", "ops-pub"))?.principalId)
    assertEquals(quorum, result.quorum)
  }

  // 2 — an unsigned (empty or garbage) signature never verifies, so the spec is refused.
  @Test
  fun unsignedSpecIsRefused() {
    val preimage = authSpecPreimage(principals, quorum)
    refused(loadAuthorizationSpec(AuthorizationSpec("", preimage), rootKey, testVerifier))
    refused(loadAuthorizationSpec(AuthorizationSpec("garbage", preimage), rootKey, testVerifier))
  }

  // 3 — the A4-8 threat itself: an attacker appends a principal to the SIGNED bytes. The root's
  // signature was over the original allow-list, so the tampered preimage no longer verifies.
  @Test
  fun addingAPrincipalToSignedBytesIsRefused() {
    val original = authSpecPreimage(principals, quorum)
    val sigOverOriginal = sign(rootKey, original)
    val tampered =
      authSpecPreimage(principals + Principal("attacker", "approver", listOf(keyX)), quorum)
    val result =
      loadAuthorizationSpec(
        AuthorizationSpec(rootSignature = sigOverOriginal, specPreimage = tampered),
        rootKey,
        testVerifier,
      )
    refused(result)
  }

  // 4 — plain wrong-root: signed by a key ABSENT from the spec, pinned to a different key. The
  // signer isn't named inside; this is the mechanical pin-mismatch, distinct from cell 5.
  @Test
  fun wrongRootAbsentFromSpecIsRefused() {
    val preimage = authSpecPreimage(principals, quorum)
    // keyY signs; nothing in `principals` holds keyY. Pinned to rootKey (≠ keyY) → refused.
    refused(loadAuthorizationSpec(signedBy(keyY, preimage), rootKey, testVerifier))
  }

  // 5a — pin-is-external DISCRIMINATOR, baseline. The spec names X internally and is self-signed
  // by X; pinned to X → Loaded. (Half a proof on its own; the contrast with 5b is the proof.)
  @Test
  fun pinIsExternal_loadsWhenPinnedToTheKeyTheSpecNames() {
    loaded(loadAuthorizationSpec(specSelfSignedByX(), keyX, testVerifier))
  }

  // 5b — pin-is-external DISCRIMINATOR, the load-bearing half. BYTE-IDENTICAL spec + signature
  // to 5a (same specSelfSignedByX()); only the pin changes, to Y. Refused. Flipping ONLY the pin
  // flips the outcome while the spec's internal content and signature are unchanged ∴ the
  // verification key tracks the PIN, never the key the spec names. If any path let a spec
  // nominate its root, this would ALSO Load (spec names X, signed by X, self-consistent) — its
  // refusal, against 5a's load, is the proof the pin is external. [A4-8]
  @Test
  fun pinIsExternal_refusesWhenPinnedElsewhereEvenThoughSpecSelfSignsWithANamedKey() {
    refused(loadAuthorizationSpec(specSelfSignedByX(), keyY, testVerifier))
  }

  // 6 — the verifier is load-bearing: the exact spec that Loads in 5a is Refused under
  // RejectingVerifier (the honest default), so a substrate with no real verifier admits nothing.
  @Test
  fun rejectingVerifierRefusesASpecThatWouldOtherwiseLoad() {
    loaded(loadAuthorizationSpec(specSelfSignedByX(), keyX, testVerifier))
    refused(loadAuthorizationSpec(specSelfSignedByX(), keyX, RejectingVerifier))
  }

  // 7 — root-signed but structurally invalid still fails closed: verify passing does NOT waive
  // the parse. The preimage is a validly signed JSON array of the wrong shape (no quorum half).
  @Test
  fun malformedContentUnderValidRootSigIsRefused() {
    val malformed = """[[["p1","approver",[["bip340","k1"]]]]]""" // size 1: principals, no quorum
    refused(loadAuthorizationSpec(signedBy(rootKey, malformed), rootKey, testVerifier))
  }

  // 7b — parseAuthSpec is TOTAL: hostile/garbage text folds to Refused, never throws.
  @Test
  fun parseAuthSpecIsTotalOnGarbage() {
    refused(parseAuthSpec("not json at all"))
    refused(parseAuthSpec("{}")) // object, not the [principals, quorum] array
    refused(parseAuthSpec("")) // empty
    refused(parseAuthSpec("[1,2,3]")) // array of wrong shape
  }

  // 8 — round-trip AND a hand-written canonical-form anchor. The round-trip proves the codec
  // recovers what it wrote; the literal proves the exact bytes (a provenance anchor step 5's
  // offline signer depends on, not codec self-agreement).
  @Test
  fun roundTripsAndPinsTheCanonicalForm() {
    val pre = authSpecPreimage(principals, quorum)
    val recovered = loaded(parseAuthSpec(pre))
    assertEquals(
      "council",
      recovered.allowList.principalFor(SchemeKey("bip340", "council-pub"))?.principalId,
    )
    // role too: cell 8b pins the ENCODER's bytes, not the parser's field mapping — a parser
    // reading role from the wrong array position would pass 8b but corrupt the recovered principal.
    assertEquals("approver", recovered.allowList.byId("council")?.role)
    assertEquals(quorum, recovered.quorum)

    val one = listOf(Principal("p1", "council", listOf(SchemeKey("bip340", "key1"))))
    assertEquals(
      "[[[\"p1\",\"council\",[[\"bip340\",\"key1\"]]]]," +
        "{\"type\":\"group\",\"threshold\":1,\"children\":[{\"type\":\"signer\",\"principalId\":\"p1\"}]}]",
      authSpecPreimage(one, oneOfOne("p1")),
    )
  }

  // 9 — canonicalization is load-bearing (sort stability). Same principals in different input
  // order, and same keys in different order within a principal, both produce byte-identical
  // output. Without the sort this passes only by construction habit and step 5's offline signer
  // breaks when a caller assembles the list differently.
  @Test
  fun canonicalizationIsOrderIndependent() {
    val a = Principal("aaa", "approver", listOf(SchemeKey("bip340", "ka")))
    val b = Principal("bbb", "approver", listOf(SchemeKey("bip340", "kb")))
    val c = Principal("ccc", "approver", listOf(SchemeKey("bip340", "kc")))
    val q = oneOfOne("aaa")
    assertEquals(authSpecPreimage(listOf(a, b, c), q), authSpecPreimage(listOf(c, a, b), q))

    val keysForward =
      Principal("p", "approver", listOf(SchemeKey("bip340", "k1"), SchemeKey("bip340", "k2")))
    val keysReversed =
      Principal("p", "approver", listOf(SchemeKey("bip340", "k2"), SchemeKey("bip340", "k1")))
    assertEquals(
      authSpecPreimage(listOf(keysForward), oneOfOne("p")),
      authSpecPreimage(listOf(keysReversed), oneOfOne("p")),
    )
  }
}
