package com.geekinasuit.agency.nostr

import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.SpecLoadResult
import com.geekinasuit.agency.shared.auth.loadAuthorizationSpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Signing an authorization spec with a bip340 root: what the operator writes, signed, round-trips
 * through the file a lead reads and loads under the root's public key; and the specs that would
 * load badly or never work are refused at signing time, before anything is deployed.
 */
class AuthSpecSigningTest {

  private fun hex(n: Int) = n.toString(16).padStart(64, '0')

  private fun bytes(hex: String) = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

  private val rootSecret = hex(11)
  private val rootPub = Bip340.xonlyPubkeyHex(rootSecret)
  private val operatorPub = Bip340.xonlyPubkeyHex(hex(3))
  private val secondPub = Bip340.xonlyPubkeyHex(hex(7))
  private val aux = "0".repeat(64)

  private fun spec(principals: String, quorum: String = """{"type":"signer","principalId":"operator"}""") =
    """{"principals":[$principals],"quorum":$quorum}"""

  private fun principal(id: String, pub: String) =
    """{"principalId":"$id","role":"approver","keys":[{"schemeId":"bip340","publicKey":"$pub"}]}"""

  private fun signed(text: String) =
    AuthSpecSigning.parse(text).let { (p, q) -> AuthSpecSigning.sign(p, q, bytes(rootSecret), aux) }

  @Test
  fun aSignedSpecRoundTripsThroughItsFileAndLoadsUnderTheRoot() {
    val file = AuthSpecSigning.toJson(signed(spec(principal("operator", operatorPub))))
    val read = checkNotNull(AuthSpecSigning.fromJson(file))
    val loaded = loadAuthorizationSpec(read, SchemeKey("bip340", rootPub), Bip340ApprovalVerifier)
    assertTrue("$loaded", loaded is SpecLoadResult.Loaded)
    assertEquals("operator", (loaded as SpecLoadResult.Loaded).allowList.principalFor(SchemeKey("bip340", operatorPub))?.principalId)
  }

  @Test
  fun aPrincipalWithABip340KeyBesideAnotherSchemesIsAccepted() {
    val mixed =
      """{"principalId":"operator","role":"approver","keys":[""" +
        """{"schemeId":"bip340","publicKey":"$operatorPub"},{"schemeId":"other-scheme","publicKey":"k"}]}"""
    signed(spec(mixed))
  }

  @Test
  fun theOrderTheOperatorWroteDoesNotChangeWhatIsSigned() {
    val a = principal("operator", operatorPub)
    val b = principal("second", secondPub)
    assertEquals(signed(spec("$a,$b")).specPreimage, signed(spec("$b,$a")).specPreimage)
  }

  @Test
  fun aSpecThatWouldLoadBadlyOrNeverWorkIsRefusedAtSigning() {
    // Each refusal, with the words its reason must carry.
    val refused =
      listOf(
        spec(principal("operator", operatorPub.uppercase())) to "64 lowercase hex digits",
        spec(principal("operator", "0".repeat(63) + "5")) to "names a point on secp256k1",
        spec(principal("operator", operatorPub) + "," + principal("operator", secondPub)) to "duplicate principalId",
        spec(principal("operator", operatorPub), """{"type":"signer","principalId":"stranger"}""") to "does not list: stranger",
        spec(principal("operator", operatorPub).replace("\"bip340\"", "\"BIP340\"")) to "could never approve: operator",
        """{"quorum":{"type":"signer","principalId":"operator"}}""" to "no principals array",
        "principals: operator" to "not JSON",
      )
    for ((text, reason) in refused) {
      val x = assertThrows(text, IllegalArgumentException::class.java) { signed(text) }
      assertTrue("'${x.message}' should say '$reason'", x.message!!.contains(reason))
    }
  }

  @Test
  fun aSpecSignedByAnotherRootDoesNotLoadUnderThisOne() {
    val read = AuthSpecSigning.fromJson(AuthSpecSigning.toJson(signed(spec(principal("operator", operatorPub)))))!!
    val other = SchemeKey("bip340", Bip340.xonlyPubkeyHex(hex(13)))
    assertTrue(loadAuthorizationSpec(read, other, Bip340ApprovalVerifier) is SpecLoadResult.Refused)
  }

  @Test
  fun aFileThatIsNotASignedSpecReadsAsNothing() {
    for (text in listOf("", "{}", """{"rootSignature":1,"specPreimage":"x"}""", """{"rootSignature":"s"}""", "[[]]")) {
      assertNull(text, AuthSpecSigning.fromJson(text))
    }
  }
}
