package com.geekinasuit.agency.nostr

import com.geekinasuit.agency.shared.auth.committedPreimage
import java.security.MessageDigest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The bip340 authorization verifier against real signatures. The message signed is
 * `sha256(committedPreimage)` — the authorization layer's own preimage, NOT a nostr event id, so
 * this exercises the layer separation directly: the same primitive, a different message than the
 * transport signature. The adversarial cells are the ones that matter — a verifier that accepts
 * a signature over the wrong preimage, or by the wrong key, would pass a round-trip and admit a
 * forged approval.
 */
class Bip340ApprovalVerifierTest {
  private val secretKey = "0000000000000000000000000000000000000000000000000000000000000003"
  private val otherKey = "0000000000000000000000000000000000000000000000000000000000000005"
  private val auxRand = "0000000000000000000000000000000000000000000000000000000000000000"

  private fun sha256Hex(s: String): String =
    MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8)).joinToString("") {
      "%02x".format(it)
    }

  /** A real BIP-340 signature over sha256(preimage), exactly what the adapter re-checks. */
  private fun signOver(preimage: String, sk: String): String =
    Bip340.signHex(sha256Hex(preimage), sk, auxRand)

  @Test
  fun `a real signature over sha256 of the committed preimage verifies`() {
    val pubkey = Bip340.xonlyPubkeyHex(secretKey)
    val preimage = committedPreimage(pubkey, "gate-1", "digest-1", "nonce-1")
    assertTrue(Bip340ApprovalVerifier.verifies("bip340", pubkey, signOver(preimage, secretKey), preimage))
  }

  @Test
  fun `a non-bip340 scheme is refused even with an otherwise valid signature`() {
    val pubkey = Bip340.xonlyPubkeyHex(secretKey)
    val preimage = committedPreimage(pubkey, "gate-1", "digest-1", "nonce-1")
    assertFalse(Bip340ApprovalVerifier.verifies("ed25519", pubkey, signOver(preimage, secretKey), preimage))
  }

  @Test
  fun `a signature over a different committed preimage is refused`() {
    val pubkey = Bip340.xonlyPubkeyHex(secretKey)
    val signed = committedPreimage(pubkey, "gate-1", "digest-1", "nonce-1")
    val sig = signOver(signed, secretKey)
    // Same everything but the nonce — the digest the signature commits to differs, so re-checking
    // the signature against the other preimage must fail (this is the replay/tamper guard).
    val other = committedPreimage(pubkey, "gate-1", "digest-1", "nonce-2")
    assertFalse(Bip340ApprovalVerifier.verifies("bip340", pubkey, sig, other))
  }

  @Test
  fun `a signature by a key other than the named one is refused`() {
    val pubkey = Bip340.xonlyPubkeyHex(secretKey)
    val preimage = committedPreimage(pubkey, "gate-1", "digest-1", "nonce-1")
    val sig = signOver(preimage, secretKey)
    assertFalse(Bip340ApprovalVerifier.verifies("bip340", Bip340.xonlyPubkeyHex(otherKey), sig, preimage))
  }

  @Test
  fun `a malformed key or signature folds to false, never throws`() {
    val pubkey = Bip340.xonlyPubkeyHex(secretKey)
    val preimage = committedPreimage(pubkey, "gate-1", "digest-1", "nonce-1")
    val sig = signOver(preimage, secretKey)
    assertFalse(Bip340ApprovalVerifier.verifies("bip340", "not-hex", sig, preimage))
    assertFalse(Bip340ApprovalVerifier.verifies("bip340", pubkey, "not-hex", preimage))
  }

  @Test
  fun `the scheme tag is matched exactly and case-sensitively`() {
    val pubkey = Bip340.xonlyPubkeyHex(secretKey)
    val preimage = committedPreimage(pubkey, "gate-1", "digest-1", "nonce-1")
    val sig = signOver(preimage, secretKey)
    // The registration contract: only the literal "bip340" is answered; a differently-cased or
    // aliased tag verifies nothing (fail-closed), so a spec must spell the scheme exactly.
    assertFalse(Bip340ApprovalVerifier.verifies("BIP340", pubkey, sig, preimage))
    assertFalse(Bip340ApprovalVerifier.verifies("Bip340", pubkey, sig, preimage))
    assertFalse(Bip340ApprovalVerifier.verifies("bip-340", pubkey, sig, preimage))
  }

  @Test
  fun `a preimage holding an unpaired surrogate does not verify under its question-mark spelling`() {
    // An unpaired surrogate has no UTF-8 encoding. A lenient encoder writes '?' in its place, so a
    // signature over the '?' spelling would verify for the preimage holding the surrogate: a
    // different string from the one the approver signed. A preimage can hold one when it arrives
    // inside JSON, because kotlinx parses a unicode escape without checking surrogate pairing.
    val pubkey = Bip340.xonlyPubkeyHex(secretKey)
    val signed = committedPreimage(pubkey, "gate-1", "digest-1", "nonce-?")
    val sig = signOver(signed, secretKey)
    assertTrue(
      "control: the signed spelling verifies",
      Bip340ApprovalVerifier.verifies("bip340", pubkey, sig, signed),
    )
    for (lone in listOf(Char(0xD800), Char(0xDC00))) {
      val respelled = signed.replace('?', lone)
      assertFalse(
        "U+${lone.code.toString(16)}",
        Bip340ApprovalVerifier.verifies("bip340", pubkey, sig, respelled),
      )
    }
  }

  @Test
  fun `a hex-valid key or signature of the wrong length is refused, not thrown`() {
    val pubkey = Bip340.xonlyPubkeyHex(secretKey)
    val preimage = committedPreimage(pubkey, "gate-1", "digest-1", "nonce-1")
    val sig = signOver(preimage, secretKey)
    // 31- and 33-byte keys, 63- and 65-byte signatures: all decode as hex, none is a valid
    // BIP-340 length. Each must fold to false rather than let the native layer throw — the guard
    // that stops attacker-supplied evidence from crashing the verifier instead of failing closed.
    assertFalse(Bip340ApprovalVerifier.verifies("bip340", "00".repeat(31), sig, preimage))
    assertFalse(Bip340ApprovalVerifier.verifies("bip340", "00".repeat(33), sig, preimage))
    assertFalse(Bip340ApprovalVerifier.verifies("bip340", pubkey, "00".repeat(63), preimage))
    assertFalse(Bip340ApprovalVerifier.verifies("bip340", pubkey, "00".repeat(65), preimage))
  }
}
