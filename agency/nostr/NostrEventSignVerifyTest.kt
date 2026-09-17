package com.geekinasuit.agency.nostr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Sign → verify over the real BIP-340 primitive, and the ways a hostile relay's tampering must
 * fail. The primitive itself is spec-vector-tested in agency/crypto; these cells test the codec
 * wiring — that verification recomputes the id from the fields (so content is bound to the id)
 * and then checks the signature over that id.
 */
class NostrEventSignVerifyTest {
  // Small valid secret keys (scalars 3 and 5); the derived x-only pubkeys are what the events
  // carry. aux randomness fixed at zero so signing is deterministic in the test.
  private val secretKey = "0000000000000000000000000000000000000000000000000000000000000003"
  private val auxRand = "0000000000000000000000000000000000000000000000000000000000000000"

  @Test
  fun `a signed event verifies and carries its derived pubkey`() {
    val ev = signEvent(secretKey, 1700000000L, 1, listOf(listOf("e", "x")), "hello", auxRand)
    assertEquals(Bip340.xonlyPubkeyHex(secretKey), ev.pubkey)
    assertTrue(ev.verify())
  }

  @Test
  fun `tampering with content fails because the id no longer matches the fields`() {
    val ev = signEvent(secretKey, 1700000000L, 1, listOf(listOf("e", "x")), "hello", auxRand)
    assertFalse(ev.copy(content = "tampered").verify())
  }

  @Test
  fun `a substituted id fails because the id is recomputed from the fields`() {
    val ev = signEvent(secretKey, 1700000000L, 1, emptyList(), "hello", auxRand)
    assertFalse(ev.copy(id = "00".repeat(32)).verify())
  }

  @Test
  fun `content swapped with a matching recomputed id still fails on the signature`() {
    // The relay's strongest move: change content AND recompute the id so id == sha256(fields),
    // but it cannot re-sign without the key. The signature commits to the OLD id, so it fails.
    val ev = signEvent(secretKey, 1700000000L, 1, emptyList(), "hello", auxRand)
    val forgedId = Nip01.eventId(ev.pubkey, ev.createdAt, ev.kind, ev.tags, "swapped")
    assertFalse(ev.copy(content = "swapped", id = forgedId).verify())
  }

  @Test
  fun `a malformed signature folds to false, never throws`() {
    val ev = signEvent(secretKey, 1700000000L, 1, emptyList(), "hello", auxRand)
    // The signature does not feed the id, so id still matches and verification reaches the
    // BIP-340 check with un-decodable hex — which must fold to false, not throw.
    assertFalse(ev.copy(sig = "xyz").verify())
  }

  @Test
  fun `Bip340 verify refuses a wrong-length message or signature without throwing`() {
    val ev = signEvent(secretKey, 1700000000L, 1, emptyList(), "hello", auxRand)
    // Hex-valid but wrong lengths: a 31-byte message and a 63-byte signature. The wrapper must
    // return false, never propagate a native throw — pinning the contract both callers rely on
    // rather than trusting libsecp256k1's argument validation unverified.
    assertFalse(Bip340.verify(ev.sig, "00".repeat(31), ev.pubkey))
    assertFalse(Bip340.verify("00".repeat(63), ev.id, ev.pubkey))
  }

  @Test
  fun `signEvent over key bytes produces the identical event to the hex overload`() {
    // The #42 clearable-key path signs from bytes; it must produce the same event as the hex path,
    // proving the byte cores are a behaviour-preserving extract. The hex key is secret scalar 3, so
    // its bytes are 31 zeros then 0x03.
    val secretKeyBytes = ByteArray(32).also { it[31] = 3 }
    val fromHex = signEvent(secretKey, 1700000000L, 1, listOf(listOf("e", "x")), "hello", auxRand)
    val fromBytes = signEvent(secretKeyBytes, 1700000000L, 1, listOf(listOf("e", "x")), "hello", auxRand)
    assertEquals(fromHex, fromBytes)
  }
}
