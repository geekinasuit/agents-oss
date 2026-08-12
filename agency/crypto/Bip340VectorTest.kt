package com.geekinasuit.agency.crypto

import fr.acinq.secp256k1.Secp256k1
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * BIP-340 schnorr sign and verify, checked against the BIP's own published vectors.
 *
 * Three separable things this establishes, in the order they can fail:
 *
 *  1. The libsecp256k1 natives load on this platform at all. The aggregate `-jni-jvm`
 *     coordinate pulls the darwin/linux/mingw platform jars and its loader picks the matching
 *     one off the classpath at runtime; no other dependency in this module ships native code,
 *     so a load failure here is the module's only platform-shaped failure mode and is worth
 *     isolating in its own target.
 *  2. Signing is spec-exact, not merely self-consistent. With aux_rand fixed, BIP-340 signing
 *     is deterministic and the spec publishes the expected signature, so this asserts equality
 *     with the published bytes rather than that sign-then-verify agrees with itself. A
 *     signature produced here is therefore verifiable by any other BIP-340 implementation —
 *     which is the property the authorization layer's evidence record actually promises.
 *  3. Verification REFUSES every invalid case the spec lists. This is the half that matters:
 *     a verifier that accepts everything passes a round-trip test and accepts a forged
 *     approval. Ten of the vectors used here are negative.
 *
 * Scope: only the 32-byte-message vectors. Nostr signs a 32-byte event id, so the fixed-32
 * path is the entire requirement and `schnorrsig_sign32` is the matching primitive. The
 * variable-length vectors are named and excluded in testdata/PROVENANCE.md rather than
 * quietly dropped, and the counts below fail if the filter ever empties out.
 */
class Bip340VectorTest {
    private val secp = Secp256k1.get()

    private data class Vector(
        val index: Int,
        val secretKey: String,
        val publicKey: String,
        val auxRand: String,
        val message: String,
        val signature: String,
        val shouldVerify: Boolean,
        val comment: String,
    )

    private val vectors: List<Vector> by lazy {
        ProbeVectors.read("bip340-test-vectors.csv")
            .lineSequence()
            .drop(1) // header
            .filter { it.isNotBlank() }
            .map { line ->
                // The trailing comment column can contain no commas in this file, but split
                // with a limit anyway so a future comment containing one cannot shift columns.
                val c = line.split(",", limit = 8)
                check(c.size == 8) { "expected 8 columns, got ${c.size}: $line" }
                Vector(
                    index = c[0].toInt(),
                    secretKey = c[1],
                    publicKey = c[2],
                    auxRand = c[3],
                    message = c[4],
                    signature = c[5],
                    shouldVerify = when (c[6]) {
                        "TRUE" -> true
                        "FALSE" -> false
                        else -> error("unparseable verification result '${c[6]}' in: $line")
                    },
                    comment = c[7],
                )
            }
            .toList()
    }

    /** The vectors whose message is exactly 32 bytes — see the class comment for why. */
    private val fixed32: List<Vector> by lazy { vectors.filter { it.message.length == 64 } }

    @Test
    fun `the vector file parses and still contains what these assertions cover`() {
        // A guard on the fixture, not on the crypto: an upstream edit that renamed a column or
        // dropped the negative cases would otherwise turn this suite green by vacuity.
        assertEquals("total vectors parsed", 19, vectors.size)
        assertEquals("32-byte-message vectors", 15, fixed32.size)
        assertEquals("of those, signable (secret key present)", 4, fixed32.count { it.secretKey.isNotEmpty() })
        assertEquals("of those, must-reject", 10, fixed32.count { !it.shouldVerify })
    }

    @Test
    fun `signing reproduces the published signature byte for byte`() {
        val signable = fixed32.filter { it.secretKey.isNotEmpty() }
        for (v in signable) {
            val sig = secp.signSchnorr(
                ProbeVectors.decodeHex(v.message),
                ProbeVectors.decodeHex(v.secretKey),
                ProbeVectors.decodeHex(v.auxRand),
            )
            assertEquals(
                "vector ${v.index}: signature must equal the spec's published bytes",
                v.signature.lowercase(),
                ProbeVectors.encodeHex(sig),
            )
        }
    }

    @Test
    fun `the derived public key matches the vector's x-only key`() {
        // pubkeyCreate returns a 65-byte uncompressed point; BIP-340 names a key by its
        // 32-byte x coordinate alone. Establishing this conversion here is what lets the
        // authorization layer treat a principal id as 32 opaque bytes.
        val signable = fixed32.filter { it.secretKey.isNotEmpty() }
        for (v in signable) {
            val full = secp.pubkeyCreate(ProbeVectors.decodeHex(v.secretKey))
            assertEquals("vector ${v.index}: uncompressed point is 65 bytes", 65, full.size)
            val xOnly = full.copyOfRange(1, 33)
            assertEquals(
                "vector ${v.index}: x-only public key",
                v.publicKey.lowercase(),
                ProbeVectors.encodeHex(xOnly),
            )
        }
    }

    @Test
    fun `verification accepts every valid vector and refuses every invalid one`() {
        for (v in fixed32) {
            // An invalid public key or signature can be rejected either by returning false or
            // by throwing out of the native layer; both are refusals, and treating a throw as
            // a test error would make the suite fail on correct behaviour.
            val accepted = try {
                secp.verifySchnorr(
                    ProbeVectors.decodeHex(v.signature),
                    ProbeVectors.decodeHex(v.message),
                    ProbeVectors.decodeHex(v.publicKey),
                )
            } catch (e: Exception) {
                false
            }
            if (v.shouldVerify) {
                assertTrue("vector ${v.index} must verify", accepted)
            } else {
                assertFalse("vector ${v.index} must be refused (${v.comment})", accepted)
            }
        }
    }
}
