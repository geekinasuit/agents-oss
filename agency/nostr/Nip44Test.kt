package com.geekinasuit.agency.nostr

import fr.acinq.secp256k1.Secp256k1
import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The production NIP-44 v2 codec, checked against the specification's own published vectors and
 * against the properties the reference probe could not assert.
 *
 * Every valid-vector assertion runs THROUGH [Nip44]'s own API rather than a second run of our
 * code, so a self-consistent-but-wrong codec fails. Beyond the vectors this adds what production
 * owes and the probe did not: that a malformed payload returns `null` rather than throwing (the
 * totality contract a hostile relay input relies on), that the shared-point primitive is point
 * multiplication and not the library's hashing ecdh (the trap, pinned in THIS module), that a
 * fresh nonce is drawn per message, that the 16-bit length ceiling is enforced at both ends, and
 * that the helpers the codec zeroes its derived key material with do zero it. That the codec's
 * own paths call those helpers is checked by reading: a test has no handle on an array the codec
 * creates and drops inside one call.
 *
 * The vector file is agency/crypto/testdata/nip44.vectors.json — the spec's own file, shared
 * rather than copied so its published SHA-256 stays a single source of truth. It arrives via the
 * NIP44_VECTORS env var the build fills with a runfiles path.
 */
class Nip44Test {
    private val secp = Secp256k1.get()

    private val vectors: JSONObject by lazy {
        val srcdir = System.getenv("TEST_SRCDIR") ?: error("TEST_SRCDIR not set (not under bazel test)")
        val rloc = System.getenv("NIP44_VECTORS") ?: error("NIP44_VECTORS not set (the test target supplies it)")
        val f = File(srcdir, rloc)
        check(f.exists()) { "vector file not found in runfiles at $f" }
        JSONObject(f.readText()).getJSONObject("v2")
    }

    private fun valid(name: String) = vectors.getJSONObject("valid").getJSONArray(name)

    private fun invalid(name: String) = vectors.getJSONObject("invalid").getJSONArray(name)

    private fun messageKeyVectors() = vectors.getJSONObject("valid").getJSONObject("get_message_keys")

    /** The x-only public key for a private key, as NIP-44 names a counterparty. */
    private fun publicKeyOf(privateKeyHex: String): ByteArray =
        secp.pubkeyCreate(Hex.decode(privateKeyHex)).copyOfRange(1, 33)

    /** True if [block] refuses its input by throwing — the shape a `require` failure takes. */
    private fun refused(block: () -> Unit): Boolean =
        try {
            block()
            false
        } catch (_: Exception) {
            true
        }

    @Test
    fun `the vector file parses and still contains what these assertions cover`() {
        // Same fixture guard as the probe: an upstream restructuring must fail loudly rather than
        // reduce a suite to zero green iterations.
        assertEquals("conversation-key vectors", 35, valid("get_conversation_key").length())
        assertEquals("message-key vectors", 32, messageKeyVectors().getJSONArray("keys").length())
        assertEquals("padding vectors", 24, valid("calc_padded_len").length())
        assertEquals("encrypt/decrypt vectors", 10, valid("encrypt_decrypt").length())
        assertEquals("invalid conversation-key vectors", 8, invalid("get_conversation_key").length())
        assertEquals("invalid decrypt vectors", 12, invalid("decrypt").length())
    }

    @Test
    fun `the conversation key matches the spec for every vector`() {
        val arr = valid("get_conversation_key")
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            val key = Nip44.conversationKey(
                ourPrivateKey = Hex.decode(v.getString("sec1")),
                theirXOnlyPublicKey = Hex.decode(v.getString("pub2")),
            )
            assertEquals("conversation-key vector $i", v.getString("conversation_key"), Hex.encode(key))
        }
    }

    @Test
    fun `the shared point is point multiplication, not the library's hashing ecdh`() {
        // The trap named on Nip44.sharedPointX, pinned in THIS module because the probe's copy
        // lives in agency/crypto and does not cover this code. libsecp256k1's ecdh hashes the
        // shared point; NIP-44 needs it raw. Both are 32 bytes, so only an assertion like this
        // distinguishes them, and getting it wrong yields a codec that talks only to itself.
        val v = valid("get_conversation_key").getJSONObject(0)
        val sec1 = Hex.decode(v.getString("sec1"))
        val pub2 = Hex.decode(v.getString("pub2"))

        val compressed = byteArrayOf(0x02.toByte()) + pub2
        val hashedEcdh = secp.ecdh(sec1, secp.pubkeyParse(compressed))
        val rawX = Nip44.sharedPointX(sec1, pub2)

        assertEquals("both are 32 bytes, which is what makes the confusion possible", 32, hashedEcdh.size)
        assertEquals(32, rawX.size)
        assertNotEquals(
            "ecdh() must not be mistaken for the raw shared x coordinate",
            Hex.encode(hashedEcdh),
            Hex.encode(rawX),
        )
    }

    @Test
    fun `the message-key schedule matches the spec for every vector`() {
        // One conversation key serves every vector, so a schedule that zeroed it would fail from
        // the second vector on.
        val group = messageKeyVectors()
        val conversationKey = Hex.decode(group.getString("conversation_key"))
        val keys = group.getJSONArray("keys")
        for (i in 0 until keys.length()) {
            val v = keys.getJSONObject(i)
            Nip44.withMessageKeys(conversationKey, Hex.decode(v.getString("nonce"))) { derived ->
                assertMessageKeys("key $i", v, derived)
            }
        }
    }

    @Test
    fun `the padding schedule matches the spec for every vector`() {
        val arr = valid("calc_padded_len")
        for (i in 0 until arr.length()) {
            val pair = arr.getJSONArray(i)
            assertEquals("padded length for ${pair.getInt(0)}", pair.getInt(1), Nip44.paddedLength(pair.getInt(0)))
        }
    }

    @Test
    fun `encrypting with the vector's nonce reproduces the published payload`() {
        // The strongest available check: NIP-44 is deterministic once the nonce is fixed, so this
        // asserts byte equality with the spec's payload, not a round-trip through our own code. A
        // wrong padding rule, wrong MAC input, or swapped key offset fails here; none would fail a
        // round-trip. The nonce-injecting path is internal, reached here via associates=.
        val arr = valid("encrypt_decrypt")
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            val conversationKey = Nip44.conversationKey(
                ourPrivateKey = Hex.decode(v.getString("sec1")),
                theirXOnlyPublicKey = publicKeyOf(v.getString("sec2")),
            )
            assertEquals(
                "vector $i: conversation key from sec1 and pub(sec2)",
                v.getString("conversation_key"),
                Hex.encode(conversationKey),
            )
            val payload = Nip44.encryptWithNonce(
                plaintext = v.getString("plaintext"),
                conversationKey = conversationKey,
                nonce = Hex.decode(v.getString("nonce")),
            )
            assertEquals("vector $i: payload", v.getString("payload"), payload)
        }
    }

    @Test
    fun `decrypting the published payload recovers the plaintext`() {
        val arr = valid("encrypt_decrypt")
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            // Decrypt as the RECIPIENT — sec2 with pub(sec1) — which also establishes that the
            // conversation key is symmetric: both parties derive it without a handshake.
            val conversationKey = Nip44.conversationKey(
                ourPrivateKey = Hex.decode(v.getString("sec2")),
                theirXOnlyPublicKey = publicKeyOf(v.getString("sec1")),
            )
            assertEquals(
                "vector $i: the conversation key is the same from either side",
                v.getString("conversation_key"),
                Hex.encode(conversationKey),
            )
            assertEquals(
                "vector $i: plaintext",
                v.getString("plaintext"),
                Nip44.decrypt(v.getString("payload"), conversationKey),
            )
        }
    }

    @Test
    fun `every invalid conversation-key vector is refused`() {
        val arr = invalid("get_conversation_key")
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            // Decode the fixture OUTSIDE the refused-block so only the call under test can throw; a
            // throw from Hex.decode would otherwise count as a refusal without the codec running.
            val sec1 = Hex.decode(v.getString("sec1"))
            val pub2 = Hex.decode(v.getString("pub2"))
            assertTrue(
                "invalid conversation-key vector $i must be refused (${v.optString("note")})",
                refused { Nip44.conversationKey(sec1, pub2) },
            )
        }
    }

    @Test
    fun `every invalid payload decrypts to null rather than throwing`() {
        // The production totality contract, and a stronger claim than the probe's "throws OR
        // returns": decrypt is total over hostile input, so each malformed payload must fold to
        // null. A throw here — from base64, a short buffer, or the MAC — is itself a failure.
        val arr = invalid("decrypt")
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            assertNull(
                "invalid decrypt vector $i must be null, not an exception (${v.optString("note")})",
                Nip44.decrypt(v.getString("payload"), Hex.decode(v.getString("conversation_key"))),
            )
        }
    }

    @Test
    fun `the plaintext length ceiling is enforced at both ends`() {
        // NIP-44 v2 frames the plaintext length in 16 bits, so 65535 bytes is the format's hard
        // ceiling. This pins it against a future regression to a wrong bound or an invented wider
        // length branch: the maximal message round-trips, one byte more is refused, and empty is
        // refused. ASCII 'a' is one UTF-8 byte, so char count is byte count here.
        val key = Hex.decode(valid("get_conversation_key").getJSONObject(0).getString("conversation_key"))

        assertTrue("empty plaintext is refused", refused { Nip44.encrypt("", key) })
        assertTrue("one byte over the ceiling is refused", refused { Nip44.encrypt("a".repeat(65536), key) })

        val maximal = "a".repeat(65535)
        assertEquals("a maximal-length message round-trips", maximal, Nip44.decrypt(Nip44.encrypt(maximal, key), key))
    }

    @Test
    fun `a plaintext holding an unpaired surrogate is refused, not encrypted as a question mark`() {
        // An unpaired surrogate has no UTF-8 encoding. A lenient encoder would encrypt '?' in its
        // place, and the recipient would decrypt a different string from the one the caller passed.
        // The plaintext is ours, so this is a local bug and throws, as an empty plaintext does.
        val key = Hex.decode(valid("get_conversation_key").getJSONObject(0).getString("conversation_key"))
        for (lone in listOf(Char(0xD800), Char(0xDC00))) {
            assertThrows("U+${lone.code.toString(16)}", IllegalArgumentException::class.java) {
                Nip44.encrypt("a" + lone + "b", key)
            }
        }
        val pair = "a" + String(Character.toChars(0x1F600)) + "b"
        val roundTripped = Nip44.decrypt(Nip44.encrypt(pair, key), key)
        assertEquals("control: a surrogate pair round-trips", pair, roundTripped)
    }

    @Test
    fun `encrypt draws a fresh nonce for every message`() {
        // Two encryptions of the same plaintext under the same key must differ, and must differ in
        // the nonce specifically — 32 CSPRNG bytes, not a constant. The nonce is bytes [1,33) of
        // the decoded payload (after the 1-byte version). Reuse would reproduce the whole derived
        // key triple and leak both plaintexts, so this is a security property, not a nicety.
        val key = Hex.decode(valid("get_conversation_key").getJSONObject(0).getString("conversation_key"))
        val a = java.util.Base64.getDecoder().decode(Nip44.encrypt("same message", key))
        val b = java.util.Base64.getDecoder().decode(Nip44.encrypt("same message", key))

        val nonceA = a.copyOfRange(1, 33)
        val nonceB = b.copyOfRange(1, 33)
        assertEquals("nonce is 32 bytes", 32, nonceA.size)
        assertEquals("nonce is 32 bytes", 32, nonceB.size)
        assertNotEquals("two messages must not share a nonce", Hex.encode(nonceA), Hex.encode(nonceB))
    }

    @Test
    fun `zeroedAfter zeroes the array whether its block returns or throws`() {
        val returned = ByteArray(32) { 0x5a.toByte() }
        val seen = returned.zeroedAfter { it.copyOf() }
        assertTrue("the block sees the bytes before they are zeroed", seen.all { it == 0x5a.toByte() })
        assertTrue("zeroed once the block returns", returned.isZeroed())

        val thrown = ByteArray(32) { 0x5a.toByte() }
        assertThrows(IllegalStateException::class.java) { thrown.zeroedAfter { error("the block failed") } }
        assertTrue("zeroed once the block throws", thrown.isZeroed())
    }

    @Test
    fun `the shared point and its x coordinate are zeroed once the conversation key is derived`() {
        val v = valid("get_conversation_key").getJSONObject(0)
        val compressed = byteArrayOf(0x02.toByte()) + Hex.decode(v.getString("pub2"))
        val point = secp.pubKeyTweakMul(secp.pubkeyParse(compressed), Hex.decode(v.getString("sec1")))
        assertFalse("the point starts out as key material", point.isZeroed())

        val x = Nip44.xOfSharedPoint(point)
        assertTrue("the point is zeroed once its x is copied out", point.isZeroed())
        assertFalse("x starts out as key material", x.isZeroed())

        val key = Nip44.conversationKeyFromSharedX(x)
        assertEquals("the conversation key is the spec's", v.getString("conversation_key"), Hex.encode(key))
        assertTrue("x is zeroed once the conversation key is derived", x.isZeroed())
    }

    @Test
    fun `the HKDF output is zeroed once it is split into the message keys`() {
        // The spec cuts the three keys from one 76-byte HKDF output, in order, so a vector's three
        // keys concatenated are that output.
        val v = messageKeyVectors().getJSONArray("keys").getJSONObject(0)
        val okm = Hex.decode(v.getString("chacha_key") + v.getString("chacha_nonce") + v.getString("hmac_key"))
        assertEquals("the HKDF output is 76 bytes", 76, okm.size)

        assertMessageKeys("split", v, Nip44.splitMessageKeys(okm))
        assertTrue("the HKDF output is zeroed once split", okm.isZeroed())
    }

    @Test
    fun `the message keys are zeroed once their block returns or throws, and the conversation key is not`() {
        val group = messageKeyVectors()
        val conversationKey = Hex.decode(group.getString("conversation_key"))
        val v = group.getJSONArray("keys").getJSONObject(0)
        val nonce = Hex.decode(v.getString("nonce"))

        val returned =
            Nip44.withMessageKeys(conversationKey, nonce) { keys ->
                assertMessageKeys("in the block", v, keys)
                keys
            }
        assertTrue("zeroed once the block returns", returned.isZeroed())

        var thrown: Nip44.MessageKeys? = null
        assertThrows(IllegalStateException::class.java) {
            Nip44.withMessageKeys(conversationKey, nonce) { keys ->
                thrown = keys
                error("the block failed")
            }
        }
        assertTrue("zeroed once the block throws", thrown!!.isZeroed())
        // A round trip through the public API on the same key, so the check below also covers
        // encrypt and decrypt leaving the caller's key alone, not only withMessageKeys.
        assertEquals(
            "the key round-trips a message",
            "m",
            Nip44.decrypt(Nip44.encrypt("m", conversationKey), conversationKey),
        )
        assertEquals(
            "the caller's conversation key is left as it was",
            group.getString("conversation_key"),
            Hex.encode(conversationKey),
        )
    }

    /** Asserts that [keys] are the message keys message-key vector [v] lists. */
    private fun assertMessageKeys(label: String, v: JSONObject, keys: Nip44.MessageKeys) {
        assertEquals("$label chacha_key", v.getString("chacha_key"), Hex.encode(keys.chachaKey))
        assertEquals("$label chacha_nonce", v.getString("chacha_nonce"), Hex.encode(keys.chachaNonce))
        assertEquals("$label hmac_key", v.getString("hmac_key"), Hex.encode(keys.hmacKey))
    }

    private fun ByteArray.isZeroed(): Boolean = all { it == 0.toByte() }

    private fun Nip44.MessageKeys.isZeroed(): Boolean =
        chachaKey.isZeroed() && chachaNonce.isZeroed() && hmacKey.isZeroed()
}
