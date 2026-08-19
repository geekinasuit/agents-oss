package com.geekinasuit.agency.crypto

import fr.acinq.secp256k1.Secp256k1
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * NIP-44 v2, checked against the specification's own published vectors.
 *
 * The question this answers is narrower than it looks, and worth stating precisely: not "is
 * our codec correct" — there is no codec yet — but "can this platform produce and read the
 * exact bytes the spec defines, using the crypto library we picked". Those are separable, and
 * only the second gates the plan. Every assertion here compares against published values
 * rather than against a second run of our own code, so a self-consistent-but-wrong
 * implementation fails.
 *
 * See [Nip44Reference] for what is borrowed and what is ours; the short version is that the
 * library contributes one operation, the JDK contributes three, and the rest is a key
 * schedule and a padding rule.
 */
class Nip44VectorTest {
    private val vectors: JSONObject by lazy {
        JSONObject(ProbeVectors.read("nip44.vectors.json")).getJSONObject("v2")
    }

    private fun valid(name: String) = vectors.getJSONObject("valid").getJSONArray(name)

    private fun invalid(name: String) = vectors.getJSONObject("invalid").getJSONArray(name)

    /** Unlike its neighbours this vector is one object — a conversation key and its keys. */
    private fun messageKeyVectors() = vectors.getJSONObject("valid").getJSONObject("get_message_keys")

    @Test
    fun `the vector file parses and still contains what these assertions cover`() {
        // Same fixture guard as the BIP-340 probe: an upstream restructuring must fail loudly
        // rather than reduce this suite to zero iterations of a green loop.
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
            val key = Nip44Reference.conversationKey(
                ourPrivateKey = ProbeVectors.decodeHex(v.getString("sec1")),
                theirXOnlyPublicKey = ProbeVectors.decodeHex(v.getString("pub2")),
            )
            assertEquals(
                "conversation-key vector $i",
                v.getString("conversation_key"),
                ProbeVectors.encodeHex(key),
            )
        }
    }

    @Test
    fun `the library's own ecdh is not the shared x coordinate`() {
        // Pinning the trap documented on Nip44Reference.sharedPointX. libsecp256k1's ecdh
        // hashes the shared point; NIP-44 needs it raw. Both are 32 bytes, so nothing but an
        // assertion like this one distinguishes them — and getting it wrong yields a codec
        // that talks only to itself. If a future binding ever makes these agree, this test
        // fails and the comment gets re-read, which is the intent.
        val v = valid("get_conversation_key").getJSONObject(0)
        val sec1 = ProbeVectors.decodeHex(v.getString("sec1"))
        val pub2 = ProbeVectors.decodeHex(v.getString("pub2"))

        val compressed = byteArrayOf(0x02) + pub2
        val hashedEcdh = Secp256k1.get().ecdh(sec1, Secp256k1.get().pubkeyParse(compressed))
        val rawX = Nip44Reference.sharedPointX(sec1, pub2)

        assertEquals("both are 32 bytes, which is what makes the confusion possible", 32, hashedEcdh.size)
        assertEquals(32, rawX.size)
        assertNotEquals(
            "ecdh() must not be mistaken for the raw shared x coordinate",
            ProbeVectors.encodeHex(hashedEcdh),
            ProbeVectors.encodeHex(rawX),
        )
    }

    @Test
    fun `the message-key schedule matches the spec for every vector`() {
        val group = messageKeyVectors()
        val conversationKey = ProbeVectors.decodeHex(group.getString("conversation_key"))
        val keys = group.getJSONArray("keys")
        for (i in 0 until keys.length()) {
            val v = keys.getJSONObject(i)
            val derived = Nip44Reference.messageKeys(
                conversationKey,
                ProbeVectors.decodeHex(v.getString("nonce")),
            )
            assertEquals("key $i chacha_key", v.getString("chacha_key"), ProbeVectors.encodeHex(derived.chachaKey))
            assertEquals("key $i chacha_nonce", v.getString("chacha_nonce"), ProbeVectors.encodeHex(derived.chachaNonce))
            assertEquals("key $i hmac_key", v.getString("hmac_key"), ProbeVectors.encodeHex(derived.hmacKey))
        }
    }

    @Test
    fun `the padding schedule matches the spec for every vector`() {
        val arr = valid("calc_padded_len")
        for (i in 0 until arr.length()) {
            val pair = arr.getJSONArray(i)
            val unpadded = pair.getInt(0)
            assertEquals("padded length for $unpadded", pair.getInt(1), Nip44Reference.paddedLength(unpadded))
        }
    }

    @Test
    fun `encrypting with the vector's nonce reproduces the published payload`() {
        // The strongest available check: NIP-44 is deterministic once the nonce is fixed, so
        // this asserts byte equality with the spec's payload rather than a round-trip through
        // our own code. A wrong padding rule, a wrong MAC input, or a swapped key offset all
        // fail here and none of them would fail a round-trip.
        val arr = valid("encrypt_decrypt")
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            val conversationKey = Nip44Reference.conversationKey(
                ourPrivateKey = ProbeVectors.decodeHex(v.getString("sec1")),
                theirXOnlyPublicKey = publicKeyOf(v.getString("sec2")),
            )
            assertEquals(
                "vector $i: conversation key derived from sec1 and pub(sec2)",
                v.getString("conversation_key"),
                ProbeVectors.encodeHex(conversationKey),
            )
            val payload = Nip44Reference.encrypt(
                plaintext = v.getString("plaintext"),
                conversationKey = conversationKey,
                nonce = ProbeVectors.decodeHex(v.getString("nonce")),
            )
            assertEquals("vector $i: payload", v.getString("payload"), payload)
        }
    }

    @Test
    fun `decrypting the published payload recovers the plaintext`() {
        val arr = valid("encrypt_decrypt")
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            // Decrypt as the RECIPIENT — sec2 with pub(sec1) — so this also establishes that
            // the conversation key is symmetric, which is the property that lets both parties
            // derive it independently without a handshake.
            val conversationKey = Nip44Reference.conversationKey(
                ourPrivateKey = ProbeVectors.decodeHex(v.getString("sec2")),
                theirXOnlyPublicKey = publicKeyOf(v.getString("sec1")),
            )
            assertEquals(
                "vector $i: the conversation key is the same from either side",
                v.getString("conversation_key"),
                ProbeVectors.encodeHex(conversationKey),
            )
            assertEquals(
                "vector $i: plaintext",
                v.getString("plaintext"),
                Nip44Reference.decrypt(v.getString("payload"), conversationKey),
            )
        }
    }

    @Test
    fun `every invalid conversation-key vector is refused`() {
        val arr = invalid("get_conversation_key")
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            val note = v.optString("note")
            val refused = try {
                Nip44Reference.conversationKey(
                    ourPrivateKey = ProbeVectors.decodeHex(v.getString("sec1")),
                    theirXOnlyPublicKey = ProbeVectors.decodeHex(v.getString("pub2")),
                )
                false
            } catch (e: Exception) {
                true
            }
            assertTrue("invalid conversation-key vector $i must be refused ($note)", refused)
        }
    }

    @Test
    fun `every invalid payload is refused rather than decrypted`() {
        // The negative half again, and for the same reason as in the BIP-340 probe: this is
        // the set that separates a real check from a decoder that returns whatever it got.
        val arr = invalid("decrypt")
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            val note = v.optString("note")
            val refused = try {
                Nip44Reference.decrypt(
                    v.getString("payload"),
                    ProbeVectors.decodeHex(v.getString("conversation_key")),
                )
                false
            } catch (e: Exception) {
                true
            }
            assertTrue("invalid decrypt vector $i must be refused ($note)", refused)
        }
    }

    /** The x-only public key for a private key, as NIP-44 names a counterparty. */
    private fun publicKeyOf(privateKeyHex: String): ByteArray =
        Secp256k1.get().pubkeyCreate(ProbeVectors.decodeHex(privateKeyHex)).copyOfRange(1, 33)
}
