package com.geekinasuit.agency.crypto

import fr.acinq.secp256k1.Secp256k1
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.ChaCha20ParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A reference implementation of the NIP-44 v2 payload format, for the step-0 probe only.
 *
 * WHY THIS EXISTS AS A PROBE RATHER THAN AS THE REAL CODEC: step 0's job is to find out
 * whether this platform can do NIP-44 at all before anything is built on the assumption that
 * it can. Answering that requires running the scheme end to end against the published
 * vectors, because "the primitives are present" and "the scheme produces the spec's bytes"
 * are different claims and only the second one is load-bearing. So this is deliberately
 * test-scope: no key management, no nonce generation, no error taxonomy, no streaming, no
 * input validation beyond what the published vectors exercise, and it does not belong to
 * the authorization layer's API. The layer's own codec is a separate deliverable.
 *
 * The split of labour it demonstrates is the point of the whole library decision:
 *
 *   from libsecp256k1 — the shared point, and nothing else
 *   from the JDK      — HMAC-SHA256, ChaCha20, base64
 *   ours              — the key schedule, the padding rule, the payload framing
 *
 * That third line is small, which is what makes the crypto library replaceable instead of
 * load-bearing: a different secp256k1 binding, or a pure-JVM one, would change only
 * [sharedPointX].
 */
internal object Nip44Reference {
    private const val VERSION: Byte = 2
    private val SALT = "nip44-v2".toByteArray(Charsets.UTF_8)

    private val secp = Secp256k1.get()

    /**
     * The x coordinate of the secp256k1 point [ourPrivateKey] * [theirXOnlyPublicKey].
     *
     * THE TRAP THIS AVOIDS, AND THE REASON IT IS A NAMED FUNCTION: libsecp256k1's own `ecdh`
     * applies a hash to the shared point before returning it (SHA-256 of the compressed
     * form), because that is what most protocols want. NIP-44 wants the RAW x coordinate. So
     * the obvious call is the wrong one, and it is wrong in the worst way — it returns 32
     * plausible bytes and every self-consistent round-trip test passes while nothing this
     * code produces can be read by any other nostr implementation. Point multiplication is
     * the correct primitive; [Nip44VectorTest] pins the distinction with an assertion.
     */
    fun sharedPointX(ourPrivateKey: ByteArray, theirXOnlyPublicKey: ByteArray): ByteArray {
        require(theirXOnlyPublicKey.size == 32) { "x-only public key must be 32 bytes" }
        // NIP-44 interprets a 32-byte nostr pubkey as the even-y point with that x coordinate.
        val compressed = ByteArray(33)
        compressed[0] = 0x02
        theirXOnlyPublicKey.copyInto(compressed, 1)
        val point = secp.pubKeyTweakMul(secp.pubkeyParse(compressed), ourPrivateKey)
        check(point.size == 65) { "expected an uncompressed point, got ${point.size} bytes" }
        return point.copyOfRange(1, 33)
    }

    /** HKDF-extract over the shared point: the per-pair key, independent of any message. */
    fun conversationKey(ourPrivateKey: ByteArray, theirXOnlyPublicKey: ByteArray): ByteArray =
        hmac(key = SALT, data = sharedPointX(ourPrivateKey, theirXOnlyPublicKey))

    class MessageKeys(val chachaKey: ByteArray, val chachaNonce: ByteArray, val hmacKey: ByteArray)

    /** HKDF-expand to 76 bytes, split by the spec's offsets. */
    fun messageKeys(conversationKey: ByteArray, nonce: ByteArray): MessageKeys {
        val okm = hkdfExpand(prk = conversationKey, info = nonce, length = 76)
        return MessageKeys(
            chachaKey = okm.copyOfRange(0, 32),
            chachaNonce = okm.copyOfRange(32, 44),
            hmacKey = okm.copyOfRange(44, 76),
        )
    }

    /**
     * The spec's padding schedule: pad to a power-of-two-derived chunk so that a payload's
     * length leaks only a coarse bucket rather than the exact message size.
     */
    fun paddedLength(unpaddedLength: Int): Int {
        require(unpaddedLength > 0) { "unpadded length must be positive" }
        if (unpaddedLength <= 32) return 32
        val nextPower = 1 shl (32 - Integer.numberOfLeadingZeros(unpaddedLength - 1))
        val chunk = if (nextPower <= 256) 32 else nextPower / 8
        return chunk * ((unpaddedLength - 1) / chunk + 1)
    }

    /**
     * [nonce] must be 32 fresh CSPRNG bytes per message and NEVER reused under a conversation
     * key: it is the HKDF info input, so a repeat reproduces the entire derived triple —
     * ChaCha key, ChaCha nonce, and MAC key — which is keystream reuse across both messages
     * (their XOR leaks both plaintexts) plus a repeated MAC key. This class neither generates
     * nor validates it; the tests pass the spec's published nonces.
     */
    fun encrypt(plaintext: String, conversationKey: ByteArray, nonce: ByteArray): String {
        val unpadded = plaintext.toByteArray(Charsets.UTF_8)
        require(unpadded.isNotEmpty() && unpadded.size <= 65535) { "plaintext length out of range" }
        val padded = ByteArray(2 + paddedLength(unpadded.size))
        padded[0] = (unpadded.size ushr 8).toByte()
        padded[1] = (unpadded.size and 0xff).toByte()
        unpadded.copyInto(padded, 2)

        val keys = messageKeys(conversationKey, nonce)
        val ciphertext = chacha20(keys.chachaKey, keys.chachaNonce, padded)
        val mac = hmac(key = keys.hmacKey, data = nonce + ciphertext)
        return Base64.getEncoder().encodeToString(byteArrayOf(VERSION) + nonce + ciphertext + mac)
    }

    fun decrypt(payload: String, conversationKey: ByteArray): String {
        require(!payload.startsWith("#")) { "unsupported payload version" }
        val raw = Base64.getDecoder().decode(payload)
        require(raw.size >= 99) { "payload too short: ${raw.size} bytes" }
        require(raw[0] == VERSION) { "unsupported payload version: ${raw[0]}" }

        val nonce = raw.copyOfRange(1, 33)
        val ciphertext = raw.copyOfRange(33, raw.size - 32)
        val mac = raw.copyOfRange(raw.size - 32, raw.size)

        val keys = messageKeys(conversationKey, nonce)
        // Authenticate BEFORE decrypting, and compare in constant time: a MAC checked after
        // the fact, or with an early-exit comparison, is the classic way this format is got
        // wrong.
        val expected = hmac(key = keys.hmacKey, data = nonce + ciphertext)
        require(MessageDigest.isEqual(expected, mac)) { "invalid MAC" }

        val padded = chacha20(keys.chachaKey, keys.chachaNonce, ciphertext)
        val declared = ((padded[0].toInt() and 0xff) shl 8) or (padded[1].toInt() and 0xff)
        require(declared > 0 && 2 + declared <= padded.size) { "invalid padding: declared $declared" }
        // The declared length must be the one the padding rule would have produced, or a
        // sender could hide bytes in the padding that a reader never sees. This check is also
        // what bounds an accepted payload at the spec's 65,603-byte decoded ceiling: declared
        // is 16-bit, so nothing longer than 2 + paddedLength(65535) can agree with any
        // declared length — the bound is enforced, but only after the MAC and decrypt work.
        require(padded.size == 2 + paddedLength(declared)) { "invalid padding length" }
        return String(padded, 2, declared, Charsets.UTF_8)
    }

    private fun chacha20(key: ByteArray, nonce: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "ChaCha20"),
            ChaCha20ParameterSpec(nonce, 0),
        )
        return cipher.doFinal(data)
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val out = ByteArray(length)
        var previous = ByteArray(0)
        var written = 0
        var counter = 1
        while (written < length) {
            previous = hmac(key = prk, data = previous + info + byteArrayOf(counter.toByte()))
            val take = minOf(previous.size, length - written)
            previous.copyInto(out, written, 0, take)
            written += take
            counter++
        }
        return out
    }
}
