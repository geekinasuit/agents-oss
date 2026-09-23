package com.geekinasuit.agency.nostr

import fr.acinq.secp256k1.Secp256k1
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.ChaCha20ParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The NIP-44 v2 payload codec: the production encryption the 2a.4 gate-open notice rides on
 * (A4-6 — the notice is encrypted to the operator's key so a readable notice is what lets the
 * operator decline rather than blind-sign; that is a security property, not a convenience).
 *
 * This is the hardened sibling of the step-0 reference probe in agency/crypto, which proved
 * this platform can produce the spec's bytes but deliberately stopped there: no key
 * management, no nonce generation, no error taxonomy, no input validation. This codec supplies
 * exactly those, and nothing about the scheme itself changes — the same three-line split of
 * labour holds (libsecp256k1 gives one point multiplication, the JDK gives HMAC-SHA256 /
 * ChaCha20 / base64, and the key schedule + padding rule + payload framing are ours), so the
 * crypto library stays replaceable rather than load-bearing.
 *
 * TWO TRUST BOUNDARIES, TWO DISCIPLINES — the reason encrypt and decrypt are not symmetric:
 *
 *   [encrypt] consumes OUR OWN plaintext. A bad length here is a local bug, and a silent
 *   failure would be worse than a throw — an encrypt that quietly returned nothing could ship
 *   an absent or unencrypted notice past a caller that ignored the result. So it validates with
 *   `require` and throws, and it never lets a caller supply the nonce: it draws 32 fresh
 *   CSPRNG bytes per message itself, because nonce reuse under a conversation key reproduces the
 *   entire derived key triple — keystream reuse across two messages leaks both plaintexts. The
 *   nonce-injecting path exists only as an `internal` seam for the vector tests, which must
 *   reproduce the spec's published nonces to assert byte equality; production cannot reach it.
 *
 *   [decrypt] consumes HOSTILE relay bytes. A malformed payload is an expected, routine input,
 *   not an exception, so decrypt is TOTAL over its payload argument: any defect — bad base64,
 *   wrong version, short buffer, forged MAC, dishonest padding — folds to `null`, never a throw
 *   that escapes, exactly as [Bip340.verifyBytes] folds a bad signature to `false`. Its OTHER
 *   argument, the conversation key, is ours (derived locally from configured keys), so a
 *   wrong-sized key IS a local bug and throws loudly rather than hiding as a `null`.
 *
 * WHO USES WHICH, AND WHY THE ASYMMETRY IS SAFE: the daemon's notifier (step 4) encrypts to the
 * operator; the operator's approval client (step 6) decrypts. A relay never sees a decryptable
 * key, and the fold's release decision does not depend on this codec at all — confidentiality
 * of the notice and authorization of the release are separate layers.
 */
object Nip44 {
    private const val VERSION: Byte = 2
    private val SALT = "nip44-v2".toByteArray(Charsets.UTF_8)

    // Its own secp handle: [Bip340] exposes schnorr only and no ECDH, on purpose. NIP-44 needs
    // point multiplication (see [sharedPointX]), a different primitive, so this object holds the
    // handle that offers it. Get() returns a shared context; holding two references is fine.
    private val secp = Secp256k1.get()

    // One CSPRNG for the module's nonces. SecureRandom is thread-safe; a single shared instance
    // is the documented, contention-free way to use it.
    private val secureRandom = SecureRandom()

    /**
     * The x coordinate of the secp256k1 point [ourPrivateKey] * [theirXOnlyPublicKey].
     *
     * THE TRAP, KEPT NAMED FROM THE PROBE: libsecp256k1's own `ecdh` hashes the shared point
     * (SHA-256 of its compressed form) before returning it, because that is what most protocols
     * want. NIP-44 wants the RAW x coordinate. The obvious call is the wrong one and wrong in
     * the worst way — 32 plausible bytes, every self-consistent round-trip green, nothing any
     * other nostr implementation can read. Point multiplication is the correct primitive;
     * `Nip44Test` pins the distinction with an assertion carried into this module, because the
     * probe's assertion lives in agency/crypto and does not cover this code.
     */
    internal fun sharedPointX(ourPrivateKey: ByteArray, theirXOnlyPublicKey: ByteArray): ByteArray {
        require(theirXOnlyPublicKey.size == 32) { "x-only public key must be 32 bytes" }
        // NIP-44 interprets a 32-byte nostr pubkey as the even-y point with that x coordinate.
        val compressed = ByteArray(33)
        compressed[0] = 0x02
        theirXOnlyPublicKey.copyInto(compressed, 1)
        val point = secp.pubKeyTweakMul(secp.pubkeyParse(compressed), ourPrivateKey)
        check(point.size == 65) { "expected an uncompressed point, got ${point.size} bytes" }
        return point.copyOfRange(1, 33)
    }

    /**
     * The per-pair conversation key: HKDF-extract (HMAC with the fixed salt) over the shared
     * point, independent of any message. Symmetric — both parties derive the same value without
     * a handshake. Throws on a malformed counterparty key: this derives from configured keys, so
     * a bad one is a local error, not hostile traffic to fold closed.
     */
    fun conversationKey(ourPrivateKey: ByteArray, theirXOnlyPublicKey: ByteArray): ByteArray =
        hmac(key = SALT, data = sharedPointX(ourPrivateKey, theirXOnlyPublicKey))

    internal class MessageKeys(val chachaKey: ByteArray, val chachaNonce: ByteArray, val hmacKey: ByteArray)

    /** HKDF-expand the conversation key to 76 bytes with [nonce] as info, split by the spec's
     * offsets: ChaCha key [0,32), ChaCha nonce [32,44), HMAC key [44,76). */
    internal fun messageKeys(conversationKey: ByteArray, nonce: ByteArray): MessageKeys {
        val okm = hkdfExpand(prk = conversationKey, info = nonce, length = 76)
        return MessageKeys(
            chachaKey = okm.copyOfRange(0, 32),
            chachaNonce = okm.copyOfRange(32, 44),
            hmacKey = okm.copyOfRange(44, 76),
        )
    }

    /**
     * The spec's padding schedule: pad to a power-of-two-derived chunk so a payload's length
     * leaks only a coarse bucket, not the exact message size. Vector-checked against the spec's
     * `calc_padded_len` set.
     */
    internal fun paddedLength(unpaddedLength: Int): Int {
        require(unpaddedLength > 0) { "unpadded length must be positive" }
        if (unpaddedLength <= 32) return 32
        val nextPower = 1 shl (32 - Integer.numberOfLeadingZeros(unpaddedLength - 1))
        val chunk = if (nextPower <= 256) 32 else nextPower / 8
        return chunk * ((unpaddedLength - 1) / chunk + 1)
    }

    /**
     * Encrypt [plaintext] to a NIP-44 v2 payload under [conversationKey], drawing a fresh 32-byte
     * CSPRNG nonce for this message. Throws [IllegalArgumentException] if the UTF-8 plaintext is
     * empty or longer than 65535 bytes — NIP-44 v2 frames the length in a 16-bit prefix, so 65535
     * is the format's hard ceiling, not a policy choice. A payload that would exceed it is not a
     * bigger message to this codec; it is an artifact to encrypt separately and reference (A4-6).
     * It also throws if [plaintext] holds an unpaired surrogate: such a string has no UTF-8
     * encoding, and a lenient encoder would encrypt `?` in its place, so the recipient would read
     * a different string from the one passed here.
     */
    fun encrypt(plaintext: String, conversationKey: ByteArray): String =
        encryptWithNonce(plaintext, conversationKey, randomNonce())

    /**
     * The nonce-injecting encrypt, INTERNAL on purpose: the only legitimate caller that fixes a
     * nonce is a vector test reproducing the spec's published payloads byte for byte. Production
     * reaches encryption through [encrypt], which supplies its own fresh nonce, so a reused nonce
     * cannot be expressed by any public caller.
     */
    internal fun encryptWithNonce(plaintext: String, conversationKey: ByteArray, nonce: ByteArray): String {
        require(conversationKey.size == 32) { "conversation key must be 32 bytes" }
        require(nonce.size == 32) { "nonce must be 32 bytes" }
        val unpadded = requireNotNull(utf8OrNull(plaintext)) {
            "plaintext holds an unpaired surrogate, which has no UTF-8 encoding"
        }
        require(unpadded.isNotEmpty() && unpadded.size <= 65535) {
            "plaintext length out of range: ${unpadded.size} (must be 1..65535)"
        }
        val padded = ByteArray(2 + paddedLength(unpadded.size))
        padded[0] = (unpadded.size ushr 8).toByte()
        padded[1] = (unpadded.size and 0xff).toByte()
        unpadded.copyInto(padded, 2)

        val keys = messageKeys(conversationKey, nonce)
        val ciphertext = chacha20(keys.chachaKey, keys.chachaNonce, padded)
        val mac = hmac(key = keys.hmacKey, data = nonce + ciphertext)
        return Base64.getEncoder().encodeToString(byteArrayOf(VERSION) + nonce + ciphertext + mac)
    }

    /**
     * Decrypt a relay-delivered NIP-44 v2 [payload] under [conversationKey], returning the
     * plaintext, or `null` if the payload is malformed or its MAC does not verify. TOTAL over
     * [payload]: every failure path folds to `null`, none throws — a decrypt that cannot run is
     * not a silent pass, it is a refusal. [conversationKey] is ours, so a wrong size throws.
     */
    fun decrypt(payload: String, conversationKey: ByteArray): String? {
        require(conversationKey.size == 32) { "conversation key must be 32 bytes" }
        return try {
            decryptChecked(payload, conversationKey)
        } catch (_: Exception) {
            null
        }
    }

    private fun decryptChecked(payload: String, conversationKey: ByteArray): String {
        // A leading '#' is the spec's reserved marker for a future, unsupported encoding; reject
        // it before feeding the string to the base64 decoder.
        require(!payload.startsWith("#")) { "unsupported payload version" }
        val raw = Base64.getDecoder().decode(payload)
        // Shortest legal payload: version(1) + nonce(32) + ciphertext(>=34) + mac(32). The
        // ciphertext of a 1-byte plaintext is 2 + paddedLength(1) = 34 bytes, so 99 is the floor.
        require(raw.size >= 99) { "payload too short: ${raw.size} bytes" }
        require(raw[0] == VERSION) { "unsupported payload version: ${raw[0]}" }

        val nonce = raw.copyOfRange(1, 33)
        val ciphertext = raw.copyOfRange(33, raw.size - 32)
        val mac = raw.copyOfRange(raw.size - 32, raw.size)

        val keys = messageKeys(conversationKey, nonce)
        // Authenticate BEFORE decrypting, and compare in constant time. A MAC checked after the
        // fact, or with an early-exit byte comparison, is the classic way this format is got
        // wrong; MessageDigest.isEqual is the constant-time compare, and totality does not
        // weaken it — the throw-vs-return timing is not the side channel, an early-exit compare
        // would be.
        val expected = hmac(key = keys.hmacKey, data = nonce + ciphertext)
        require(MessageDigest.isEqual(expected, mac)) { "invalid MAC" }

        val padded = chacha20(keys.chachaKey, keys.chachaNonce, ciphertext)
        val declared = ((padded[0].toInt() and 0xff) shl 8) or (padded[1].toInt() and 0xff)
        require(declared > 0 && 2 + declared <= padded.size) { "invalid padding: declared $declared" }
        // The declared length must be the one the padding rule would have produced, or a sender
        // could hide bytes in the padding a reader never sees. This is also what bounds an
        // accepted payload at the spec's 65,603-byte decoded ceiling: declared is 16-bit, so
        // nothing longer than 2 + paddedLength(65535) can agree with any declared length.
        require(padded.size == 2 + paddedLength(declared)) { "invalid padding length" }
        return String(padded, 2, declared, Charsets.UTF_8)
    }

    private fun randomNonce(): ByteArray {
        val nonce = ByteArray(32)
        secureRandom.nextBytes(nonce)
        return nonce
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
