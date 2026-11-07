package com.geekinasuit.agency.wiring

import java.math.BigInteger
import java.security.MessageDigest

/**
 * An approver built from `agency/APPROVING.md` alone, as an implementer on another platform would
 * build one. It shares no code with [com.geekinasuit.agency.nostr.ApprovalSigning]: its BIP-340 is
 * plain arithmetic on [BigInteger], and its JSON is written by hand, so when the lead accepts what
 * this produces, the written contract is what was followed. It runs on the JVM to live in this
 * repository's tests, and uses nothing a non-JVM implementer would lack. Test support only: nothing
 * here is constant-time.
 */
object SpecApprover {
  private val P = BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
  private val N = BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
  private val G =
    Point(
      BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
      BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
    )

  private data class Point(val x: BigInteger, val y: BigInteger)

  /** [s] as a JSON string, by the document's escaping table. */
  fun jsonString(s: String): String =
    buildString {
      append('"')
      for (c in s) {
        when {
          c == '"' -> append("\\\"")
          c == '\\' -> append("\\\\")
          c == '\b' -> append("\\b")
          c.code == 0x0C -> append("\\f")
          c == '\n' -> append("\\n")
          c == '\r' -> append("\\r")
          c == '\t' -> append("\\t")
          c.code < 0x20 -> append("\\u00").append("%02x".format(c.code))
          else -> append(c)
        }
      }
      append('"')
    }

  fun preimage(publicKey: String, gateId: String, payloadDigest: String, nonce: String): String =
    listOf("agency/gate-approval/v1", publicKey, gateId, payloadDigest, nonce).joinToString(",", "[", "]", transform = ::jsonString)

  fun publicKey(secretKeyHex: String): String = hex(bytes32(mul(BigInteger(secretKeyHex, 16), G).x))

  fun sha256Hex(text: String): String = hex(sha256(text.toByteArray(Charsets.UTF_8)))

  /** A BIP-340 signature by [secretKeyHex] over the 32 bytes of [messageHex]. */
  fun sign(messageHex: String, secretKeyHex: String, auxRandHex: String): String {
    val message = unhex(messageHex)
    val d0 = BigInteger(secretKeyHex, 16)
    val pub = mul(d0, G)
    val d = if (pub.y.testBit(0)) N - d0 else d0
    val px = bytes32(pub.x)
    val mask = taggedHash("BIP0340/aux", unhex(auxRandHex))
    val t = ByteArray(32) { (bytes32(d)[it].toInt() xor mask[it].toInt()).toByte() }
    val k0 = BigInteger(1, taggedHash("BIP0340/nonce", t + px + message)).mod(N)
    val r = mul(k0, G)
    val k = if (r.y.testBit(0)) N - k0 else k0
    val rx = bytes32(r.x)
    val e = BigInteger(1, taggedHash("BIP0340/challenge", rx + px + message)).mod(N)
    return hex(rx + bytes32((k + e * d).mod(N)))
  }

  /** The content of the approval rumor, with no `carrierArtifactId`, as the document says. */
  fun rumorContent(secretKeyHex: String, gateId: String, payloadDigest: String, nonce: String, auxRandHex: String): String {
    val publicKey = publicKey(secretKeyHex)
    val preimage = preimage(publicKey, gateId, payloadDigest, nonce)
    val signature = sign(sha256Hex(preimage), secretKeyHex, auxRandHex)
    fun member(name: String, value: String) = "${jsonString(name)}:${jsonString(value)}"
    val evidence =
      listOf(
          member("schemeId", "bip340"),
          member("publicKey", publicKey),
          member("signature", signature),
          member("gateId", gateId),
          member("payloadDigest", payloadDigest),
          member("nonce", nonce),
          member("signedPreimage", preimage),
        )
        .joinToString(",", "{", "}")
    return "{${member("gateId", gateId)},${member("nonce", nonce)},${member("payloadDigest", payloadDigest)},\"evidence\":$evidence}"
  }

  private fun add(a: Point?, b: Point?): Point? {
    if (a == null) return b
    if (b == null) return a
    if (a.x == b.x && a.y != b.y) return null
    val slope =
      if (a == b) (BigInteger.valueOf(3) * a.x * a.x * (BigInteger.TWO * a.y).modInverse(P)).mod(P)
      else ((b.y - a.y) * (b.x - a.x).modInverse(P)).mod(P)
    val x = (slope * slope - a.x - b.x).mod(P)
    return Point(x, (slope * (a.x - x) - a.y).mod(P))
  }

  private fun mul(k: BigInteger, point: Point): Point {
    var result: Point? = null
    for (i in k.bitLength() - 1 downTo 0) {
      result = add(result, result)
      if (k.testBit(i)) result = add(result, point)
    }
    return checkNotNull(result)
  }

  private fun taggedHash(tag: String, message: ByteArray): ByteArray {
    val tagHash = sha256(tag.toByteArray(Charsets.UTF_8))
    return sha256(tagHash + tagHash + message)
  }

  private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

  private fun bytes32(x: BigInteger): ByteArray {
    val raw = x.toByteArray()
    return ByteArray(32) { i -> raw.getOrElse(raw.size - 32 + i) { 0 } }
  }

  private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

  private fun unhex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
