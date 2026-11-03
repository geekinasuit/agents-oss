package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.nostr.AuthSpecSigning
import com.geekinasuit.agency.nostr.Bip340
import com.geekinasuit.agency.nostr.SecretKeyHex
import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.security.SecureRandom
import kotlin.system.exitProcess

/**
 * The operator's tool for the authorization spec (A4-8), run where the root key lives, never on the
 * lead's host:
 *
 *  - `auth_spec pubkey --root-key-file F` prints the root's public key: the value a deployment pins.
 *  - `auth_spec sign --spec S --root-key-file F --out O` signs the spec S describes (see
 *    [AuthSpecSigning]) with the root key and writes the signed file O a lead loads. It refuses a
 *    spec that would not load or could never be met, and an O that already exists.
 *
 * The root key file holds the key as 64 hex characters (surrounding ASCII whitespace ignored). The key is
 * read into a clearable holder and its characters zeroed; it is never printed. Exit 0 on success, 1 on
 * a refusal, 2 on a usage error, each with one line on stderr saying why.
 */
object AuthSpecTool {
  @JvmStatic
  fun main(args: Array<String>) {
    exitProcess(run(args.toList(), System.out, System.err))
  }

  fun run(args: List<String>, out: PrintStream, err: PrintStream): Int {
    val command = args.firstOrNull() ?: return usage(err, "no command")
    val allowed = COMMANDS[command] ?: return usage(err, "unknown command '$command'")
    val flags =
      try {
        flagsOf(args.drop(1), allowed)
      } catch (x: IllegalArgumentException) {
        return usage(err, x.message ?: "bad arguments")
      }
    return try {
      when (command) {
        "pubkey" -> {
          val key = readKey(flags.required("--root-key-file"))
          try {
            out.println(key.useKeyBytes { Bip340.xonlyPubkeyFromKeyBytes(it) })
          } finally {
            key.clear()
          }
          0
        }
        else -> {
          val outPath = Paths.get(flags.required("--out"))
          val (principals, quorum) = AuthSpecSigning.parse(File(flags.required("--spec")).readText())
          val key = readKey(flags.required("--root-key-file"))
          val signed =
            try {
              key.useKeyBytes { AuthSpecSigning.sign(principals, quorum, it, freshAuxRandHex()) }
            } finally {
              key.clear()
            }
          // CREATE_NEW refuses an existing path, a dangling symlink included, in the same call that
          // creates the file, so nothing is overwritten.
          Files.write(outPath, (AuthSpecSigning.toJson(signed) + "\n").toByteArray(), StandardOpenOption.CREATE_NEW)
          out.println("signed ${principals.size} principal(s) to $outPath")
          0
        }
      }
    } catch (x: java.nio.file.FileAlreadyExistsException) {
      err.println("auth_spec: refusing to overwrite ${x.file}")
      1
    } catch (x: IllegalArgumentException) {
      err.println("auth_spec: ${x.message}")
      1
    } catch (x: java.io.IOException) {
      err.println("auth_spec: ${x.javaClass.simpleName}: ${x.message}")
      1
    }
  }

  // Read as bytes, not a String, so the key's text is in arrays this zeroes, not in a String no code
  // can overwrite. ASCII whitespace around the key is dropped; anything else, inside it included, is
  // left for SecretKeyHex to refuse. The key must also name a secp256k1 scalar, which the native would
  // otherwise refuse with an exception of its own.
  private fun readKey(path: String): SecretKeyHex {
    val raw = File(path).readBytes()
    var start = 0
    var end = raw.size
    while (start < end && raw[start].isAsciiSpace()) start++
    while (end > start && raw[end - 1].isAsciiSpace()) end--
    val chars = CharArray(end - start) { raw[start + it].toInt().toChar() }
    try {
      val key = SecretKeyHex.ofHex(chars)
      if (!key.useKeyBytes { Bip340.isValidSecretKeyBytes(it) }) {
        key.clear()
        throw IllegalArgumentException(
          "the root key is 64 hex characters but not a secp256k1 secret key (zero, or not below the curve order)"
        )
      }
      return key
    } finally {
      raw.fill(0)
      chars.fill(Char(0))
    }
  }

  private fun Byte.isAsciiSpace(): Boolean = this == ' '.code.toByte() || this == '\t'.code.toByte() ||
    this == '\n'.code.toByte() || this == '\r'.code.toByte()

  private fun flagsOf(args: List<String>, allowed: Set<String>): Map<String, String> {
    require(args.size % 2 == 0) { "each flag needs a value" }
    val flags = mutableMapOf<String, String>()
    for ((flag, value) in args.chunked(2)) {
      require(flag in allowed) { "'$flag' is not a flag of this command" }
      require(flags.put(flag, value) == null) { "'$flag' is given twice" }
    }
    return flags
  }

  private fun Map<String, String>.required(flag: String): String =
    this[flag] ?: throw IllegalArgumentException("missing $flag")

  private fun usage(err: PrintStream, why: String): Int {
    err.println("auth_spec: $why")
    err.println("usage: auth_spec pubkey --root-key-file F | auth_spec sign --spec S --root-key-file F --out O")
    return 2
  }

  private fun freshAuxRandHex(): String {
    val bytes = ByteArray(32)
    SecureRandom().nextBytes(bytes)
    return bytes.joinToString("") { "%02x".format(it) }
  }

  private val COMMANDS =
    mapOf(
      "pubkey" to setOf("--root-key-file"),
      "sign" to setOf("--spec", "--root-key-file", "--out"),
    )
}
