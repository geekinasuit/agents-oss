package com.geekinasuit.agency.pod

import com.geekinasuit.agency.shared.text.utf8OrNull
import java.security.MessageDigest

/**
 * Artifact digests — the hand-off's shared vocabulary (artifacts + digests are the
 * ONLY pod→lead hand-off). Shared because BOTH sides
 * compute it: the engine digests the bytes of its disciplined read, and the lead
 * RE-computes from the file at the path it assigned (a pod's self-reported digest is
 * untrusted input, cross-checked and escalated on mismatch). One implementation means the
 * cross-check compares like with like — two copies could silently disagree on encoding and
 * turn every completion into a mismatch escalation.
 */

/** SHA-256 of raw bytes, lowercase hex: a gate binds to the artifact's
 * bytes ON DISK, not a charset-decoded string. Both the engine's read and the lead's
 * recompute go through this over raw bytes, so a pod producing binary / non-UTF8 output
 * binds the same digest a byte-oriented tool would — not the SHA of a lossily decoded
 * string. */
fun sha256HexBytes(bytes: ByteArray): String =
  MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

/** SHA-256 of a string's UTF-8 encoding — a convenience over [sha256HexBytes] for known-text
 * content (the scripted fake pod's artifacts). Equal to the raw-byte digest of that same text
 * written UTF-8, so text pods and the lead's byte-recompute agree. THROWS
 * [IllegalArgumentException] if [content] holds an unpaired surrogate: it has no UTF-8 encoding,
 * and the lenient one would give it the digest of the same text with `?` in its place. */
fun sha256Hex(content: String): String =
  sha256HexBytes(
    requireNotNull(utf8OrNull(content)) { "content holds an unpaired surrogate, which has no UTF-8 encoding" }
  )
