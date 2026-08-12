package com.geekinasuit.agency.crypto

import java.io.File

/**
 * Vector-file plumbing shared by the step-0 crypto probes: runfiles lookup and a hex codec.
 *
 * The vector files under testdata/ are the specifications' own published files, checked in
 * verbatim — see testdata/PROVENANCE.md for sources and for which vectors each probe uses.
 */
internal object ProbeVectors {
    /** Reads a checked-in vector file out of the test's runfiles. */
    fun read(name: String): String {
        val srcdir = System.getenv("TEST_SRCDIR") ?: error("TEST_SRCDIR not set (not under bazel test)")
        val f = File(srcdir, "_main/agency/crypto/testdata/$name")
        check(f.exists()) { "vector file not found in runfiles at $f" }
        return f.readText()
    }

    fun decodeHex(s: String): ByteArray {
        require(s.length % 2 == 0) { "odd-length hex string (${s.length} chars)" }
        return ByteArray(s.length / 2) { i -> ((digit(s[2 * i]) shl 4) or digit(s[2 * i + 1])).toByte() }
    }

    fun encodeHex(b: ByteArray): String {
        val out = StringBuilder(b.size * 2)
        for (byte in b) {
            val v = byte.toInt() and 0xff
            out.append(HEX[v ushr 4]).append(HEX[v and 0x0f])
        }
        return out.toString()
    }

    private const val HEX = "0123456789abcdef"

    private fun digit(c: Char): Int {
        val d = Character.digit(c, 16)
        require(d >= 0) { "not a hex digit: '$c'" }
        return d
    }
}
