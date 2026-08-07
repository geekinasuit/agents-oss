package com.geekinasuit.agency.shared.journal

import java.io.File
import java.io.RandomAccessFile

/**
 * The receiver-side half of the exactly-once contract: exactly-once = at-least-once
 * delivery + an idempotent receiver keyed on the intent's idempotency key. This file-based
 * receiver is the boundary contract demonstrator used by the durability scenarios; real
 * effect executors must honor the same shape.
 *
 * `dedup=false` exists so scenario tests can run the POSITIVE CONTROL cell proving the
 * harness observes a double-fire when dedup is absent — a check that cannot see the
 * failure is not evidence.
 */
class EffectReceiver(dir: String, private val fileName: String = "effects.log") {
  private val file = File(dir, fileName).also { it.parentFile.mkdirs() }

  sealed interface FireResult {
    data object Fired : FireResult
    data object Suppressed : FireResult
  }

  fun fire(key: String, message: String, dedup: Boolean): FireResult {
    if (dedup && seenKeys().contains(key)) return FireResult.Suppressed
    RandomAccessFile(file, "rw").use { raf ->
      raf.seek(raf.length())
      raf.write("EFFECT $key $message\n".toByteArray(Charsets.UTF_8))
      raf.fd.sync()
    }
    return FireResult.Fired
  }

  fun seenKeys(): Set<String> =
    if (!file.exists()) emptySet()
    else file.readLines().filter { it.startsWith("EFFECT ") }.map { it.split(" ")[1] }.toSet()

  fun lineCountFor(key: String): Int =
    if (!file.exists()) 0 else file.readLines().count { it.startsWith("EFFECT $key ") }
}
