package com.geekinasuit.agency.lead

import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.Path

/** Whether this host can make a FIFO, which the cells that swap one in need. */
fun canMakeAFifo(): Boolean = File(MKFIFO).canExecute()

/** Replaces whatever sits at [path], a link included, with a FIFO. Opening that FIFO to read blocks
 * until something opens it to write. */
fun replaceWithAFifo(path: String) {
  Files.deleteIfExists(Path.of(path))
  val exit = ProcessBuilder(MKFIFO, path).start().waitFor()
  check(exit == 0) { "mkfifo $path exited $exit" }
}

/**
 * Opens the FIFO at [path] to write and closes it, so that an open blocked on reading it returns,
 * and the read after it sees the end of the file. With no reader waiting, the open blocks instead,
 * so it runs on a daemon thread, waited on for at most [deadlineMs]. Returns whether it finished.
 * Call it only on a FIFO: opened to write, a regular file would be truncated.
 */
fun releaseFifo(path: String, deadlineMs: Long = 5_000): Boolean {
  val writer = Thread { runCatching { FileOutputStream(path).close() } }
  writer.isDaemon = true
  writer.start()
  writer.join(deadlineMs)
  return !writer.isAlive
}

/** The live threads the lead opens and reads bound copies on. */
fun boundReadThreads(): List<Thread> =
  Thread.getAllStackTraces().keys.filter { it.name == LeadDaemon.BOUND_READ_THREAD_NAME && it.isAlive }

/** Waits up to [deadlineMs] for every bound-copy read thread to finish. Returns whether they did. */
fun awaitNoBoundReadThreads(deadlineMs: Long = 5_000): Boolean {
  val until = System.nanoTime() + deadlineMs * 1_000_000
  while (boundReadThreads().isNotEmpty()) {
    if (System.nanoTime() > until) return false
    Thread.sleep(10)
  }
  return true
}

private const val MKFIFO = "/usr/bin/mkfifo"
