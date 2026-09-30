package com.geekinasuit.agency.lead

import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger

/**
 * Runs a read that can block without end on a thread of its own, and waits for it at most
 * [deadlineMs]. Opening a FIFO blocks until something opens it to write, and a blocked open cannot
 * be interrupted, so the caller's thread can only stop waiting, never stop the read. A read that
 * misses its deadline is left running, parked, on its thread, which ends when the read returns.
 *
 * At most [maxParked] reads are left parked at once. While that many are, [read] starts no read and
 * returns [Outcome.Refused], so reads that keep blocking cannot grow the process's threads without
 * end. A parked read that returns frees its place. Each thread is a daemon thread named
 * [threadName], so a parked read does not keep the process running.
 *
 * Meant for one calling thread: [read] checks the parked count and then starts the read, and two
 * callers could both pass the check.
 */
internal class DeadlinedReads(
  private val deadlineMs: Long,
  private val maxParked: Int,
  private val threadName: String,
) {
  init {
    require(deadlineMs > 0) { "deadlineMs must be positive, was $deadlineMs" }
    require(maxParked >= 1) { "maxParked must be at least 1, was $maxParked" }
  }

  sealed interface Outcome<out T> {
    /** The read returned [value] within the deadline. */
    class Done<T>(val value: T) : Outcome<T>

    /** The read did not return within the deadline, and is left parked. */
    data object TimedOut : Outcome<Nothing>

    /** [parked] reads were parked, the most allowed, so the read was not started. */
    data class Refused(val parked: Int) : Outcome<Nothing>
  }

  private val running = AtomicInteger(0)

  /** Reads started and not yet returned. Between calls to [read], these are the parked ones. */
  fun unfinished(): Int = running.get()

  /**
   * Runs [block] on a new thread and waits for it at most the deadline. A throw from [block] is
   * rethrown here. An interrupt of the waiting thread is rethrown too, with its interrupt flag set
   * again, and the read is left parked.
   */
  fun <T> read(block: () -> T): Outcome<T> {
    val parked = running.get()
    if (parked >= maxParked) return Outcome.Refused(parked)
    val result = CompletableFuture<T>()
    val thread = Thread({
      val outcome = runCatching(block)
      // The count drops before the result is handed over, so the caller never counts as parked a
      // read it has already seen return.
      running.decrementAndGet()
      outcome.fold(result::complete, result::completeExceptionally)
    }, threadName)
    thread.isDaemon = true
    running.incrementAndGet()
    try {
      thread.start()
    } catch (t: Throwable) {
      running.decrementAndGet()
      throw t
    }
    return try {
      Outcome.Done(result.get(deadlineMs, TimeUnit.MILLISECONDS))
    } catch (e: TimeoutException) {
      Outcome.TimedOut
    } catch (e: ExecutionException) {
      throw e.cause ?: e
    } catch (e: InterruptedException) {
      Thread.currentThread().interrupt()
      throw e
    }
  }
}
