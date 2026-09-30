package com.geekinasuit.agency.lead

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Reads run off the calling thread with a deadline, and a bound on the reads left blocked past it.
 * A latch stands in for an open that blocks, so no cell needs a FIFO or waits out more than a short
 * deadline.
 */
class DeadlinedReadsTest {

  private val deadlineMs = 50L

  /** Latches the cells' blocked reads wait on, all released after each cell so no thread stays. */
  private val gates = mutableListOf<CountDownLatch>()

  @After
  fun releaseEveryBlockedRead() {
    gates.forEach { it.countDown() }
  }

  private fun gate(): CountDownLatch = CountDownLatch(1).also { gates += it }

  /** Waits up to a few seconds for [reads] to have no read unfinished. */
  private fun awaitNoneUnfinished(reads: DeadlinedReads): Boolean {
    val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
    while (reads.unfinished() > 0) {
      if (System.nanoTime() > until) return false
      Thread.sleep(5)
    }
    return true
  }

  @Test
  fun aReadThatReturnsInTimeHandsBackItsValue() {
    val reads = DeadlinedReads(5_000, 1, "test-read")
    val outcome = reads.read { "the bytes" }
    assertTrue("the read finished", outcome is DeadlinedReads.Outcome.Done)
    assertEquals("the read's value", "the bytes", (outcome as DeadlinedReads.Outcome.Done).value)
    assertEquals("nothing is left unfinished", 0, reads.unfinished())
  }

  // A read that the caller waited out to the end would hang the cell, so each cell whose read blocks
  // has a timeout of its own, and fails instead.
  @Test(timeout = 10_000)
  fun aReadPastTheDeadlineTimesOutAndIsLeftParkedOnADaemonThread() {
    val reads = DeadlinedReads(deadlineMs, 1, "test-read")
    val blocked = gate()
    val thread = AtomicReference<Thread>()
    val outcome =
      reads.read {
        thread.set(Thread.currentThread())
        blocked.await()
      }
    assertSame("the read timed out", DeadlinedReads.Outcome.TimedOut, outcome)
    assertEquals("the read is left parked", 1, reads.unfinished())
    assertTrue("on a thread of its own, still running", thread.get().isAlive)
    assertTrue("a daemon thread, which does not keep the process running", thread.get().isDaemon)
    assertEquals("named as given", "test-read", thread.get().name)

    blocked.countDown()
    assertTrue("a parked read that returns frees its place", awaitNoneUnfinished(reads))
  }

  @Test(timeout = 10_000)
  fun atTheBoundTheNextReadIsRefusedWithoutStarting() {
    val reads = DeadlinedReads(deadlineMs, 2, "test-read")
    val first = gate()
    val second = gate()
    assertSame(DeadlinedReads.Outcome.TimedOut, reads.read { first.await() })
    assertSame(DeadlinedReads.Outcome.TimedOut, reads.read { second.await() })

    var started = false
    val refused = reads.read { started = true }
    assertEquals("refused at the bound, naming it", DeadlinedReads.Outcome.Refused(2), refused)
    assertFalse("the refused read was never started", started)
    assertEquals("no thread was added", 2, reads.unfinished())

    first.countDown()
    val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
    while (reads.unfinished() > 1 && System.nanoTime() < until) Thread.sleep(5)
    val next = reads.read { "read again" }
    assertTrue("with a place free, a read runs again", next is DeadlinedReads.Outcome.Done)
  }

  @Test
  fun aThrowFromTheReadIsRethrownToTheCaller() {
    val reads = DeadlinedReads(5_000, 1, "test-read")
    val thrown = IllegalStateException("the read failed")
    val caught = assertThrows(IllegalStateException::class.java) { reads.read { throw thrown } }
    assertSame("the read's own throw", thrown, caught)
    assertEquals("nothing is left unfinished", 0, reads.unfinished())
  }

  @Test
  fun aDeadlineOrBoundBelowOneIsRefused() {
    assertThrows(IllegalArgumentException::class.java) { DeadlinedReads(0, 1, "test-read") }
    assertThrows(IllegalArgumentException::class.java) { DeadlinedReads(1, 0, "test-read") }
  }
}
