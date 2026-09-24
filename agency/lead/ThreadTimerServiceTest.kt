package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.ArmedTimer
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The wall-clock timer service a deployment wires, armed directly: a timer it arms calls back once
 * with the timer's id, not before the timer's time, on a daemon thread of the service's own, so the
 * thread never keeps a process running. Arming returns without waiting for the timer's time: the
 * lead arms a gate-open retry on its loop thread, and the loop takes no wake while `arm` holds it. A
 * timer whose time has passed, as one has when adopt re-arms it after a restart, is still called
 * back. So is a timer armed after an earlier one on the same service was called back: a deployment
 * keeps one service for the lead's lifetime and arms each later retry on it. */
class ThreadTimerServiceTest {

  private class Call(val id: String, val at: Long, val thread: Thread)

  @Test
  fun callsOnDueOnceWithTheTimersIdNoEarlierThanItsFireTimeOnADaemonThreadOfItsOwn() {
    val caller = Thread.currentThread()
    val calls = LinkedBlockingQueue<Call>()
    val fireAt = System.currentTimeMillis() + 300
    ThreadTimerService().arm(ArmedTimer("t-wall", fireAt, "noop")) { id ->
      calls.put(Call(id, System.currentTimeMillis(), Thread.currentThread()))
    }

    val call = calls.poll(10, TimeUnit.SECONDS) ?: throw AssertionError("onDue was never called")
    assertEquals("onDue was given the timer's id", "t-wall", call.id)
    assertTrue("onDue came ${fireAt - call.at} ms before the timer's time", call.at >= fireAt)
    assertTrue("onDue ran on the service's thread, not the caller's", call.thread !== caller)
    assertTrue("the service's thread is a daemon", call.thread.isDaemon)
    assertEquals("onDue was called once", null, calls.poll(500, TimeUnit.MILLISECONDS))
  }

  @Test
  fun armReturnsWithoutWaitingForTheTimersTime() {
    val started = System.nanoTime()
    ThreadTimerService().arm(ArmedTimer("t-later", System.currentTimeMillis() + 30_000, "noop")) {}
    val heldMs = (System.nanoTime() - started) / 1_000_000
    assertTrue("arm held its caller for $heldMs ms of the timer's 30 s", heldMs < 10_000)
  }

  @Test
  fun callsOnDueForATimerWhoseTimeHasPassed() {
    val calls = LinkedBlockingQueue<String>()
    val fireAt = System.currentTimeMillis() - 30_000
    ThreadTimerService().arm(ArmedTimer("t-due", fireAt, "noop")) { id -> calls.put(id) }

    assertEquals("onDue was given the timer's id", "t-due", calls.poll(10, TimeUnit.SECONDS))
    assertEquals("onDue was called once", null, calls.poll(500, TimeUnit.MILLISECONDS))
  }

  @Test
  fun callsOnDueForATimerArmedAfterAnEarlierOneOnTheSameServiceWasCalledBack() {
    val calls = LinkedBlockingQueue<String>()
    val service = ThreadTimerService()
    service.arm(ArmedTimer("t-first", System.currentTimeMillis() + 50, "noop")) { id -> calls.put(id) }
    assertEquals("onDue was given the first timer's id", "t-first", calls.poll(10, TimeUnit.SECONDS))

    service.arm(ArmedTimer("t-second", System.currentTimeMillis() + 50, "noop")) { id -> calls.put(id) }
    assertEquals("onDue was given the second timer's id", "t-second", calls.poll(10, TimeUnit.SECONDS))
  }
}
