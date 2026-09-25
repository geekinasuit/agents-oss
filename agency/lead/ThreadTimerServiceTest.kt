package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.ArmedTimer
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** The wall-clock timer service a deployment wires, armed directly: a timer it arms calls back once
 * with the timer's id, not before the timer's time, on a daemon thread of the service's own, so the
 * thread never keeps a process running. Arming returns without waiting for the timer's time: the
 * lead arms a gate-open retry on its loop thread, and the loop takes no wake while `arm` holds it. A
 * timer whose time has passed, as one has when adopt re-arms it after a restart, is still called
 * back. So is a timer armed after an earlier one on the same service was called back, including
 * one whose callback threw, whether its report went to the default or to an `onError` that threw
 * too: a deployment keeps one service for the lead's lifetime and arms each later retry on it. A
 * callback that throws is reported, by default to the thread's uncaught-exception handler: the
 * default handler if one is set, and otherwise a print to standard error. Timers pending at once are
 * all called back, each no earlier than its time, in the order they are due, whatever order they
 * were armed in.
 * The delay the service schedules is checked through a scheduler that records it, since a retry's
 * delay runs to minutes and no cell waits that long. */
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

  @Test
  fun reportsAnOnDueThatThrowsAndStillCallsBackATimerArmedAfterIt() {
    val reports = LinkedBlockingQueue<Pair<String, Throwable>>()
    val calls = LinkedBlockingQueue<String>()
    val service = ThreadTimerService(onError = { id, error -> reports.put(id to error) })
    val threw = CountDownLatch(1)
    val boom = IllegalStateException("boom")
    service.arm(ArmedTimer("t-throws", System.currentTimeMillis() + 50, "noop")) {
      threw.countDown()
      throw boom
    }
    assertTrue("the throwing onDue was never called", threw.await(10, TimeUnit.SECONDS))

    service.arm(ArmedTimer("t-after", System.currentTimeMillis() + 50, "noop")) { id -> calls.put(id) }
    assertEquals("a timer armed after the throw is called back", "t-after", calls.poll(10, TimeUnit.SECONDS))
    val report = reports.poll(10, TimeUnit.SECONDS) ?: throw AssertionError("the throw was never reported")
    assertEquals("the report names the timer", "t-throws", report.first)
    assertSame("the report carries what onDue threw", boom, report.second)
  }

  @Test
  fun ignoresAnOnErrorThatThrowsAndStillCallsBackATimerArmedAfterIt() {
    val calls = LinkedBlockingQueue<String>()
    val reported = CountDownLatch(1)
    val service =
      ThreadTimerService(
        onError = { _, _ ->
          reported.countDown()
          throw IllegalStateException("onError boom")
        }
      )
    service.arm(ArmedTimer("t-throws", System.currentTimeMillis() + 50, "noop")) {
      throw IllegalStateException("boom")
    }
    assertTrue("onError was never called", reported.await(10, TimeUnit.SECONDS))

    service.arm(ArmedTimer("t-after", System.currentTimeMillis() + 50, "noop")) { id -> calls.put(id) }
    assertEquals("a timer armed after onError threw is called back", "t-after", calls.poll(10, TimeUnit.SECONDS))
  }

  @Test
  fun byDefaultReportsAnOnDueThatThrowsToTheUncaughtExceptionHandler() {
    val reports = LinkedBlockingQueue<Throwable>()
    val calls = LinkedBlockingQueue<String>()
    val previous = Thread.getDefaultUncaughtExceptionHandler()
    Thread.setDefaultUncaughtExceptionHandler { _, error -> reports.put(error) }
    try {
      val service = ThreadTimerService()
      val boom = IllegalStateException("boom")
      service.arm(ArmedTimer("t-default", System.currentTimeMillis() + 50, "noop")) { throw boom }
      val report = reports.poll(10, TimeUnit.SECONDS) ?: throw AssertionError("the throw was never reported")
      assertSame("the report carries what onDue threw as its cause", boom, report.cause)
      assertTrue("the report names the timer: ${report.message}", report.message.orEmpty().contains("t-default"))

      service.arm(ArmedTimer("t-after", System.currentTimeMillis() + 50, "noop")) { id -> calls.put(id) }
      assertEquals("a timer armed after the report is called back", "t-after", calls.poll(10, TimeUnit.SECONDS))
    } finally {
      Thread.setDefaultUncaughtExceptionHandler(previous)
    }
  }

  @Test
  fun byDefaultPrintsAnOnDueThatThrowsWhenNoDefaultHandlerIsSet() {
    // A JVM starts with no default handler, and then the thread's handler is its thread group,
    // which prints the report to standard error.
    val calls = LinkedBlockingQueue<String>()
    val printed = ByteArrayOutputStream()
    val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
    val previousErr = System.err
    Thread.setDefaultUncaughtExceptionHandler(null)
    System.setErr(PrintStream(printed, true, Charsets.UTF_8))
    try {
      val service = ThreadTimerService()
      val threw = CountDownLatch(1)
      service.arm(ArmedTimer("t-unhandled", System.currentTimeMillis() + 50, "noop")) {
        threw.countDown()
        throw IllegalStateException("boom")
      }
      assertTrue("the throwing onDue was never called", threw.await(10, TimeUnit.SECONDS))
      // The service's one thread prints the report before it calls back the next timer, so the
      // report is complete once the later timer is called back.
      service.arm(ArmedTimer("t-after", System.currentTimeMillis() + 50, "noop")) { id -> calls.put(id) }
      assertEquals("a timer armed after the throw is called back", "t-after", calls.poll(10, TimeUnit.SECONDS))
    } finally {
      System.setErr(previousErr)
      Thread.setDefaultUncaughtExceptionHandler(previousHandler)
    }
    val report = printed.toString(Charsets.UTF_8)
    assertTrue("the report names the timer: <$report>", report.contains("onDue for timer t-unhandled threw"))
    assertTrue("the report carries what onDue threw: <$report>", report.contains("IllegalStateException: boom"))
  }

  @Test
  fun callsBackEveryPendingTimerInTheOrderTheyAreDueEachNoEarlierThanItsTime() {
    // Armed in neither the order they are due nor its reverse, so a service that calls back in
    // either arm order fails this, as does one where each arm supersedes the one before. The call
    // times catch a service that calls back every pending timer once the first one is due.
    val calls = LinkedBlockingQueue<Pair<String, Long>>()
    val service = ThreadTimerService()
    val now = System.currentTimeMillis()
    val due = mapOf("t-first" to now + 300, "t-second" to now + 900, "t-third" to now + 1_500)
    for (id in listOf("t-second", "t-third", "t-first")) {
      service.arm(ArmedTimer(id, due.getValue(id), "noop")) { calls.put(it to System.currentTimeMillis()) }
    }

    val called = List(3) { calls.poll(10, TimeUnit.SECONDS) }
    assertEquals(
      "every timer is called back, in the order they are due",
      listOf("t-first", "t-second", "t-third"),
      called.map { it?.first },
    )
    for ((id, at) in called.filterNotNull()) {
      assertTrue("$id was called back ${due.getValue(id) - at} ms before its time", at >= due.getValue(id))
    }
  }

  @Test
  fun schedulesATimerDueThirtyMinutesAheadForThirtyMinutesOut() {
    val delays = mutableListOf<Long>()
    val service = ThreadTimerService(scheduler = { delayMs, _ -> delays += delayMs })
    val thirtyMinutes = 30 * 60_000L
    service.arm(ArmedTimer("t-retry", System.currentTimeMillis() + thirtyMinutes, "noop")) {}

    assertEquals("one task was scheduled", 1, delays.size)
    assertTrue(
      "scheduled ${delays[0]} ms out for a timer due in $thirtyMinutes ms",
      delays[0] in (thirtyMinutes - 10_000)..thirtyMinutes,
    )
  }
}
