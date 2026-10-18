package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.ArmedTimer

// Host seams any agent's daemon uses, whatever workflow it runs: timers and the deterministic
// fault seam.

/** Timer seam: adopt re-arms pending timers through this; firing enqueues a wake. */
fun interface TimerService {
  fun arm(timer: ArmedTimer, onDue: (String) -> Unit)

  companion object {
    /** Fires nothing: a test that passes it fires each timer itself, with
     * [LeadDaemon.injectTimerDue]. A daemon under a ceremony auth refuses it, since there a failed
     * gate-open announce waits on a timer to be sent again or escalated. */
    val NOOP = TimerService { _, _ -> }
  }
}

/** Runs a task once, after a delay in milliseconds: the seam through which a test sees the delay
 * [ThreadTimerService] schedules, without waiting for it. */
fun interface TimerScheduler {
  fun schedule(delayMs: Long, task: () -> Unit)

  companion object {
    /** Runs every task on one daemon thread named [name], so the thread never keeps a process
     * running. It waits on the wall clock. A task that throws ends the thread, and every later
     * schedule then throws, so a task given here must not throw. */
    fun daemonThread(name: String): TimerScheduler {
      val timer = java.util.Timer(name, true)
      return TimerScheduler { delayMs, task ->
        timer.schedule(
          object : java.util.TimerTask() {
            override fun run() = task()
          },
          delayMs,
        )
      }
    }
  }
}

/**
 * Wall-clock timer service for real runs: schedules the wake at fireAtEpochMs, on [scheduler].
 *
 * A deployment keeps one service for the lead's lifetime and arms every later gate-open retry on
 * it, and the default scheduler runs every timer on one thread that a throwing task would end. So
 * each callback runs inside a catch: an `onDue` that throws is reported to [onError], and later
 * timers still fire. The default [onError] hands the error to the thread's uncaught-exception
 * handler, which prints it, and the thread keeps running. An [onError] that throws is ignored, for
 * the same reason.
 */
class ThreadTimerService(
  private val onError: (timerId: String, error: Throwable) -> Unit = ::reportToUncaughtHandler,
  private val scheduler: TimerScheduler = TimerScheduler.daemonThread("lead-timers"),
) : TimerService {
  override fun arm(timer: ArmedTimer, onDue: (String) -> Unit) {
    val delay = (timer.fireAtEpochMs - System.currentTimeMillis()).coerceAtLeast(0)
    scheduler.schedule(delay) {
      try {
        onDue(timer.id)
      } catch (t: Throwable) {
        try {
          onError(timer.id, t)
        } catch (_: Throwable) {
          // Nothing is left to report to, and the thread has to keep running.
        }
      }
    }
  }
}

private fun reportToUncaughtHandler(timerId: String, error: Throwable) {
  val thread = Thread.currentThread()
  thread.uncaughtExceptionHandler.uncaughtException(
    thread,
    RuntimeException("onDue for timer $timerId threw", error),
  )
}

/** Deterministic fault seam: the fixture exits 42 at a named instruction boundary. */
fun interface FaultInjector {
  fun at(boundary: String)

  companion object {
    val NONE = FaultInjector { }
  }
}
