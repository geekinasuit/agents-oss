package com.geekinasuit.agency.shared.journal

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The durability scenarios, hermetic: each cell spawns the
 * fixture binary from runfiles, injects a DETERMINISTIC death at the exercised instruction
 * boundary (exit 42 — deterministic kill points, not sleeps), then recovers with a fresh
 * process re-folding the journal. Positive-control cells prove the harness can observe
 * each failure it claims to prevent.
 */
class ScenarioTest {

  @get:Rule val tmp = TemporaryFolder()

  private val fixture: String by lazy {
    val srcdir = System.getenv("TEST_SRCDIR") ?: error("TEST_SRCDIR not set (not under bazel test)")
    // The runfiles path comes from BUILD ($(rlocationpath)): its leading repo segment
    // depends on whether this module is the build root or a consumed dependency.
    val rloc =
        System.getenv("JOURNAL_FIXTURE")
            ?: error("JOURNAL_FIXTURE not set (scenario_test supplies it via rlocationpath)")
    val f = File(srcdir, rloc)
    check(f.exists()) { "journal_fixture not found in runfiles at $f" }
    f.absolutePath
  }

  private fun run(dir: String, vararg args: String): Int {
    val cmd = listOf(fixture) + args + listOf("--dir", dir)
    val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
    val out = p.inputStream.readBytes().toString(Charsets.UTF_8)
    val code = p.waitFor()
    if (code !in setOf(0, 42, 3)) {
      throw AssertionError("fixture ${args.toList()} exited $code:\n$out")
    }
    return code
  }

  private fun effectCount(dir: String, key: String): Int = EffectReceiver(dir).lineCountFor(key)

  @Test
  fun killAfterIntentThenResumeFiresExactlyOnce() {
    val dir = tmp.newFolder().absolutePath
    assertEquals(42, run(dir, "step-effect", "--key", "k1", "--fault", "after-intent"))
    assertEquals(0, effectCount(dir, "k1")) // died before the effect fired
    assertEquals(0, run(dir, "resume"))
    assertEquals(1, effectCount(dir, "k1"))
    SqliteStore(dir, componentId = "fixture").use { store ->
      assertTrue(fold(store.readAll()).pendingEffectKeys.isEmpty())
    }
  }

  @Test
  fun killAfterEffectThenResumeDoesNotDoubleFire() {
    val dir = tmp.newFolder().absolutePath
    assertEquals(42, run(dir, "step-effect", "--key", "k1", "--fault", "after-effect"))
    assertEquals(1, effectCount(dir, "k1")) // fired once, but no done entry survives
    assertEquals(0, run(dir, "resume")) // re-fires; the receiver dedups on the idempotency key
    assertEquals(1, effectCount(dir, "k1"))
    SqliteStore(dir, componentId = "fixture").use { store ->
      val state = fold(store.readAll())
      assertTrue(state.pendingEffectKeys.isEmpty())
      assertEquals(2, state.doneKeys["k1"]) // completion recorded by the resume attempt
    }
  }

  @Test
  fun positiveControlWithoutDedupObservesTheDoubleFire() {
    val dir = tmp.newFolder().absolutePath
    assertEquals(42, run(dir, "step-effect", "--key", "k1", "--fault", "after-effect", "--no-dedup"))
    assertEquals(0, run(dir, "resume", "--no-dedup"))
    // A check that cannot see the failure is not evidence: without receiver dedup the
    // crash window really does double-fire, and this harness observes it.
    assertEquals(2, effectCount(dir, "k1"))
  }

  @Test
  fun multiplePendingEffectsAllRecoverExactlyOnce() {
    val dir = tmp.newFolder().absolutePath
    assertEquals(42, run(dir, "step-effect", "--key", "k1", "--fault", "after-intent"))
    assertEquals(42, run(dir, "step-effect", "--key", "k2", "--fault", "after-effect"))
    assertEquals(0, run(dir, "resume"))
    assertEquals(1, effectCount(dir, "k1"))
    assertEquals(1, effectCount(dir, "k2"))
  }

  @Test
  fun timerSurvivesProcessDeathAndFiresAfterRestart() {
    val dir = tmp.newFolder().absolutePath
    assertEquals(42, run(dir, "arm-timer", "--id", "t1", "--fire-in-ms", "150", "--fault", "after-arm"))
    assertEquals(0, run(dir, "serve-timers", "--wait-ms", "15000")) // fresh process re-arms from the fold
    assertEquals(1, EffectReceiver(dir, fileName = "timers.log").lineCountFor("timer-t1"))
    SqliteStore(dir, componentId = "fixture").use { store ->
      assertTrue(fold(store.readAll()).pendingTimers.isEmpty())
    }
  }

  @Test
  fun positiveControlSkipRearmObservesTheMissingFire() {
    val dir = tmp.newFolder().absolutePath
    assertEquals(42, run(dir, "arm-timer", "--id", "t1", "--fire-in-ms", "50", "--fault", "after-arm"))
    assertEquals(0, run(dir, "serve-timers", "--wait-ms", "500", "--skip-rearm"))
    assertEquals(0, EffectReceiver(dir, fileName = "timers.log").lineCountFor("timer-t1"))
  }
}
