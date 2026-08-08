package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.EngineTimings
import com.geekinasuit.agency.pod.FakeAgentLauncher
import com.geekinasuit.agency.pod.FakeAgentVariant
import com.geekinasuit.agency.pod.FakeArtifactAction
import com.geekinasuit.agency.pod.FixtureAgentProfile
import com.geekinasuit.agency.pod.PermissionDecision
import com.geekinasuit.agency.pod.PodAuthMode
import com.geekinasuit.agency.pod.PodCompletion
import com.geekinasuit.agency.pod.PodEvent
import com.geekinasuit.agency.pod.PodProvider
import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.pod.PodTransport
import java.io.File
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * [EnginePodRunner] unit cells: the seam that puts the REAL engine stack
 * behind the daemon's [PodRunner]. The engine's own behavior is AcpPodEngineTest's job —
 * these cells pin what the RUNNER adds: transport dispatch (and its honest refusals), the
 * bind-once event sink, and the AGENCY-028 health drain's watermark contract over BOTH of
 * its counters — the engine's, driven by a dead-on-arrival launch, and the bridge's,
 * driven by a live fake agent whose ask facts the sink refuses.
 */
class EnginePodRunnerTest {

  @get:Rule val tmp = TemporaryFolder()

  /** A command that exists on every macOS/Linux host, is ABSOLUTE (a pod resolves against
   * the constructed env, not a login PATH), and speaks no acp: every launch attempt fails
   * at the initialize handshake — the deterministic way to drive the restart ladder to
   * exhaustion, with no protocol machinery anywhere in the cell. */
  private fun garbageProfile() = FixtureAgentProfile(listOf("/usr/bin/false"))

  private fun timings(
    initializeMs: Long = 2_000,
    newSessionMs: Long = 2_000,
    turnMs: Long = 2_000,
    askDeadlineMs: Long = 1_000,
    podWallClockMs: Long = 30_000,
    restartCap: Int = 1,
  ) =
    EngineTimings(
      initializeMs = initializeMs,
      newSessionMs = newSessionMs,
      turnMs = turnMs,
      askDeadlineMs = askDeadlineMs,
      groupReportMs = 2_000,
      podWallClockMs = podWallClockMs,
      restartCap = restartCap,
      backoffBaseMs = 10,
    )

  private fun runner() = EnginePodRunner(garbageProfile(), timings()) { PermissionDecision.AllowOnce }

  /** A runner over a REAL fake-agent subprocess, with engine-battery generosity in its
   * timings (a live JVM agent needs boot/handshake room the garbage-profile defaults
   * deliberately lack; restartCap=2 rides out a slow first boot without changing what a
   * cell observes). Null when [FakeAgentLauncher.agentCommand] is null — the caller
   * skips. */
  private fun fakeAgentRunner(): EnginePodRunner? {
    val command =
      FakeAgentLauncher.agentCommand(
        "--variant",
        FakeAgentVariant.HONEST.name,
        "--artifact-action",
        FakeArtifactAction.WRITE_FILE.name,
      ) ?: return null
    return EnginePodRunner(
      FixtureAgentProfile(command),
      timings(
        initializeMs = 20_000,
        newSessionMs = 20_000,
        turnMs = 20_000,
        askDeadlineMs = 10_000,
        podWallClockMs = 60_000,
        restartCap = 2,
      ),
    ) { PermissionDecision.AllowOnce }
  }

  /** The ONE legitimate skip: no usable `java` to launch the fake agent with, i.e. this
   * class is running outside bazel. Every other missing thing is a FAILURE — a battery
   * whose failure mode is skip reports green on the regressions it exists to catch. */
  private fun skip() {
    assumeTrue("fake agent binary not staged (run under bazel)", false)
  }

  private val noCompletion: (PodCompletion) -> Unit = {
    throw AssertionError("no completion expected in this cell")
  }

  @Test
  fun httpTransportIsRefusedLoudlyNamingTheMissingEngine() {
    runner().use { r ->
      r.bindEventSink {}
      val httpSpec =
        PodSpec(
          provider = PodProvider.LOCAL,
          model = "llama3",
          baseUrl = "http://127.0.0.1:11434",
          authMode = PodAuthMode.NONE,
          transport = PodTransport.HTTP,
          pinnedVersion = "http-0",
        )
      try {
        r.spawn(httpSpec, "plan:EPR-http", tmp.newFolder(), "unused", noCompletion)
        throw AssertionError("an HTTP spec must not spawn yet")
      } catch (expected: IllegalStateException) {
        // A configuration fault stated plainly: WHAT is missing, and which spec caused it.
        assertTrue(expected.message!!.contains("no engine for transport=http"))
        assertTrue(expected.message!!.contains("ACP pods only"))
        assertTrue(expected.message!!.contains("provider=local"))
      }
    }
  }

  @Test
  fun theAcpNonClaudeFenceHoldsAtTheRunnerSeamToo() {
    runner().use { r ->
      r.bindEventSink {}
      val grok =
        PodSpec(
          provider = PodProvider.GROK,
          model = "grok-4",
          authMode = PodAuthMode.API_KEY_FILE,
          transport = PodTransport.ACP,
          pinnedVersion = "grok-cli",
        )
      try {
        r.spawn(grok, "plan:EPR-grok", tmp.newFolder(), "unused", noCompletion)
        throw AssertionError("the acp-non-claude fence must hold at the runner's own spawn site")
      } catch (expected: IllegalStateException) {
        assertTrue(expected.message!!.contains("fenced pod profile"))
      }
    }
  }

  @Test
  fun eventSinkBindsExactlyOnce() {
    runner().use { r ->
      r.bindEventSink {}
      try {
        r.bindEventSink {}
        throw AssertionError("a second bind must be refused (bind-once)")
      } catch (expected: IllegalStateException) {
        assertTrue(expected.message!!.contains("event sink already bound"))
      }
    }
  }

  @Test
  fun healthDrainStartsEmpty() {
    runner().use { r -> assertTrue(r.drainHealthFaults().isEmpty()) }
  }

  @Test
  fun refusedEventReportsSurfaceThroughTheHealthDrainOnceThenTheWatermarkHolds() {
    // AGENCY-028, the runner's half: a sink that THROWS (the daemon's accept can refuse —
    // store failure, oversize) must not lose the fact silently. The engine counts the
    // refused report; the drain converts NEW counts into exactly one fault line naming the
    // ticket, and a second drain reports nothing new (watermark, not a latch).
    runner().use { r ->
      val exhausted = CountDownLatch(1)
      r.bindEventSink { e ->
        if (e is PodEvent.RestartsExhausted) exhausted.countDown()
        throw RuntimeException("sink refused (rig)")
      }
      val ws = tmp.newFolder()
      r.spawn(
        PodSpec.fixture(),
        "plan:EPR-1",
        ws,
        File(ws, "artifacts/plan-EPR-1").path,
        noCompletion,
      )
      assertTrue(
        "expected the garbage command to exhaust its restarts",
        exhausted.await(60, TimeUnit.SECONDS),
      )
      // The engine's failure count increments right after the sink's throw (same
      // supervisor thread); a bounded settle covers those few instructions.
      Thread.sleep(250)

      val faults = r.drainHealthFaults()
      assertTrue("expected an aggregated engine fault, got $faults", faults.isNotEmpty())
      assertTrue(
        faults.any { it.contains("pod-engine event sink refused") && it.contains("AGENCY-028") },
      )
      assertEquals("a second drain reports nothing new", emptyList<String>(), r.drainHealthFaults())
    }
  }

  @Test
  fun unjournalableAsksSurfaceTheBridgeFaultThroughTheHealthDrainOnceThenTheWatermarkHolds() {
    // AGENCY-028, the bridge's half: an ask whose PermissionAsked fact the sink refuses
    // is denied on the wire without the decider being consulted (PermissionBridgeTest
    // pins that direction); the RUNNER owes the record's half — the counted hole comes
    // out of the drain as the bridge's own fault line exactly once, then the watermark
    // holds. The sink refuses ONLY the ask fact, so the engine counter stays still and
    // the drained line is attributable to the bridge counter alone.
    val runner = fakeAgentRunner() ?: return skip()
    runner.use { r ->
      // Every delivered event is recorded (the refused ask facts too, before the throw):
      // a timed-out await below is otherwise a bare "expected X" with no clue which stage
      // stalled — and the restart causes carry the agent's own stderr tail.
      val seen = CopyOnWriteArrayList<PodEvent>()
      r.bindEventSink { e ->
        seen += e
        if (e is PodEvent.PermissionAsked) throw RuntimeException("sink refused the ask fact (rig)")
      }
      val completed = CountDownLatch(1)
      val ws = tmp.newFolder()
      r.spawn(PodSpec.fixture(), "plan:EPR-2", ws, File(ws, "artifacts/plan-EPR-2").path) {
        completed.countDown()
      }
      // The fixture agent completes its turns under wire-level denies, and each ask's
      // refusal is counted BEFORE its deny crosses the wire — so a delivered completion
      // already implies the counter is visible to the drain.
      assertTrue(
        "expected the pod to complete under denied-unjournaled asks [events: " +
          seen.joinToString("; ") + "]",
        completed.await(60, TimeUnit.SECONDS),
      )

      val faults = r.drainHealthFaults()
      assertEquals("expected exactly the bridge fault, got $faults", 1, faults.size)
      assertTrue(
        faults.single().contains("permission-bridge event sink refused") &&
          faults.single().contains("AGENCY-028"),
      )
      assertTrue(
        "the fault names the fail-closed consequence",
        faults.single().contains("denied unjournaled"),
      )
      assertEquals("a second drain reports nothing new", emptyList<String>(), r.drainHealthFaults())
    }
  }
}
