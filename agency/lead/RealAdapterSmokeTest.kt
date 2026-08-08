package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.ClaudeAdapterProfile
import com.geekinasuit.agency.pod.EngineTimings
import com.geekinasuit.agency.pod.PermissionDecision
import com.geekinasuit.agency.pod.PodCompletion
import com.geekinasuit.agency.pod.PodEvent
import com.geekinasuit.agency.pod.PodSpec
import java.io.File
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Env-gated STRUCTURAL smoke against the REAL pinned Claude adapter: the full production
 * stack —
 * [EnginePodRunner] → AcpPodEngine → PermissionBridge → [ClaudeAdapterProfile] → the
 * lockfile-pinned `@agentclientprotocol/claude-agent-acp` under node — driving one live
 * pod on a real host with the machine credential. This is the cell that answers the
 * composition question the deterministic battery cannot: does the adapter
 * launch, handshake at the pinned protocol, establish a session under the lead-owned
 * workspace-INDEPENDENT config (settingSources: [] + relocated CLAUDE_CONFIG_DIR), and
 * route permission asks through our bridge?
 *
 * DECIDER: REJECT-ALL, deliberately (a human-answered full-task demo is a separate exit
 * criterion, not this cell): every ask the adapter routes is denied, so the run spends at
 * most a couple of refused model turns and no tool ever executes. STRUCTURE is asserted —
 * a session established, at least one ask routed (the liveness preflight guarantees one on
 * any correctly-launched adapter), and a clean terminal outcome — while the OUTCOME may
 * be either a completion (the adapter may auto-allow plain file writes without routing an
 * ask) or a terminal refusal (artifact missing because every ask was denied). Both are
 * structurally sound; which one a given adapter build produces is telemetry, recorded to
 * the test's undeclared outputs (welfare floor: the pod's event record is preserved, not
 * discarded with the sandbox).
 *
 * GATING (all skips, never failures, so wildcard builds stay green):
 *  - AGENCY_ADAPTER_SMOKE=1        — the explicit opt-in.
 *  - AGENCY_ADAPTER_DIR            — ABSOLUTE path to the adapter install dir (the
 *                                    directory holding package.json + node_modules after
 *                                    `npm ci --ignore-scripts` in the agency module's
 *                                    agency/pod/adapter package — e.g. a module checkout,
 *                                    or a derived copy of the pinned manifests).
 *  - AGENCY_ADAPTER_NODE           — ABSOLUTE path to the node binary (pods resolve
 *                                    against a constructed env, never a login PATH).
 *  - AGENCY_ADAPTER_CONFIG_DIR     — optional ABSOLUTE lead-owned CLAUDE_CONFIG_DIR. When
 *                                    unset a FRESH temp dir is used — the strictest
 *                                    workspace-independent shape, which also probes
 *                                    whether machine-credential auth composes with a
 *                                    relocated config root; an operator can point this at
 *                                    a prepared dir to answer the other half.
 *  - AGENCY_ADAPTER_MODEL          — optional model name, default "haiku" (cheapest).
 *
 * Run (from the repo root, node on PATH, adapter installed per AGENCY_ADAPTER_DIR above):
 *   AGENCY_ADAPTER_SMOKE=1 bazel test //agency/lead:real_adapter_smoke_test \
 *     --test_env=AGENCY_ADAPTER_SMOKE \
 *     --test_env=AGENCY_ADAPTER_DIR=<abs path to the installed adapter package dir> \
 *     --test_env=AGENCY_ADAPTER_NODE=$(command -v node) \
 *     --test_output=streamed
 */
class RealAdapterSmokeTest {

  @get:Rule val tmp = TemporaryFolder()

  @Test
  fun realAdapterLaunchesHandshakesRoutesAsksAndTerminatesCleanly() {
    assumeTrue(
      "real-adapter smoke is env-gated: set AGENCY_ADAPTER_SMOKE=1 to run",
      System.getenv("AGENCY_ADAPTER_SMOKE") == "1",
    )
    val adapterDir = System.getenv("AGENCY_ADAPTER_DIR")
    assumeTrue("AGENCY_ADAPTER_DIR must point at the adapter install", adapterDir != null)
    val node = System.getenv("AGENCY_ADAPTER_NODE")
    assumeTrue("AGENCY_ADAPTER_NODE must point at the node binary", node != null)
    val entry =
      File(
        adapterDir!!,
        "node_modules/@agentclientprotocol/claude-agent-acp/dist/index.js",
      )
    assumeTrue(
      "adapter entry missing — run `npm ci --ignore-scripts` in the agency module's " +
        "agency/pod/adapter package first (looked at ${entry.path})",
      entry.isFile,
    )

    val configDir =
      System.getenv("AGENCY_ADAPTER_CONFIG_DIR")?.let(::File)
        ?: tmp.newFolder("lead-config") // fresh + workspace-independent
    val profile = ClaudeAdapterProfile(File(node!!), entry.absoluteFile, configDir)
    val spec =
      PodSpec.claudeAdapter(
        model = System.getenv("AGENCY_ADAPTER_MODEL") ?: "haiku",
        maxTurns = 4,
        maxBudgetUsd = 0.50,
      )
    // Generous real-world clocks; restartCap=1 so a broken host fails in ONE attempt's
    // worth of time with the failure named, instead of grinding the ladder.
    val timings =
      EngineTimings(
        initializeMs = 60_000,
        newSessionMs = 60_000,
        turnMs = 240_000,
        askDeadlineMs = 20_000,
        groupReportMs = 5_000,
        podWallClockMs = 480_000,
        restartCap = 1,
        backoffBaseMs = 500,
      )

    val events = CopyOnWriteArrayList<PodEvent>()
    val completion = AtomicReference<PodCompletion?>(null)
    val settled = CountDownLatch(1)

    val runner = EnginePodRunner(profile, timings) { PermissionDecision.RejectOnce }
    runner.use { r ->
      r.bindEventSink { e ->
        events += e
        if (
          e is PodEvent.PreflightRefused ||
            e is PodEvent.ArtifactRefused ||
            e is PodEvent.RestartsExhausted ||
            e is PodEvent.DeadlineKilled
        ) {
          settled.countDown()
        }
      }
      val ws = tmp.newFolder("smoke-ws")
      r.spawn(
        spec,
        // The taskRef is the pod's task line verbatim — plain and honest about what this
        // run is (welfare floor: prompt dignity even in instrument mode).
        "smoke: this is a structural launch check; write a short friendly note (2-3 " +
          "sentences, any topic you like) to the artifact path, then stop",
        ws,
        File(ws, "artifacts/smoke-note.md").path,
      ) {
        completion.set(it)
        settled.countDown()
      }
      assertTrue(
        "the pod neither completed nor reached a terminal refusal within its wall clock " +
          "(events so far: $events)",
        settled.await(520, TimeUnit.SECONDS),
      )
    }

    // Preserve the pod's full event record + outcome beside the test log, win or refuse.
    dumpRecord(events, completion.get())

    val established = events.filterIsInstance<PodEvent.SessionEstablished>()
    assertTrue("the real adapter must establish a session, events: $events", established.isNotEmpty())
    val asks = events.filterIsInstance<PodEvent.PermissionAsked>()
    assertTrue(
      "a correctly-launched adapter routes at least the liveness preflight ask, events: $events",
      asks.isNotEmpty(),
    )
    val done = completion.get()
    val terminal =
      events.any {
        it is PodEvent.PreflightRefused ||
          it is PodEvent.ArtifactRefused ||
          it is PodEvent.RestartsExhausted ||
          it is PodEvent.DeadlineKilled
      }
    assertTrue("either outcome is structural: completion or terminal refusal", done != null || terminal)
    if (done != null) {
      assertTrue("a completion carries the snapshot's own bytes", done.snapshot.isNotEmpty())
    }
    assertTrue("every pod terminal + executors down after close", runner.closedCleanly())
  }

  /** The record outlives the sandbox via TEST_UNDECLARED_OUTPUTS_DIR (bazel exports it in
   * outputs.zip); stdout carries a copy either way. */
  private fun dumpRecord(events: List<PodEvent>, completion: PodCompletion?) {
    val lines = buildString {
      appendLine("== real-adapter smoke record ==")
      for (e in events) appendLine(e.toString())
      appendLine("completion: ${completion?.let { "digest=${it.resultDigest} costUsd=${it.costUsd}" } ?: "none"}")
      completion?.let { appendLine("-- snapshot --\n${String(it.snapshot)}") }
    }
    print(lines)
    System.getenv("TEST_UNDECLARED_OUTPUTS_DIR")?.let {
      File(it, "smoke-record.txt").writeText(lines)
    }
  }
}
