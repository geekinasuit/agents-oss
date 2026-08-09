package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.shared.harness.ClaudeHarness
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Model-backed smoke — env-gated OUT of CI and bazel-tagged manual. Run it by hand on a
 * host with a logged-in claude binary — session credential state under `$HOME`, because
 * the constructed subprocess env never carries `ANTHROPIC_*`, so an exported API key
 * cannot authenticate it (see `Subprocess.POD_ENV_ALLOWLIST`):
 *
 * ```
 * bazel test //agency/lead:claude_cognition_smoke_test \
 *   --test_env=AGENCY_MODEL_TESTS=1 \
 *   --test_env=PATH \
 *   --test_output=all --nocache_test_results
 * ```
 *
 * Both `--test_env` forms are required, not decoration: bazel does not forward the client
 * environment into the test JVM, so an exported AGENCY_MODEL_TESTS alone leaves the gate
 * skipping while reporting PASSED — and the harness builds the claude subprocess's
 * environment from the test JVM's own PATH (the cleanEnv allowlist), so without
 * `--test_env=PATH` the run fails red on binary lookup under bazel's stripped action PATH
 * instead of running.
 *
 * Budget-capped, and the assertions are STRUCTURAL only — a wake consulted the
 * model, the decision was journaled with cognition provenance (sessionId + cost
 * attached), and nothing the model produced released a gate. Never prose.
 */
class ClaudeCognitionSmokeTest {

  @get:Rule val tmp = TemporaryFolder()

  @Test
  fun modelBackedWakeJournalsProposalsAndReleasesNothing() {
    assumeTrue(
      "set AGENCY_MODEL_TESTS=1 to run the model-backed smoke",
      System.getenv("AGENCY_MODEL_TESTS") == "1",
    )
    val dir = tmp.newFolder()
    File(dir, "ticket.txt").writeText("t1\n")
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val counting =
      CountingCognition(
        ClaudeCognition(
          harness = ClaudeHarness(),
          workDir = dir,
          maxBudgetUsd = 0.25,
        )
      )
    val daemon =
      LeadDaemon(
        store = store,
        cognition = counting,
        // Held completions: this smoke exercises ONE model wake deterministically; the
        // scripted walk owns full-pipeline coverage.
        podRunner = FakePodRunner(holdCompletions = true),
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
      )

    val folded = daemon.driveUntilQuiescent()

    // Structural: the wake happened, and each model decision is journaled with
    // cognition provenance carrying session identity and cost.
    assertTrue(counting.calls >= 1)
    val cogEntries = store.readAll().filter { it.kind == LeadKinds.COGNITION_PROPOSED }
    assertTrue("model produced no journaled decision", cogEntries.isNotEmpty())
    assertTrue(cogEntries.all { it.origin == ORIGIN_COGNITION })
    assertTrue(cogEntries.all { it.payloadJson.contains("sessionId") })
    // Discriminates a real turn from a failed-harness escalation: a session id was minted.
    assertTrue(
      "no cognition entry carries a real session id",
      cogEntries.any { it.payloadJson.contains(ClaudeHarness.UUID_RE) },
    )

    // Structural: nothing the model did released a gate — the fold's provenance check
    // is indifferent to model output.
    assertTrue(folded.lead.releasedGates.isEmpty())
    assertTrue(folded.shared.gateReleases.isEmpty())
    store.close()
  }
}
