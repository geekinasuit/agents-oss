package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.shared.harness.OpenAiAuthMode
import com.geekinasuit.agency.shared.harness.OpenAiCompatHarness
import com.geekinasuit.agency.shared.harness.OpenAiCompatProfile
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The model-backed cognition gate, run against a real local model.
 *
 * **Status, stated plainly: this is a LOCAL/MANUAL
 * criterion, not a CI gate.** The CI runner's Ollama availability is not assumed,
 * so a skip here is expected in CI and proves nothing. The CI floor for this path is
 * [OpenAiCompatCognitionTest], which covers the same code deterministically. Run this by
 * hand on a host with Ollama:
 *
 * ```
 * bazel test //agency/lead:ollama_cognition_smoke_test \
 *   --test_env=AGENCY_MODEL_TESTS=1 \
 *   --test_output=all --nocache_test_results
 * ```
 *
 * `--test_env` is required, not decoration: bazel does not forward the client environment
 * into the test JVM, so an exported variable alone leaves the gate skipping while
 * reporting PASSED. Add `--test_env=AGENCY_OLLAMA_MODEL=<tag>` to override the model.
 * Assertions are STRUCTURAL only — never on the content of what
 * the model said.
 *
 * **What this cell cannot observe.** "Zero egress" is asserted as the configuration it is:
 * the endpoint is loopback and the profile carries no credential. That does not — and no
 * test at this layer can — observe a second HTTP client, a telemetry lane, or a DNS
 * lookup, which are the classes an egress *claim* would have to cover.
 */
class OllamaCognitionSmokeTest {

  @get:Rule val tmp = TemporaryFolder()

  private val model: String = System.getenv("AGENCY_OLLAMA_MODEL") ?: DEFAULT_MODEL

  private val profile: OpenAiCompatProfile
    get() = OpenAiCompatProfile.ollama(model)

  /**
   * Skips ONLY when no connection could be established — the one condition this host
   * legitimately may not meet. Every other failure (a missing model tag, an error status, a
   * read timeout, a reset mid-exchange) is a real failure and is left to fail: a gate whose
   * failure mode is "skip" reports green on exactly the regressions it exists to catch.
   *
   * Keyed on [OpenAiCompatHarness.CONNECT_FAILURE_CODE] specifically, which is why that code
   * is distinct from the generic transport failure. A fault DURING an exchange proves
   * something was listening and misbehaved — skipping on that would hide a broken endpoint
   * behind "Ollama isn't installed here".
   */
  private fun requireOllama() {
    assumeTrue(
      "set AGENCY_MODEL_TESTS=1 to run the model-backed gate",
      System.getenv("AGENCY_MODEL_TESTS") == "1",
    )
    val probe =
      OpenAiCompatHarness(profile).chat("ping", "ping", maxTokens = 1, timeoutSec = PROBE_TIMEOUT_SEC)
    assumeTrue(
      "no Ollama listening at ${profile.baseUrl} (${probe.error})",
      probe.status != OpenAiCompatHarness.CONNECT_FAILURE_CODE,
    )
  }

  private fun cognition() = OpenAiCompatCognition(OpenAiCompatHarness(profile))

  @Test
  fun theConfigurationIsLoopbackAndKeyFree() {
    // Deliberately NOT gated on Ollama running: this is the configuration assertion that
    // stands in for the egress claim, and it is a property of the profile alone.
    assertTrue("the cognition endpoint must be loopback", profile.isLoopback)
    assertEquals("no credential may be configured on this path", OpenAiAuthMode.NONE, profile.authMode)
  }

  @Test
  fun aModelBackedWakeJournalsACognitionProposalAndReleasesNothing() {
    requireOllama()
    val dir = tmp.newFolder()
    File(dir, "ticket.txt").writeText("TEST-7\n")
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val counting = CountingCognition(cognition())
    val daemon =
      LeadDaemon(
        store = store,
        cognition = counting,
        // Held completions: this gate exercises the model wake, not the pipeline walk.
        podRunner = FakePodRunner(holdCompletions = true),
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        maxCognitionAttempts = OpenAiCompatCognition.MAX_ATTEMPTS_PER_WAKE,
      )

    val folded = daemon.driveUntilQuiescent()

    assertTrue("no wake consulted the model", counting.calls >= 1)
    val cogEntries = store.readAll().filter { it.kind == LeadKinds.COGNITION_PROPOSED }
    assertTrue("model produced no journaled decision", cogEntries.isNotEmpty())
    assertTrue(cogEntries.all { it.origin == ORIGIN_COGNITION })
    // Token counts are this wire's provenance where the Claude path has a session id;
    // their presence discriminates a real completed turn from a failed-transport escalation.
    assertTrue(
      "no cognition entry carries this transport's provenance",
      cogEntries.any { it.payloadJson.contains("completionTokens") },
    )

    // Nothing the model produced released a gate. Read narrowly: on this fixture the model
    // has no reason to propose a gate-open, so this shows the run stayed inside its lane —
    // NOT that the origin check would refuse one. That property is proven where it can
    // actually be exercised, by the fold's own tests against a forged cognition-origin
    // release, and is not what a live model happening to behave demonstrates.
    assertTrue(folded.lead.releasedGates.isEmpty())
    assertTrue(folded.shared.gateReleases.isEmpty())
    store.close()
  }

  @Test
  fun idleBlocksWithZeroStrategyCallsWhileTheQueueIsEmpty() {
    requireOllama()
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val counting = CountingCognition(cognition())
    val daemon =
      LeadDaemon(
        store = store,
        cognition = counting,
        podRunner = FakePodRunner(holdCompletions = true),
        podSpec = PodSpec.fixture(),
        // No ticket: nothing to do, so the loop reaches its blocking state immediately.
        ticketSource = FileTicketSource(File(dir, "absent-ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        maxCognitionAttempts = OpenAiCompatCognition.MAX_ATTEMPTS_PER_WAKE,
      )
    val thread = Thread { daemon.runLoop() }
    thread.start()

    awaitTrue("the adopt wake consulted the model once") { counting.calls == 1 }
    // Idle is measured by STRATEGY CALLS, not by cost: a free local model would report a
    // spend of zero whether the loop were blocked or spinning, so cost cannot tell the two
    // apart and call count is the only observable that can.
    Thread.sleep(IDLE_OBSERVATION_MS)
    assertEquals("a blocked loop must consult nothing", 1, counting.calls)

    daemon.injectMail("wake up")
    awaitTrue("mail injection woke the loop") { counting.calls == 2 }

    daemon.shutdown()
    thread.join(JOIN_TIMEOUT_MS)
    assertTrue("the loop did not exit", !thread.isAlive)
    store.close()
  }

  private fun awaitTrue(what: String, deadlineMs: Long = AWAIT_TIMEOUT_MS, cond: () -> Boolean) {
    val giveUpAt = System.nanoTime() + deadlineMs * 1_000_000
    while (System.nanoTime() < giveUpAt) {
      if (cond()) return
      Thread.sleep(POLL_MS)
    }
    throw AssertionError("timed out after ${deadlineMs}ms waiting: $what")
  }

  companion object {
    private const val DEFAULT_MODEL = "qwen3-coder:30b"
    private const val PROBE_TIMEOUT_SEC = 10

    /** How long the loop is watched doing nothing. Comfortably longer than a wake's own
     * turn, so a loop that were polling would have called again within the window. */
    private const val IDLE_OBSERVATION_MS = 2_000L

    /** Generous: a local turn on a 30B model is seconds, not milliseconds. */
    private const val AWAIT_TIMEOUT_MS = 120_000L
    private const val JOIN_TIMEOUT_MS = 30_000L
    private const val POLL_MS = 50L
  }
}
