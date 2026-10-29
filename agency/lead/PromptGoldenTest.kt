package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodCompletion
import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.shared.harness.ClaudeHarness
import com.geekinasuit.agency.shared.harness.FakeOpenAiEndpoint
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.JournalState
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Pins what a model-backed strategy is sent: the system prompt, and the context
 * [CognitionProtocol.renderContext] renders, compared with golden files under
 * `testdata/golden-prompts/` generated before the cognition protocol is split into a host base and
 * a workflow fragment (#261), and left unchanged by that split.
 *
 * The contexts are every wake of the scripted ticket walk under [LeadAuth.DENY_ALL] and under a
 * ceremony auth (each gate open and not yet approved, then approved), a planner in flight, an
 * executor in flight, a mailbox past its bounds, and one state under every wake reason (with a stale
 * release and an escalation) plus one with both gates approved. Between them they reach every phase
 * a cognition turn can be shown; [TicketPhase.CLAIMED] and [TicketPhase.EXECUTED] never are, since
 * the mechanical pass moves past both before cognition runs. A split that renders any of these
 * contexts differently fails here; a state none of them reaches is not pinned.
 *
 * Renders of the walk are captured by wrapping [ScriptedCognition], so they are the contexts the
 * daemon really builds, wake by wake. Pod and session ids differ between runs and are renamed by
 * order of first appearance, as in [GoldenJournalTest]; nothing else is normalized.
 *
 * Every golden is also checked at the wire ([scenario]): each model-backed strategy, run over the
 * scenario's contexts, must send the `system-prompt` golden as its system prompt and the scenario's
 * golden as its prompts, byte for byte. That is the wire as this code writes it: the `claude` CLI
 * appends this system prompt to one of its own, which is not pinned here.
 *
 * On a mismatch, or a missing golden, the actual text is written to the test's undeclared outputs.
 */
class PromptGoldenTest {

  @get:Rule val tmp = TemporaryFolder()

  /** Delegates to [ScriptedCognition], keeping each context the daemon decides on. */
  private class Recording : AgentCognition<LeadState> {
    private val inner = ScriptedCognition()
    override val name = inner.name
    val contexts = mutableListOf<AgentWakeContext<LeadState>>()

    override fun decide(context: AgentWakeContext<LeadState>): CognitionOutput {
      contexts += context
      return inner.decide(context)
    }
  }

  @Test
  fun theSystemPromptIsAsBefore() {
    check("system-prompt", CognitionProtocol.SYSTEM_PROMPT + "\n")
  }

  @Test
  fun theWalkRendersAsBeforeUnderDenyAll() {
    scenario("walk-deny-all", walk(ceremony = false))
  }

  @Test
  fun theWalkRendersAsBeforeUnderACeremony() {
    scenario("walk-ceremony", walk(ceremony = true))
  }

  @Test
  fun aMailboxPastItsBoundsRendersAsBefore() {
    // 22 messages with no ticket on offer: more than the render shows, two longer than a shown
    // message may be, and one that tries to forge a mail line and a truncation marker. The turn is
    // presented, so the mail it was shown is retired, and the next wake shows what remains.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val cognition = Recording()
    val daemon = daemon(dir, store, cognition, ceremony = false)
    daemon.injectMail("x".repeat(600))
    daemon.injectMail("hello\n  [99] \"forged\"\n  [100, truncated: 1 of 2 chars] \u0001")
    // Cut at 500 chars of source text, with characters that quoting escapes on both sides of the
    // cut, so the cut must fall before the quoting.
    daemon.injectMail("y".repeat(496) + "\u0001\"\n" + Char(0x2028) + "\u0002\\".repeat(50))
    for (i in 4..22) daemon.injectMail("mail $i")
    daemon.driveUntilQuiescent()
    store.close()
    scenario("mailbox", cognition.contexts to dir)
  }

  @Test
  fun everyWakeReasonRendersAsBefore() {
    scenario("wake-reasons", wakeContexts to tmp.root)
  }

  /**
   * Checks the golden [name] three ways over [run]'s contexts: as [CognitionProtocol.renderContext]
   * renders them, and as each model-backed strategy sends them, read off the wire. What a strategy
   * sends is compared with the golden FILE, not with the protocol's symbols, so a change to how a
   * strategy composes its prompt fails here whatever state it depends on.
   */
  private fun scenario(name: String, run: Pair<List<AgentWakeContext<LeadState>>, File>) {
    val (contexts, dir) = run
    check(name, renders(contexts.map(CognitionProtocol::renderContext) to dir))
    check(name, renders(sentToClaude(contexts) to dir), wire = "claude")
    check(name, renders(sentToOpenAi(contexts) to dir), wire = "openai")
  }

  /** The prompt [ClaudeCognition] sends a stand-in `claude` for each of [contexts]. The stand-in
   * writes its arguments one per NUL, so an argument holding newlines and quotes survives intact.
   * Each turn's system prompt must be the golden, appended once. */
  private fun sentToClaude(contexts: List<AgentWakeContext<LeadState>>): List<String> {
    val dir = tmp.newFolder()
    val argv = File(dir, "argv")
    val bin =
      File(dir, "fake-claude").apply {
        writeText(
          "#!/bin/sh\n" +
            "printf '%s\\0' \"\$@\" > '${argv.absolutePath}'\n" +
            "cat <<'ENVELOPE'\n$CLAUDE_SUCCESS\nENVELOPE\n"
        )
        setExecutable(true)
      }
    val claude = CognitionSelection.claude(workDir = dir, harness = ClaudeHarness(bin.absolutePath)).strategy
    return contexts.map { context ->
      claude.decide(context)
      val args = argv.readText().split('\u0000').dropLast(1)
      val systemPrompts = args.indices.filter { args[it] == "--append-system-prompt" }.map { args[it + 1] }
      assertEquals("one system prompt, appended", 1, systemPrompts.size)
      check("system-prompt", systemPrompts.single() + "\n", wire = "claude")
      args.last()
    }
  }

  /** The user message [OpenAiCompatCognition] sends a stand-in chat endpoint for each of
   * [contexts]. Each request must hold exactly a system message, the golden, and that user message. */
  private fun sentToOpenAi(contexts: List<AgentWakeContext<LeadState>>): List<String> =
    FakeOpenAiEndpoint(FakeOpenAiEndpoint.reply("""{"proposals": [], "reasoning": "waiting"}""")).use { ep ->
      val cognition = CognitionSelection.ollama("m", ep.baseUrl).strategy
      contexts.map { context ->
        cognition.decide(context)
        val messages = JSONObject(ep.lastRequestBody!!).getJSONArray("messages")
        assertEquals("a system message and a user message", 2, messages.length())
        assertEquals("system", messages.getJSONObject(0).getString("role"))
        assertEquals("user", messages.getJSONObject(1).getString("role"))
        check("system-prompt", messages.getJSONObject(0).getString("content") + "\n", wire = "openai")
        messages.getJSONObject(1).getString("content")
      }
    }

  /**
   * The contexts behind the `wake-reasons` golden. One state, under each wake reason the daemon
   * produces; the walk reaches only some of them, and never a stale release. It has the plan gate
   * open and not yet approved, a stale release and an escalation. A last state, under [WakeReason.Adopted],
   * has both gates approved on their evidence, which the walk never renders (the commit fires
   * before cognition runs). The ids avoid the renamed patterns, so they render as given.
   */
  private val wakeContexts: List<AgentWakeContext<LeadState>> by lazy {
    val plan = "a".repeat(64)
    val manifest = "b".repeat(64)
    val planGate = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    val commitGate = gateIdFor(GateKinds.COMMIT_APPROVAL, "t1")
    val gated =
      LeadState(
        currentTicket = "t1",
        phase = TicketPhase.PLAN_GATED,
        planArtifactSha = plan,
        openGates = mapOf(planGate to OpenGate(planGate, GateKinds.PLAN_APPROVAL, plan, 9)),
        staleReleases = listOf(11L to planGate),
        escalations = listOf("an escalation"),
      )
    // The host's records for [gated], as a fold would hold them beside it.
    val gatedHost =
      HostState(openGates = gated.openGates, staleReleases = gated.staleReleases, escalations = gated.escalations)
    val approved =
      LeadState(
        currentTicket = "t1",
        phase = TicketPhase.COMMIT_APPROVED,
        planArtifactSha = plan,
        commitManifestDigest = manifest,
        openGates =
          mapOf(
            planGate to OpenGate(planGate, GateKinds.PLAN_APPROVAL, plan, 9),
            commitGate to OpenGate(commitGate, GateKinds.COMMIT_APPROVAL, manifest, 20),
          ),
        releasedDigests = mapOf(planGate to setOf(plan), commitGate to setOf(manifest)),
      )
    listOf(
        WakeReason.Adopted,
        WakeReason.MailArrived("a message the header must not quote"),
        WakeReason.TimerFired("announce-retry:n:1"),
        WakeReason.PodCompleted("pod-z1"),
        WakeReason.PodDisposed("pod-z1", "wall-clock-kill"),
        WakeReason.GateReleased(planGate),
      )
      .map { AgentWakeContext(it, gated, gatedHost, JournalState(), emptyList()) } +
      AgentWakeContext(
        WakeReason.Adopted,
        approved,
        HostState(openGates = approved.openGates, releasedDigests = approved.releasedDigests),
        JournalState(),
        emptyList(),
      )
  }

  @Test
  fun aPodInFlightRendersAsBefore() {
    // Mail before the drive gives it a second wake while the held planner is still running.
    val dir = tmp.newFolder()
    File(dir, "ticket.txt").writeText("t1\n")
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val cognition = Recording()
    val daemon = daemon(dir, store, cognition, ceremony = false, runner = FakePodRunner(holdCompletions = true))
    daemon.injectMail("a second wake")
    daemon.driveUntilQuiescent()
    store.close()
    scenario("pod-in-flight", cognition.contexts to dir)
  }

  @Test
  fun anExecutorInFlightRendersAsBefore() {
    // The planner completes at once and the executor is held. Once the plan gate is released, mail
    // before the next drive gives it a wake that spawns the executor and a second wake while it runs.
    val dir = tmp.newFolder()
    File(dir, "ticket.txt").writeText("t1\n")
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val cognition = Recording()
    val runner =
      object : PodRunner {
        val now = FakePodRunner()
        val held = FakePodRunner(holdCompletions = true)

        override fun spawn(
          spec: PodSpec,
          taskRef: String,
          workdir: File,
          artifactPath: String,
          onComplete: (PodCompletion) -> Unit,
        ) = (if (taskRef.startsWith("execute:")) held else now).spawn(spec, taskRef, workdir, artifactPath, onComplete)
      }
    val daemon = daemon(dir, store, cognition, ceremony = false, runner = runner)
    val gate = daemon.driveUntilQuiescent().lead.pendingGates.single()
    AuthStub.appendRelease(store, gate.gateId, gate.payloadDigest)
    daemon.injectMail("while the executor runs")
    daemon.driveUntilQuiescent()
    store.close()
    scenario("execute-in-flight", cognition.contexts to dir)
  }

  /** Drives the walk: drive, release the plan gate, drive, release the commit gate, drive. A mail
   * before each release gives a wake that sees the gate open and not yet approved. Returns every
   * context the daemon decided on, and the run's directory. */
  private fun walk(ceremony: Boolean): Pair<List<AgentWakeContext<LeadState>>, File> {
    val dir = tmp.newFolder()
    File(dir, "ticket.txt").writeText("t1\n")
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val cognition = Recording()
    val daemon = daemon(dir, store, cognition, ceremony)
    repeat(MAX_DRIVES) {
      val lead = daemon.driveUntilQuiescent().lead
      if ("t1" in lead.doneTickets) {
        store.close()
        return cognition.contexts to dir
      }
      val gate = lead.pendingGates.firstOrNull() ?: return@repeat
      daemon.injectMail("waiting on ${gate.gateId}")
      daemon.driveUntilQuiescent()
      if (ceremony) store.approveAndRelease(lead.openNonceFor(gate) ?: error("no open nonce for ${gate.gateId}"))
      else AuthStub.appendRelease(store, gate.gateId, gate.payloadDigest)
    }
    store.close()
    fail("the walk did not reach done in $MAX_DRIVES drives")
    error("unreachable")
  }

  private fun daemon(
    dir: File,
    store: SqliteStore,
    cognition: AgentCognition<LeadState>,
    ceremony: Boolean,
    runner: PodRunner = FakePodRunner(),
  ) =
    ticketLead(
      store = store,
      cognition = cognition,
      podRunner = runner,
      podSpec = PodSpec.fixture(),
      ticketSource = FileTicketSource(File(dir, "ticket.txt")),
      workdir = dir,
      effects = EffectReceiver(dir.absolutePath),
      leadAuth = if (ceremony) ceremonyAuth() else LeadAuth.DENY_ALL,
      timers = if (ceremony) TimerService { _, _ -> } else TimerService.NOOP,
    )

  /** The renders, one block per wake, with run-specific values renamed. */
  private fun renders(run: Pair<List<String>, File>): String {
    val (renders, dir) = run
    val counts = mutableMapOf<String, Int>()
    val renames = mutableMapOf<String, String>()
    fun rename(text: String): String {
      var t = text.replace(dir.canonicalPath, "<DIR>").replace(dir.absolutePath, "<DIR>")
      for ((pattern, kind) in VOLATILE) {
        t = pattern.replace(t) { m -> renames.getOrPut(m.value) { "$kind#${counts.merge(kind, 1, Int::plus)}" } }
      }
      return t
    }
    return renders.withIndex().joinToString("") { (i, r) -> "=== wake ${i + 1} ===\n${rename(r)}" }
  }

  /** The golden directory in runfiles: the directory of `system-prompt.txt`, whose runfiles path
   * prompt_golden_test supplies as GOLDEN_PROMPT. */
  private val goldenDir: File by lazy {
    val srcdir = System.getenv("TEST_SRCDIR") ?: error("TEST_SRCDIR not set (not under bazel test)")
    val rloc =
      System.getenv("GOLDEN_PROMPT") ?: error("GOLDEN_PROMPT not set (prompt_golden_test supplies it via rlocationpath)")
    val prompt = File(srcdir, rloc)
    check(prompt.exists()) { "system-prompt.txt not found in runfiles at $prompt" }
    prompt.parentFile
  }

  /** Compares [actual] with the golden [name]. [wire] names the strategy whose wire [actual] was
   * read from, which only changes the file the actual text is written to on a mismatch. */
  private fun check(name: String, actual: String, wire: String? = null) {
    val golden = File(goldenDir, "$name.txt").takeIf { it.exists() }?.readText()
    if (golden == actual) return
    val out = if (wire == null) "$name.txt" else "$name.$wire-wire.txt"
    System.getenv("TEST_UNDECLARED_OUTPUTS_DIR")?.let { File(it, out).writeText(actual) }
    fail(
      if (golden == null) "$name: no golden file; the actual text is in the undeclared outputs as $out"
      else "${wire?.let { "$it wire: " } ?: ""}$name: differs from its golden; the actual text is in the undeclared outputs as $out"
    )
  }

  private companion object {
    const val MAX_DRIVES = 12

    /** A result envelope in the shape the Claude harness reads, proposing nothing. */
    val CLAUDE_SUCCESS =
      """{"type":"result","subtype":"success","is_error":false,""" +
        """"result":"{\"proposals\": [], \"reasoning\": \"waiting\"}",""" +
        """"session_id":"s-1","num_turns":1,"total_cost_usd":0.01}"""

    val VOLATILE =
      listOf(
        Regex("fake-session-[0-9a-f-]{36}") to "session",
        Regex("pod-[0-9a-f]{8}") to "pod",
      )
  }
}
