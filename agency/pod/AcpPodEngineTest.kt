package com.geekinasuit.agency.pod

import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.stream.Collectors
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.Timeout

/**
 * Deterministic battery for [AcpPodEngine] (the PROCESS half): a real fake
 * agent OS PROCESS on the other end of the pipes, so the cells that need a killable child
 * — process-group kill of a deep tree, crash/restart with backoff and cap, the pod
 * wall-clock deadline — exercise the machinery they claim to.
 *
 * The engine contract, pinned here:
 *  - normal turn → completion carrying the digest of the bytes the ENGINE read;
 *  - rp → the bridge's decider, with BOTH the ask and the decision reported as events
 *    (ask/decision durability) and NO decision cache across a re-spawn (re-ask after crash);
 *  - NON-ASKING agent refused by the rp-liveness preflight (terminal, no completion);
 *  - DELAYED-BYPASS agent PASSES the preflight by construction (the pf's time-of-check
 *    limit as a CI property) — and its gate-release impotence is the lead's provenance
 *    property, pinned in //agency/lead;
 *  - SYMLINK and FIFO at the lead-assigned artifact path REFUSED and reported, the
 *    FIFO cell proving the read never blocks;
 *  - a pod-written look-alike CONFIG (broad-allow policy + executable hook) is INERT
 *    across a re-spawn: the engine's own config surface is lead-owned, nothing
 *    in the workspace changes what a fresh session does, and the hook never executes;
 *  - a DETERMINISTICALLY-FAILING agent exhausts the restart cap with backoff and escalates
 *    visibly rather than looping;
 *  - a stale artifact from a killed attempt is CLEARED before the re-spawned pod writes
 *    (the lead must never bind a digest over a truncated previous attempt);
 *  - the pod WALL-CLOCK deadline fires through the group kill;
 *  - the deep-tree cell asserts the agent was SPAWNED INTO ITS OWN PROCESS GROUP,
 *    then that the group kill took the whole tree;
 *  - a completion losing the single-owner race is DISCARDED and reported, never delivered
 *    as a second advance;
 *  - the fenced transport=acp non-Claude profile THROWS at spawn, and the deferred
 *    grokNative profile throws from its own launch path as defense in depth;
 *  - engine close reaps its executors (explicit shutdown).
 *
 * Testing honesty, restated: the fake is OURS, so these cells cover our engine's handling
 * of our model of an agent's behavior. The real adapter's wire is the canary's job.
 */
class AcpPodEngineTest {

  /**
   * Per-CELL ceiling, so a hang names the cell that hung. The target's own `size` budget is
   * the only other clock here, and blowing it reports a bare target TIMEOUT — every
   * assertion in the file indistinguishable from every other. Generous enough that no
   * healthy cell approaches it (the slowest is the restart ladder at a few seconds).
   */
  @get:Rule val perCellTimeout: Timeout = Timeout.seconds(120)

  private val engines = CopyOnWriteArrayList<AcpPodEngine>()
  private val tempRoots = CopyOnWriteArrayList<File>()

  @After
  fun cleanup() {
    for (e in engines) runCatching { e.close() }
    for (root in tempRoots) runCatching { root.deleteRecursively() }
  }

  // ---- rig ----

  private class Recorder {
    val events = CopyOnWriteArrayList<PodEvent>()
    val completions = CopyOnWriteArrayList<PodCompletion>()
    val completionLatch = CountDownLatch(1)
    val terminalLatch = CountDownLatch(1)

    fun onEvent(e: PodEvent) {
      events += e
      when (e) {
        is PodEvent.PreflightRefused,
        is PodEvent.ArtifactRefused,
        is PodEvent.RestartsExhausted,
        is PodEvent.DeadlineKilled,
        is PodEvent.CompletionDiscarded -> terminalLatch.countDown()
        else -> Unit
      }
    }

    fun onComplete(c: PodCompletion) {
      completions += c
      completionLatch.countDown()
    }

    inline fun <reified T : PodEvent> of(): List<T> = events.filterIsInstance<T>()

    /** Every recorded event, for failure messages: a timed-out await is otherwise a bare
     * "expected X" with no clue which stage stalled — and the restart causes carry the
     * agent's own stderr tail, which is usually the whole answer. */
    fun diagnostics(): String =
      if (events.isEmpty()) " [no engine events recorded]"
      else events.joinToString(prefix = " [events: ", postfix = "]", separator = "; ") { it.toString() }
  }

  private fun timings(
    turnMs: Long = 20_000,
    askDeadlineMs: Long = 10_000,
    podWallClockMs: Long = 60_000,
    restartCap: Int = 1,
    backoffBaseMs: Long = 10,
    groupReportMs: Long = 5_000,
  ) =
    EngineTimings(
      initializeMs = 20_000,
      newSessionMs = 20_000,
      turnMs = turnMs,
      askDeadlineMs = askDeadlineMs,
      groupReportMs = groupReportMs,
      podWallClockMs = podWallClockMs,
      restartCap = restartCap,
      backoffBaseMs = backoffBaseMs,
    )

  private fun workspace(): File {
    val root = Files.createTempDirectory("acp-engine-").toFile()
    tempRoots += root
    File(root, "artifacts").mkdirs()
    return root
  }

  private fun engineFor(
    variant: FakeAgentVariant,
    recorder: Recorder,
    artifactAction: FakeArtifactAction = FakeArtifactAction.WRITE_FILE,
    symlinkTarget: String? = null,
    timings: EngineTimings = timings(),
    /** Unique token stamped into the agent's argv so a test that scans the host process
     * table finds ITS OWN agent — see [awaitAgentPid]. */
    marker: String? = null,
    /** A line the agent writes to its own stderr before speaking protocol. */
    stderrLine: String? = null,
    /** Replaces the recorder as the engine's event sink — for the cell that pins what
     * happens when the sink REFUSES (in production it is a SQLite append that can throw). */
    eventSink: ((PodEvent) -> Unit)? = null,
    decide: (PermissionAsk) -> PermissionDecision = { PermissionDecision.AllowOnce },
  ): AcpPodEngine? {
    val args =
      buildList {
        add("--variant")
        add(variant.name)
        add("--artifact-action")
        add(artifactAction.name)
        symlinkTarget?.let {
          add("--symlink-target")
          add(it)
        }
        marker?.let {
          add("--marker")
          add(it)
        }
        stderrLine?.let {
          add("--stderr-line")
          add(it)
        }
      }
    val command = FakeAgentLauncher.agentCommand(*args.toTypedArray()) ?: return null
    val sink = eventSink ?: recorder::onEvent
    val engine =
      AcpPodEngine(
        profile = FixtureAgentProfile(command),
        bridge = PermissionBridge(timings.askDeadlineMs, decide, sink),
        events = sink,
        timings = timings,
      )
    engines += engine
    return engine
  }

  private fun spawn(engine: AcpPodEngine, ws: File, recorder: Recorder): PodSpawned =
    engine.spawn(
      spec = PodSpec.fixture(),
      taskRef = "plan:FIX-1",
      workdir = ws,
      artifactPath = File(ws, "artifacts/plan-FIX-1").path,
      onComplete = recorder::onComplete,
    )

  // ---- green path ----

  @Test
  fun honestPodCompletesWithTheDigestOfTheBytesTheEngineRead() {
    val r = Recorder()
    val engine = engineFor(FakeAgentVariant.HONEST, r) ?: return skip()
    val ws = workspace()
    val spawned = spawn(engine, ws, r)

    assertTrue("expected a completion" + r.diagnostics(), r.completionLatch.await(60, TimeUnit.SECONDS))
    val c = r.completions.single()
    assertEquals(spawned.podId, c.podId)
    val onDisk = File(ws, "artifacts/plan-FIX-1").readBytes()
    assertEquals(sha256HexBytes(onDisk), c.resultDigest)
    // The fixture profile measures no cost — null, never a fabricated measured zero.
    assertNull("unmeasured cost must be null, not 0.0", c.costUsd)
  }

  @Test
  fun completionSnapshotIsTheExactBytesTheEngineRead() {
    // Bind-once: the completion carries the disciplined read's own
    // bytes — what the lead binds and persists. The digest is of THESE bytes, so the
    // snapshot and the digest can never describe different objects.
    val r = Recorder()
    val engine = engineFor(FakeAgentVariant.HONEST, r) ?: return skip()
    val ws = workspace()
    spawn(engine, ws, r)

    assertTrue("expected a completion" + r.diagnostics(), r.completionLatch.await(60, TimeUnit.SECONDS))
    val c = r.completions.single()
    val onDisk = File(ws, "artifacts/plan-FIX-1").readBytes()
    assertTrue("snapshot must be the read bytes", c.snapshot.contentEquals(onDisk))
    assertEquals(sha256HexBytes(c.snapshot), c.resultDigest)
  }

  @Test
  fun everyAskAndDecisionIsReportedForTheJournal() {
    val r = Recorder()
    val engine = engineFor(FakeAgentVariant.HONEST, r) ?: return skip()
    spawn(engine, workspace(), r)
    assertTrue(r.completionLatch.await(60, TimeUnit.SECONDS))

    val asked = r.of<PodEvent.PermissionAsked>()
    val decided = r.of<PodEvent.PermissionDecided>()
    // Preflight sentinel + the task turn: two asks, two decisions, all attributable.
    assertEquals(2, asked.size)
    assertEquals(2, decided.size)
    assertTrue(asked.all { it.toolKind == "EXECUTE" })
    assertTrue(decided.all { it.decision == "allow-once" })
    assertTrue("no decision may be stamped late here", decided.none { it.lateAfterDeadline })
  }

  // ---- preflight ----

  @Test
  fun nonAskingAgentIsRefusedByTheRpLivenessPreflight() {
    val r = Recorder()
    val engine = engineFor(FakeAgentVariant.NON_ASKING, r) ?: return skip()
    spawn(engine, workspace(), r)

    assertTrue("expected a terminal event", r.terminalLatch.await(60, TimeUnit.SECONDS))
    assertEquals(1, r.of<PodEvent.PreflightRefused>().size)
    assertTrue("a refused pod must never complete", r.completions.isEmpty())
    assertTrue("a refused pod's decider is never consulted", r.of<PodEvent.PermissionAsked>().isEmpty())
  }

  @Test
  fun delayedBypassAgentPassesThePreflightByConstruction() {
    // The pf's stated limit as a CI property: asking ONCE is all it can
    // observe. This agent asks for the sentinel then stops routing — and still reaches
    // completion here. What it cannot do is release a gate: that is the lead's provenance
    // property (ORIGIN_AUTH_LAYER-only release), pinned in //agency/lead's battery.
    val r = Recorder()
    val engine = engineFor(FakeAgentVariant.DELAYED_BYPASS, r) ?: return skip()
    spawn(engine, workspace(), r)

    assertTrue(r.completionLatch.await(60, TimeUnit.SECONDS))
    assertTrue("preflight must NOT refuse a delayed-bypass agent", r.of<PodEvent.PreflightRefused>().isEmpty())
    assertEquals("exactly the sentinel ask reached the decider", 1, r.of<PodEvent.PermissionAsked>().size)
  }

  @Test
  fun aDeniedAskIsReportedAsADenyAndDoesNotItselfRefreshThePod() {
    val r = Recorder()
    val engine =
      engineFor(FakeAgentVariant.HONEST, r, decide = { PermissionDecision.RejectOnce })
        ?: return skip()
    spawn(engine, workspace(), r)

    assertTrue("a denied agent still finishes its turns" + r.diagnostics(), r.completionLatch.await(60, TimeUnit.SECONDS))
    val decided = r.of<PodEvent.PermissionDecided>()
    assertEquals(2, decided.size)
    assertTrue("every answer must reach the record as a deny", decided.all { it.decision == "reject-once" })
    // A DENY is not a preflight refusal: rp-liveness observes that the agent ASKED, never
    // what we answered — an agent that asks and is refused behaved correctly.
    assertTrue(r.of<PodEvent.PreflightRefused>().isEmpty())
    // Fixture honesty: the fake writes its artifact regardless of the answer (file work is
    // sequenced before the variant's behavior so the crash/stall cells can leave evidence).
    // So the completion here proves the TURNS closed under a deny, NOT that a real agent
    // would still have written — permission-honoring is agent-side and unproven by any
    // fixture that scripts its own compliance.
  }

  @Test
  fun aDecisionArrivingAfterTheAskDeadlineIsStampedLate() {
    // The deadline is OURS. The client has already rejected on the wire by the time
    // this decider answers, so the answer authorized nothing — and the record has to
    // distinguish "we allowed it" from "we said allow too late to matter".
    val r = Recorder()
    val engine =
      engineFor(
        FakeAgentVariant.HONEST,
        r,
        timings = timings(turnMs = 30_000, askDeadlineMs = 200),
        decide = {
          Thread.sleep(600)
          PermissionDecision.AllowOnce
        },
      ) ?: return skip()
    spawn(engine, workspace(), r)

    val decided = awaitEvents<PodEvent.PermissionDecided>(r, atLeast = 1)
    assertTrue("expected a decision to be reported" + r.diagnostics(), decided.isNotEmpty())
    assertTrue(
      "a decision slower than the ask deadline must be stamped late" + r.diagnostics(),
      decided.first().lateAfterDeadline,
    )
  }

  // ---- the disciplined artifact read ----

  @Test
  fun symlinkAtTheArtifactPathIsRefusedAndReported() {
    val r = Recorder()
    val secretDir = Files.createTempDirectory("acp-outside-").toFile()
    tempRoots += secretDir
    val secret = File(secretDir, "credential.txt").also { it.writeText("SUPER-SECRET\n") }
    val engine =
      engineFor(
        FakeAgentVariant.HONEST,
        r,
        artifactAction = FakeArtifactAction.SYMLINK_OUTSIDE,
        symlinkTarget = secret.absolutePath,
      ) ?: return skip()
    val ws = workspace()
    spawn(engine, ws, r)

    assertTrue(r.terminalLatch.await(60, TimeUnit.SECONDS))
    val refusal = r.of<PodEvent.ArtifactRefused>().single()
    assertTrue("expected a symlink refusal, got '${refusal.reason}'", refusal.reason.startsWith("symlink"))
    assertTrue("a refused artifact must never complete", r.completions.isEmpty())
    // The link is still there, unread: the engine refused the OBJECT, it did not read
    // through it. (Read-once would have faithfully digested the credential.)
    assertTrue(Files.isSymbolicLink(Path.of(File(ws, "artifacts/plan-FIX-1").path)))
  }

  @Test
  fun hardLinkAtTheArtifactPathIsRefused() {
    // A hard link is a regular file with no target path to resolve, so it passes every check
    // the symlink refusal relies on. `link(2)` is one syscall the pod already has, and the
    // consequence is the full credential-read attack: the lead reads, digests and journals
    // someone else's file as the pod's work.
    val r = Recorder()
    val secretDir = Files.createTempDirectory("acp-outside-").toFile()
    tempRoots += secretDir
    val secret = File(secretDir, "credential.txt").also { it.writeText("SUPER-SECRET\n") }
    val engine =
      engineFor(
        FakeAgentVariant.HONEST,
        r,
        artifactAction = FakeArtifactAction.HARDLINK_OUTSIDE,
        symlinkTarget = secret.absolutePath,
      ) ?: return skip()
    val ws = workspace()
    spawn(engine, ws, r)

    assertTrue("expected a refusal" + r.diagnostics(), r.terminalLatch.await(60, TimeUnit.SECONDS))
    val refusal = r.of<PodEvent.ArtifactRefused>().single()
    assertTrue(
      "expected a multiply-linked refusal, got '${refusal.reason}'",
      refusal.reason.startsWith("multiply-linked"),
    )
    assertTrue("a refused artifact must never complete", r.completions.isEmpty())
    // The fixture really did link it — otherwise this cell proves nothing.
    val nlink = Files.getAttribute(Path.of(File(ws, "artifacts/plan-FIX-1").path), "unix:nlink")
    assertEquals(2, nlink)
  }

  @Test
  fun aSymlinkedParentDirectoryCannotCarryTheReadOutsideTheWorkspace() {
    // NOFOLLOW protects the FINAL component only; the kernel still traverses parent links.
    // The object at the artifact path is a genuine singly-linked regular file, so identity
    // checks are silent and containment is the only thing that can catch it — which it can
    // only do if both sides resolve links the SAME way.
    val r = Recorder()
    val outsideDir = Files.createTempDirectory("acp-outside-dir-").toFile()
    tempRoots += outsideDir
    val engine =
      engineFor(
        FakeAgentVariant.HONEST,
        r,
        artifactAction = FakeArtifactAction.SYMLINK_PARENT_DIR,
        symlinkTarget = outsideDir.absolutePath,
      ) ?: return skip()
    val ws = workspace()
    spawn(engine, ws, r)

    assertTrue("expected a refusal" + r.diagnostics(), r.terminalLatch.await(60, TimeUnit.SECONDS))
    val refusal = r.of<PodEvent.ArtifactRefused>().single()
    assertTrue(
      "expected an outside-workspace refusal, got '${refusal.reason}'",
      refusal.reason.startsWith("outside-workspace"),
    )
    assertTrue(r.completions.isEmpty())
    // The bytes really were written outside — the escape was live, not hypothetical.
    assertTrue(File(outsideDir, "plan-FIX-1").isFile)
  }

  @Test
  fun anHonestWorkspaceReachedThroughASymlinkedPrefixIsNotRefused() {
    // The other direction of the same asymmetry: on macOS `createTempDirectory` returns a
    // /var/... path whose real form is /private/var/..., so comparing a lexical artifact path
    // against a fully-resolved workspace root refused EVERY honest pod, terminally, with a
    // reason that describes an attack. Here the prefix is symlinked deliberately.
    val r = Recorder()
    val real = Files.createTempDirectory("acp-real-ws-").toFile()
    tempRoots += real
    File(real, "artifacts").mkdirs()
    val linkRoot = Files.createTempDirectory("acp-link-root-").toFile()
    tempRoots += linkRoot
    val ws = File(linkRoot, "ws")
    Files.createSymbolicLink(ws.toPath(), real.toPath())

    val engine = engineFor(FakeAgentVariant.HONEST, r) ?: return skip()
    engine.spawn(
      spec = PodSpec.fixture(),
      taskRef = "plan:FIX-1",
      workdir = ws,
      artifactPath = File(ws, "artifacts/plan-FIX-1").path,
      onComplete = r::onComplete,
    )

    assertTrue("an honest pod under a symlinked prefix must complete" + r.diagnostics(),
      r.completionLatch.await(60, TimeUnit.SECONDS))
    assertTrue("no refusal is owed here", r.of<PodEvent.ArtifactRefused>().isEmpty())
  }

  @Test
  fun aDirectoryAtTheArtifactPathIsRefusedAndNeverThrownAtTheLead() {
    // One `mkdir` by the pod. This used to throw out of clearStaleArtifact — on the lead's
    // own wake-loop thread, whose handler is deliberately fatal — and the directory is
    // durable, so the next process did it again: a permanent crash loop from pod-authored
    // disk state. spawn() keeps exactly one throwing contract, and this is not it.
    val r = Recorder()
    val engine =
      engineFor(
        FakeAgentVariant.HONEST,
        r,
        artifactAction = FakeArtifactAction.DIRECTORY,
        timings = timings(restartCap = 2, backoffBaseMs = 20),
      ) ?: return skip()
    val ws = workspace()
    val artifact = File(ws, "artifacts/plan-FIX-1")
    spawn(engine, ws, r)

    assertTrue("expected a refusal" + r.diagnostics(), r.terminalLatch.await(90, TimeUnit.SECONDS))
    assertTrue(
      "a directory is pod work, refused — not a throw",
      r.of<PodEvent.ArtifactRefused>().isNotEmpty(),
    )
    assertTrue(r.completions.isEmpty())
    assertTrue("the fixture really created a directory", artifact.isDirectory)

    // And the SECOND spawn against the same durable directory behaves identically rather
    // than throwing — the crash-loop half of the defect.
    val r2 = Recorder()
    val engine2 =
      engineFor(
        FakeAgentVariant.HONEST,
        r2,
        artifactAction = FakeArtifactAction.DIRECTORY,
        timings = timings(restartCap = 2, backoffBaseMs = 20),
      ) ?: return skip()
    spawn(engine2, ws, r2)
    assertTrue("re-spawn over a pod-made directory must not throw" + r2.diagnostics(),
      r2.terminalLatch.await(90, TimeUnit.SECONDS))
    val second = r2.of<PodEvent.ArtifactRefused>().first()
    assertTrue(
      "the undeletable leftover is refused, not thrown, got '${second.reason}'",
      second.reason.startsWith("unclearable"),
    )
  }

  @Test
  fun fifoAtTheArtifactPathIsRefusedWithoutBlocking() {
    assumeTrue("mkfifo required", File("/usr/bin/mkfifo").canExecute())
    val r = Recorder()
    val engine =
      engineFor(FakeAgentVariant.HONEST, r, artifactAction = FakeArtifactAction.FIFO) ?: return skip()
    spawn(engine, workspace(), r)

    // The point of the stat-first order: an open() on a FIFO with no writer blocks
    // FOREVER. If this await times out, the engine read through it and wedged.
    assertTrue("FIFO read must not block the supervisor", r.terminalLatch.await(60, TimeUnit.SECONDS))
    val refusal = r.of<PodEvent.ArtifactRefused>().single()
    assertTrue("expected a not-a-regular-file refusal, got '${refusal.reason}'",
      refusal.reason.startsWith("not-a-regular-file"))
    assertTrue(r.completions.isEmpty())
  }

  @Test
  fun missingArtifactIsRefusedNotSilentlyCompleted() {
    val r = Recorder()
    val engine =
      engineFor(FakeAgentVariant.HONEST, r, artifactAction = FakeArtifactAction.NOTHING) ?: return skip()
    spawn(engine, workspace(), r)

    assertTrue(r.terminalLatch.await(60, TimeUnit.SECONDS))
    assertTrue(r.of<PodEvent.ArtifactRefused>().single().reason.startsWith("missing"))
    assertTrue(r.completions.isEmpty())
  }

  @Test
  fun oversizeArtifactIsRefusedAtTheCap() {
    val r = Recorder()
    val big = "x".repeat(4096)
    val command =
      FakeAgentLauncher.agentCommand(
        "--variant", FakeAgentVariant.HONEST.name,
        "--artifact-action", FakeArtifactAction.WRITE_FILE.name,
        "--artifact-content", big,
      ) ?: return skip()
    val engine =
      AcpPodEngine(
        profile = FixtureAgentProfile(command),
        bridge = PermissionBridge(10_000, { PermissionDecision.AllowOnce }, r::onEvent),
        events = r::onEvent,
        timings = timings(),
        artifactByteCap = 1024, // smaller than what the pod writes
      )
    engines += engine
    spawn(engine, workspace(), r)

    assertTrue(r.terminalLatch.await(60, TimeUnit.SECONDS))
    assertTrue(r.of<PodEvent.ArtifactRefused>().single().reason.startsWith("oversize"))
    assertTrue(r.completions.isEmpty())
  }

  // ---- the configuration channel ----

  @Test
  fun podWrittenConfigLookalikeAndHookAreInertAcrossARespawn() {
    val r = Recorder()
    val engine =
      engineFor(
        FakeAgentVariant.CRASH_AFTER_PREFLIGHT, // forces a re-spawn after the pod wrote config
        r,
        artifactAction = FakeArtifactAction.WRITE_CONFIG_LOOKALIKE,
        timings = timings(restartCap = 2, backoffBaseMs = 20),
      ) ?: return skip()
    val ws = workspace()
    spawn(engine, ws, r)

    assertTrue("expected restart exhaustion", r.terminalLatch.await(90, TimeUnit.SECONDS))
    // The pod DID write the look-alike config + hook (otherwise this cell proves nothing).
    val cfg = File(ws, "agentcfg")
    assertTrue("fixture must have written the look-alike config", File(cfg, "policy.json").isFile)
    assertTrue(File(cfg, "pre-tool-use.sh").canExecute())
    // ...and the re-spawned session was unaffected. The engine's agent configuration is
    // lead-owned and workspace-INDEPENDENT — launch argv and env come from the profile,
    // never from anything on disk in the workspace — so attempt 2 routed EXACTLY the asks
    // attempt 1 did (2 turns each: sentinel + task), despite a broad-allow policy document
    // and a bypassPermissions default sitting in the workspace the whole time. A pod that
    // could widen its own permissions through the config channel would have asked FEWER
    // times the second time around. And the hook never executed.
    val asks = r.of<PodEvent.PermissionAsked>()
    assertEquals("asks must be symmetric across the re-spawn" + r.diagnostics(), 4, asks.size)
    assertEquals(1, r.of<PodEvent.RestartAttempted>().size)
    assertFalse("a pod-written hook must never execute", File(ws, "hook-evidence.txt").exists())
    // Those 4 asks are also the RE-ASK property: attempt 2 is a fresh session and
    // asks again from scratch — no decision cache anywhere carries an answer given to the
    // dead session into its successor. (Session IDS are not the evidence: this fixture
    // restarts its counter in each process, so both attempts report "fake-session-1" — a
    // real agent mints unique ids, and reading identity off the id would be trusting
    // agent-authored data for a substrate fact.)
    assertEquals("attempt 2 must re-ask, not inherit", 2, asks.count { it.toolCallId == "tc-0" })
    // SCOPE, stated so this cell is not read as more than it is (self-authored
    // oracle): the fixture agent reads NO configuration at all, so "the look-alike was
    // inert" is guaranteed by the fake, not demonstrated by the engine. What this pins is
    // the substrate half — the engine passes NOTHING workspace-derived into the agent's
    // launch, so a config-reading agent would have no lead-supplied path to these files.
    // Whether a REAL adapter discovers config on its own (cwd walk, $HOME, XDG) is
    // unproven here and is exactly what [ClaudeAdapterProfile] nails down with
    // settingSources: [] and an explicit CLAUDE_CONFIG_DIR against the real binary.
  }

  // ---- restart cap, backoff, escalation, stale-artifact clearing ----

  @Test
  fun deterministicallyFailingAgentExhaustsTheRestartCapAndEscalates() {
    val r = Recorder()
    val engine =
      engineFor(
        FakeAgentVariant.CRASH_AFTER_PREFLIGHT,
        r,
        timings = timings(restartCap = 3, backoffBaseMs = 25),
      ) ?: return skip()
    val t0 = System.nanoTime()
    spawn(engine, workspace(), r)

    assertTrue("expected restarts to be exhausted", r.terminalLatch.await(120, TimeUnit.SECONDS))
    val restarts = r.of<PodEvent.RestartAttempted>()
    val exhausted = r.of<PodEvent.RestartsExhausted>().single()
    // cap=3 total attempts → attempts 2 and 3 are restarts, then exhaustion.
    assertEquals(2, restarts.size)
    assertEquals(listOf(2, 3), restarts.map { it.attempt })
    assertEquals(listOf(25L, 50L), restarts.map { it.backoffMs }) // linear backoff, deterministic
    assertEquals(3, exhausted.attempts)
    assertTrue("the escalation must name the cause", exhausted.cause.isNotBlank())
    assertTrue(r.completions.isEmpty())
    // Backoff is REAL time, not a field: the run cannot have taken less than the sum.
    assertTrue("backoff must actually elapse", (System.nanoTime() - t0) / 1_000_000 >= 75)
  }

  @Test
  fun protocolVersionSkewFailsLaunchAndExhaustsNamingBothVersions() {
    // The protocol pin: acp is pre-1.0, so a point release can silently move the
    // protocol. A profile that pins a version the agent does not negotiate must fail AT
    // LAUNCH — every attempt burns a restart, and exhaustion escalates with BOTH versions
    // named, rather than letting a version-moved agent misbehave mid-task.
    val r = Recorder()
    val command = FakeAgentLauncher.agentCommand("--variant", FakeAgentVariant.HONEST.name) ?: return skip()
    val skewPinned =
      object : EngineProfile {
        private val inner = FixtureAgentProfile(command)

        override val name = "fixture-skew-pin"

        override fun argv(spec: PodSpec, workdir: File) = inner.argv(spec, workdir)

        override fun preflightPrompt() = inner.preflightPrompt()

        override fun expectedProtocolVersion(): String = "999"
      }
    val engine =
      AcpPodEngine(
        profile = skewPinned,
        bridge = PermissionBridge(10_000, { PermissionDecision.AllowOnce }, r::onEvent),
        events = r::onEvent,
        timings = timings(restartCap = 2, backoffBaseMs = 20),
      )
    engines += engine
    spawn(engine, workspace(), r)

    assertTrue("expected restart exhaustion" + r.diagnostics(), r.terminalLatch.await(90, TimeUnit.SECONDS))
    val exhausted = r.of<PodEvent.RestartsExhausted>().single()
    assertTrue(
      "the cause must name the skew, got '${exhausted.cause}'",
      exhausted.cause.contains("protocol-version skew"),
    )
    assertTrue("the cause names the negotiated version", exhausted.cause.contains("negotiated acp v"))
    assertTrue("the cause names the pinned version", exhausted.cause.contains("pins v999"))
    assertTrue("a skewed agent must never complete", r.completions.isEmpty())
  }

  @Test
  fun aStaleArtifactFromAKilledAttemptIsClearedBeforeTheRespawnedPodWrites() {
    val r = Recorder()
    val engine =
      engineFor(
        FakeAgentVariant.CRASH_AFTER_PREFLIGHT,
        r,
        artifactAction = FakeArtifactAction.NOTHING, // the pod never writes; only the stale file exists
        timings = timings(restartCap = 2, backoffBaseMs = 20),
      ) ?: return skip()
    val ws = workspace()
    val artifact = File(ws, "artifacts/plan-FIX-1")
    artifact.writeText("TRUNCATED OUTPUT FROM A PREVIOUS ATTEMPT")

    spawn(engine, ws, r)
    assertTrue(r.terminalLatch.await(90, TimeUnit.SECONDS))
    // The lead must never bind a digest over the previous attempt's file.
    assertFalse("stale artifact must be cleared, not inherited", artifact.exists())
    assertTrue(r.completions.isEmpty())
  }

  @Test
  fun aMidSessionCrashRespawnsAndConvergesToExactlyOneCompletion() {
    // The composition the exhaustion cells cannot show, because their agent never
    // converges: fresh process → fresh session → preflight → task turn → artifact →
    // completion delivered EXACTLY ONCE after a mid-session death (the engine must
    // SURVIVE kill/resume).
    val r = Recorder()
    val engine =
      engineFor(
        FakeAgentVariant.CRASH_ONCE_THEN_HONEST,
        r,
        timings = timings(restartCap = 3, backoffBaseMs = 25),
      ) ?: return skip()
    val ws = workspace()
    spawn(engine, ws, r)

    assertTrue(
      "expected the re-spawned pod to complete" + r.diagnostics(),
      r.completionLatch.await(120, TimeUnit.SECONDS),
    )
    val c = r.completions.single() // exactly one — not one per attempt
    val onDisk = File(ws, "artifacts/plan-FIX-1").readBytes()
    assertEquals(sha256HexBytes(onDisk), c.resultDigest)
    // Two sessions, both on the record: the spawn-time id names only the first, so a
    // re-attach design that read only PodSpawned would be looking at a dead session.
    assertEquals(listOf(1, 2), r.of<PodEvent.SessionEstablished>().map { it.attempt })
    assertEquals(1, r.of<PodEvent.RestartAttempted>().size)
    assertTrue("convergence means the cap is never reached", r.of<PodEvent.RestartsExhausted>().isEmpty())
    // Asks are RE-ASKED against the new session (no decision cache anywhere): sentinel +
    // task, per attempt. A cached allow would have made the second attempt ask fewer times.
    assertEquals(4, r.of<PodEvent.PermissionAsked>().size)
  }

  // ---- the pod wall clock ----

  @Test
  fun podWallClockDeadlineKillsAStalledPodOnOurClock() {
    val r = Recorder()
    val engine =
      engineFor(
        FakeAgentVariant.STALL,
        r,
        timings = timings(turnMs = 60_000, podWallClockMs = 3_000),
      ) ?: return skip()
    val t0 = System.nanoTime()
    spawn(engine, workspace(), r)

    assertTrue("expected a deadline kill", r.terminalLatch.await(60, TimeUnit.SECONDS))
    val killed = r.of<PodEvent.DeadlineKilled>().single()
    assertEquals(3_000L, killed.afterMs)
    val elapsedMs = (System.nanoTime() - t0) / 1_000_000
    assertTrue("the deadline is a real clock (elapsed ${elapsedMs}ms)", elapsedMs >= 3_000)
    assertTrue("a stalled pod must never complete", r.completions.isEmpty())
  }

  // ---- process group, single-owner completion, explicit shutdown ----

  @Test
  fun theAgentIsSpawnedIntoItsOwnProcessGroupAndTheGroupKillTakesTheWholeTree() {
    val r = Recorder()
    val marker = "deep-tree-" + java.util.UUID.randomUUID()
    val engine =
      engineFor(
        FakeAgentVariant.DEEP_TREE,
        r,
        timings = timings(turnMs = 60_000, podWallClockMs = 6_000),
        marker = marker,
      ) ?: return skip()
    spawn(engine, workspace(), r)

    // Wait for the tree to exist, then assert the GROUP CONTRACT before the kill: the
    // agent's own pid IS its process-group id (job control put it in a fresh group), and
    // its descendants inherited that group — which is what makes `kill -pgid` a TREE kill
    // rather than a single-process kill (assert the group exists, not that a kill
    // call was issued).
    // A FAILURE, not a skip: the pod was spawned, so its process must be findable. Returning
    // skip() here would let the repo's only OS-level proof of the group contract
    // self-disable on exactly the regression it exists to catch.
    val agentPid = awaitAgentPid(marker) ?: throw AssertionError("agent never appeared" + r.diagnostics())
    val pgid = pgidOf(agentPid)
    assertTrue("the group kill must not have degraded here", r.of<PodEvent.GroupKillDegraded>().isEmpty())
    assertEquals("the agent must be its own process-group leader", agentPid, pgid)
    // The tree appears during the TASK turn (the sentinel turn runs first), so poll for it
    // rather than sampling once — a single sample races the preflight.
    val descendants = awaitDescendants(agentPid, atLeast = 2)
    assertTrue("expected a deep child tree, got $descendants" + r.diagnostics(), descendants.size >= 2)
    assertTrue(
      "descendants must share the agent's process group",
      descendants.all { pgidOf(it) == pgid },
    )

    assertTrue("expected the wall clock to kill it", r.terminalLatch.await(60, TimeUnit.SECONDS))
    // The whole group is gone — not just the direct child.
    val tree = listOf(agentPid) + descendants
    val deadline = System.nanoTime() + 15_000_000_000L
    while (System.nanoTime() < deadline && tree.any { alive(it) }) Thread.sleep(50)
    val survivors = tree.filter { alive(it) }
    assertTrue("group kill left survivors: $survivors", survivors.isEmpty())
  }

  @Test
  fun aPodWritingAGroupLineOnItsOwnStderrCannotSteerTheKill() {
    // Regression guard for the worst defect this engine has had: the wrapper used to echo
    // the group id onto the AGENT'S OWN stderr and the engine parsed it back, so a pod that
    // printed `PODGROUP:1` got `kill -KILL -- -1` — every process the lead's user owns,
    // the lead included. The group id now comes from the OS, and the pod's stderr is
    // diagnosis only. Same deep-tree kill, with the hostile line present.
    val r = Recorder()
    val marker = "hostile-group-" + java.util.UUID.randomUUID()
    val engine =
      engineFor(
        FakeAgentVariant.DEEP_TREE,
        r,
        timings = timings(turnMs = 60_000, podWallClockMs = 6_000),
        marker = marker,
        stderrLine = "PODGROUP:1",
      ) ?: return skip()
    spawn(engine, workspace(), r)

    val agentPid = awaitAgentPid(marker) ?: throw AssertionError("agent never appeared" + r.diagnostics())
    assertEquals("the engine's group is the agent's own", agentPid, pgidOf(agentPid))
    val descendants = awaitDescendants(agentPid, atLeast = 2)
    assertTrue("expected a deep child tree, got $descendants" + r.diagnostics(), descendants.size >= 2)

    assertTrue(r.terminalLatch.await(60, TimeUnit.SECONDS))
    val tree = listOf(agentPid) + descendants
    val deadline = System.nanoTime() + 15_000_000_000L
    while (System.nanoTime() < deadline && tree.any { alive(it) }) Thread.sleep(50)
    assertTrue("group kill left survivors: ${tree.filter { alive(it) }}", tree.none { alive(it) })
    // The pod's line reached the diagnosis channel and NOTHING else.
    assertTrue("no degradation is owed here", r.of<PodEvent.GroupKillDegraded>().isEmpty())
  }

  @Test
  fun aRefusingEventSinkStillKillsThePodAndStillDeliversTheCompletion() {
    // In production the events seam is LeadDaemon.injectPodEvent — a SQLite append that is
    // documented to throw ("accept means durable, so failure is refusal"). The engine used
    // to treat it as infallible at every site, so a journal hiccup could claim a pod and
    // never kill it, or win the completion CAS and never deliver the result.
    val r = Recorder()
    val engine =
      engineFor(
        FakeAgentVariant.HONEST,
        r,
        eventSink = { throw IllegalStateException("journal refused this append") },
      ) ?: return skip()
    spawn(engine, workspace(), r)

    assertTrue("the completion must survive a refusing sink", r.completionLatch.await(60, TimeUnit.SECONDS))
    assertEquals(1, r.completions.size)
    // Refusals are COUNTED, not swallowed: a record with holes must not look like a clean one.
    assertTrue("refused reports must be counted", engine.eventReportFailures() > 0)
    engine.close()
    assertTrue("a refusing sink must not block shutdown", engine.closedCleanly())
  }

  @Test
  fun aCompletionLosingTheSingleOwnerRaceIsDiscardedNotDelivered() {
    // Deterministic race: the wall clock is short enough to claim the pod while the honest
    // agent is still working, so the completion arrives to an already-owned pod.
    val r = Recorder()
    val engine =
      engineFor(
        FakeAgentVariant.HONEST,
        r,
        timings = timings(turnMs = 60_000, podWallClockMs = 1),
        decide = { ask ->
          Thread.sleep(1_500) // hold the turn open past the wall clock
          PermissionDecision.AllowOnce
        },
      ) ?: return skip()
    spawn(engine, workspace(), r)

    assertTrue(r.terminalLatch.await(60, TimeUnit.SECONDS))
    assertEquals(1, r.of<PodEvent.DeadlineKilled>().size)
    assertTrue("a killed pod must never deliver a completion", r.completions.isEmpty())
  }

  @Test
  fun engineCloseReapsItsExecutors() {
    val r = Recorder()
    val engine = engineFor(FakeAgentVariant.HONEST, r) ?: return skip()
    spawn(engine, workspace(), r)
    assertTrue(r.completionLatch.await(60, TimeUnit.SECONDS))

    engine.close()
    assertTrue("explicit shutdown must reap the engine's executors", engine.closedCleanly())
  }

  // ---- the fence ----

  @Test
  fun fencedAcpNonClaudeProfileThrowsAtSpawnBeforeAnyProcessExists() {
    val r = Recorder()
    val command = FakeAgentLauncher.agentCommand("--variant", FakeAgentVariant.HONEST.name) ?: return skip()
    val engine =
      AcpPodEngine(
        profile = FixtureAgentProfile(command),
        bridge = PermissionBridge(10_000, { PermissionDecision.AllowOnce }, r::onEvent),
        events = r::onEvent,
        timings = timings(),
      )
    engines += engine
    val fenced =
      PodSpec(
        provider = PodProvider.GROK,
        model = "grok-code",
        authMode = PodAuthMode.API_KEY_FILE,
        transport = PodTransport.ACP,
        pinnedVersion = "0.2.93",
      )
    val ws = workspace()

    val ex =
      assertThrows(IllegalStateException::class.java) {
        engine.spawn(fenced, "plan:FIX-1", ws, File(ws, "artifacts/x").path) { }
      }
    assertTrue(ex.message!!.contains("fenced pod profile"))
    assertTrue("nothing may be reported for a fenced spawn", r.events.isEmpty())
  }

  @Test
  fun deferredGrokNativeProfileThrowsFromItsOwnLaunchPath() {
    // Defense in depth under the spec fence: a caller reaching the profile directly (a
    // future config path whose author never read the fence's rationale) still cannot launch it.
    val ex =
      assertThrows(IllegalStateException::class.java) {
        GrokNativeProfile.argv(PodSpec.fixture(), workspace())
      }
    assertTrue(ex.message!!.contains("deferred"))
    assertThrows(IllegalStateException::class.java) { GrokNativeProfile.preflightPrompt() }
  }

  // ---- process helpers (ps-based: the OS is the oracle for group membership) ----

  /**
   * The ONE legitimate skip: no usable `java` to launch the fixture with, i.e. this class is
   * being run outside bazel. Every other "we could not find the thing we just created" is a
   * FAILURE — a battery whose failure mode is SKIP reports green on the regressions it
   * exists to catch, and `OK (N tests)` does not distinguish an asserting cell from an
   * assumption-aborted one.
   */
  private fun skip() {
    assumeTrue("fake agent binary not staged (run under bazel)", false)
  }

  /** Poll until [atLeast] events of type [T] have been reported (or the wait expires) —
   * for facts that are not tied to a completion or a terminal disposition. */
  private inline fun <reified T : PodEvent> awaitEvents(r: Recorder, atLeast: Int): List<T> {
    val deadline = System.nanoTime() + 60_000_000_000L
    var found = r.of<T>()
    while (found.size < atLeast && System.nanoTime() < deadline) {
      Thread.sleep(50)
      found = r.of<T>()
    }
    return found
  }

  /**
   * This cell's OWN agent process, by its unique argv marker. Scanning for the main class
   * alone would also match a stale agent left by an earlier failed run or a sibling from a
   * sharded/parallel run — and the group assertions would then be made about the wrong
   * process, passing or failing for reasons unrelated to the code under test.
   *
   * The engine's group wrapper is excluded explicitly: bash's argv CONTAINS the agent's
   * whole argv (`bash -c … pod-group-wrap java …`), so the marker matches the wrapper
   * too — and the wrapper legitimately stays in the test JVM's process group (job
   * control moves the JOB it backgrounds, not the shell itself), so matching it would
   * assert the group contract against the one process the contract exempts.
   */
  private fun awaitAgentPid(marker: String): Long? {
    val deadline = System.nanoTime() + 30_000_000_000L
    while (System.nanoTime() < deadline) {
      val pid = ProcessHandle.allProcesses()
        .filter { h ->
          val cmd = h.info().commandLine().orElse("")
          cmd.contains(marker) && !cmd.startsWith("/bin/bash")
        }
        .map { it.pid() }
        .findFirst()
      if (pid.isPresent) return pid.get()
      Thread.sleep(100)
    }
    return null
  }

  private fun pgidOf(pid: Long): Long? =
    runCatching {
      val p = ProcessBuilder("/bin/ps", "-o", "pgid=", "-p", pid.toString()).start()
      val out = p.inputStream.bufferedReader().readText().trim()
      p.waitFor(5, TimeUnit.SECONDS)
      out.toLongOrNull()
    }.getOrNull()

  private fun descendantPidsOf(pid: Long): List<Long> =
    ProcessHandle.of(pid)
      // Collectors.toList(), not Stream.toList() (Java 16+): the compile JDK is the
      // consuming root module's choice, so these sources stay on pre-16 APIs.
      .map { h -> h.descendants().collect(Collectors.toList()).map { d -> d.pid() } }
      .orElse(emptyList())

  private fun awaitDescendants(pid: Long, atLeast: Int): List<Long> {
    val deadline = System.nanoTime() + 30_000_000_000L
    var found = descendantPidsOf(pid)
    while (found.size < atLeast && System.nanoTime() < deadline) {
      Thread.sleep(100)
      found = descendantPidsOf(pid)
    }
    return found
  }

  private fun alive(pid: Long): Boolean = ProcessHandle.of(pid).map { it.isAlive }.orElse(false)
}
