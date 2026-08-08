package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodCompletion
import com.geekinasuit.agency.pod.PodEvent
import com.geekinasuit.agency.pod.PodSpawned
import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.pod.sha256Hex
import com.geekinasuit.agency.shared.journal.ArmedTimer
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.JournalStore
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Wake-loop tests: the full scripted walk with per-checkpoint state
 * assertions, the idle-blocks guarantee (zero strategy calls while the queue is empty —
 * a model-backed strategy would spend nothing), wake-on-injected-mail, timer re-arm at
 * adopt, and the AGENCY-021 accept-durability cells (an accepted mail or release
 * survives a death before its wake; concurrent accepts never corrupt the chain).
 * Everything here is single-threaded except the idle/wake and concurrent-accept cells,
 * which run the blocking loop on its own thread and observe only the (volatile) call
 * counter until the loop is shut down and joined.
 */
class WakeLoopTest {

  @get:Rule val tmp = TemporaryFolder()

  /** Delegates to [inner], refusing appends whose kind the [refuse] predicate matches —
   * the accept convention's failure mode (append throws) made deterministic per kind. */
  private class RefusingStore(private val inner: JournalStore) : JournalStore by inner {
    @Volatile var refuse: (kind: String) -> Boolean = { false }

    override fun append(
      kind: String,
      payload: JsonObject,
      origin: String,
      idempotencyKey: String?,
    ): JournalEntry {
      if (refuse(kind)) throw RuntimeException("store refused append of kind '$kind' (test fault)")
      return inner.append(kind, payload, origin, idempotencyKey)
    }
  }

  private class Rig(dir: File, hold: Boolean = false, ticket: String? = "t1") {
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val effects = EffectReceiver(dir.absolutePath)
    val runner = FakePodRunner(holdCompletions = hold)
    val counting = CountingCognition(ScriptedCognition())
    val ticketFile = File(dir, "ticket.txt").also { if (ticket != null) it.writeText(ticket + "\n") }
    val armed = mutableListOf<String>()
    val daemon =
      LeadDaemon(
        store = store,
        cognition = counting,
        podRunner = runner,
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(ticketFile),
        workdir = dir,
        effects = effects,
        timers = { t, _ -> armed += t.id },
      )
  }

  @Test
  fun scriptedWalkReachesEveryStateWithAssertionsPerCheckpoint() {
    val dir = tmp.newFolder()
    val rig = Rig(dir)

    // Checkpoint 1: adopt + first wake → claim, planner pod, plan recorded, plan gate open.
    val f1 = rig.daemon.driveUntilQuiescent()
    assertEquals("t1", f1.lead.currentTicket)
    assertEquals(TicketPhase.PLAN_GATED, f1.lead.phase)
    assertTrue(f1.lead.planArtifactSha != null)
    val planGateId = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    assertEquals(listOf(planGateId), f1.lead.pendingGates.map { it.gateId })
    assertEquals(f1.lead.planArtifactSha, f1.lead.pendingGates.single().payloadDigest)
    assertTrue(f1.lead.statusTail.isNotEmpty())
    assertTrue(File(f1.lead.planArtifactPath!!).exists()) // pod wrote at the lead-assigned path

    // Cognition decisions are journaled with cognition provenance before execution.
    val cogEntries = rig.store.readAll().filter { it.kind == LeadKinds.COGNITION_PROPOSED }
    assertTrue(cogEntries.isNotEmpty())
    assertTrue(cogEntries.all { it.origin == ORIGIN_COGNITION })

    // Profile provenance: every spawn record carries WHAT launched —
    // append-only means this could never be backfilled once profile switching exists.
    val spawnedEntry = rig.store.readAll().first { it.kind == LeadKinds.POD_SPAWNED }
    assertTrue(spawnedEntry.payloadJson.contains("\"provider\":\"CLAUDE\""))
    assertTrue(spawnedEntry.payloadJson.contains("\"pinnedVersion\":\"fixture\""))

    // Checkpoint 2: in-process authorization (the AuthRelease wake path) → execute pod
    // runs, manifest proposed, commit gate opens.
    rig.daemon.injectAuthRelease(planGateId, f1.lead.planArtifactSha!!)
    val f2 = rig.daemon.driveUntilQuiescent()
    assertEquals(TicketPhase.COMMIT_GATED, f2.lead.phase)
    assertTrue(f2.lead.commitManifestDigest != null)
    val commitGateId = gateIdFor(GateKinds.COMMIT_APPROVAL, "t1")
    assertEquals(listOf(commitGateId), f2.lead.pendingGates.map { it.gateId })

    // Checkpoint 3: store-level authorization (the AuthStub surface, daemon not looping)
    // → commit effect fires exactly once, ticket completes, lead returns to idle.
    AuthStub.appendRelease(rig.store, commitGateId, f2.lead.commitManifestDigest!!)
    val f3 = rig.daemon.driveUntilQuiescent()
    assertEquals(TicketPhase.IDLE, f3.lead.phase)
    assertEquals(listOf("t1"), f3.lead.doneTickets)
    assertEquals(1, rig.effects.lineCountFor("apply-commit:t1"))
    assertTrue(f3.shared.pendingEffectKeys.isEmpty())
    // TICKET_DONE clears ticket-scoped gate state — no cross-ticket
    // residue. The releases themselves are proven by the pipeline reaching done: the commit
    // effect fires only on a released commit gate, which opens only after the plan gate
    // released.
    assertTrue("done clears ticket-scoped gate state", f3.lead.releasedGates.isEmpty())

    // Quiescent again: the done ticket is not re-claimed.
    val f4 = rig.daemon.driveUntilQuiescent()
    assertEquals(TicketPhase.IDLE, f4.lead.phase)
    assertEquals(listOf("t1"), f4.lead.doneTickets)
    rig.store.close()
  }

  @Test
  fun idleBlocksWithZeroStrategyCallsAndWakesOnInjectedMail() {
    val dir = tmp.newFolder()
    val rig = Rig(dir, ticket = null) // nothing to do: pure idle
    val thread = Thread { rig.daemon.runLoop() }
    thread.start()

    awaitTrue("adopt wake consulted cognition once") { rig.counting.calls == 1 }
    Thread.sleep(200) // blocked on the queue: no polling, no strategy calls, no model spend
    assertEquals(1, rig.counting.calls)

    rig.daemon.injectMail("wake up")
    awaitTrue("mail injection woke the loop") { rig.counting.calls == 2 }

    rig.daemon.shutdown()
    thread.join(5_000)
    assertTrue(!thread.isAlive)

    // Post-join (loop thread done): the mail was journaled and marked delivered.
    val folded = rig.daemon.refold()
    assertEquals(1, folded.shared.mailboxAppended.size)
    assertTrue(folded.shared.undeliveredMail.isEmpty())
    rig.store.close()
  }

  @Test
  fun acceptedMailSurvivesADeathBeforeItsWake() {
    val dir = tmp.newFolder()
    val a = Rig(dir, ticket = null)
    // Accept only — the entry is durable when injectMail returns (journal-then-doorbell,
    // AGENCY-021). The daemon never runs, so the doorbell dies with the "process";
    // pre-fix, the message itself died here too, with no trace anything was dropped.
    a.daemon.injectMail("survives the crash")
    a.store.close()

    val b = Rig(dir, ticket = null)
    val folded = b.daemon.driveUntilQuiescent()
    assertEquals(1, folded.shared.mailboxAppended.size)
    assertTrue("the adopt wake swept the accepted mail", folded.shared.undeliveredMail.isEmpty())
    // Recovery is the Adopted wake alone — no token survives, and the fact is not
    // re-journaled when the pipeline sees it.
    assertEquals(1, b.counting.calls)
    assertEquals(1, b.store.readAll().count { it.kind == "mailbox-appended" })
    b.store.close()
  }

  @Test
  fun acceptedReleaseSurvivesADeathBeforeItsWake() {
    val dir = tmp.newFolder()
    val a = Rig(dir)
    val f1 = a.daemon.driveUntilQuiescent()
    assertEquals(TicketPhase.PLAN_GATED, f1.lead.phase)
    val planGateId = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    // Accept the approval, then die before any wake processes it. Pre-fix this approval
    // lived only in process memory and vanished silently (the KDoc'd durability caveat
    // this cell retires).
    a.daemon.injectAuthRelease(planGateId, f1.lead.planArtifactSha!!)
    a.store.close()

    val b = Rig(dir)
    val f2 = b.daemon.driveUntilQuiescent()
    assertTrue("the accepted release is honored after adopt", planGateId in f2.lead.releasedGates)
    assertEquals(TicketPhase.COMMIT_GATED, f2.lead.phase) // pipeline advanced through it
    assertEquals(1, b.store.readAll().count { it.kind == KIND_GATE_RELEASED })
    b.store.close()
  }

  @Test
  fun podEngineAsksAndDecisionsAreJournaledAtAcceptAsSubstrateFacts() {
    val dir = tmp.newFolder()
    val rig = Rig(dir, ticket = null)
    rig.daemon.injectPodEvent(
      PodEvent.PermissionAsked("pod-1", "sess-1", "tc-0", "write artifact", "EXECUTE")
    )
    rig.daemon.injectPodEvent(
      PodEvent.PermissionDecided("pod-1", "sess-1", "tc-0", "allow-once", 12, lateAfterDeadline = false)
    )

    val rows = rig.store.readAll().filter { it.kind == LeadKinds.POD_EVENT }
    assertEquals(2, rows.size)
    // OUR observation of an untrusted process — never the pod's own claim about itself.
    assertTrue("pod events are substrate-authored", rows.all { it.origin == ORIGIN_SUBSTRATE })
    assertTrue(rows[0].payloadJson.contains("permission-asked"))
    assertTrue(rows[1].payloadJson.contains("allow-once"))
    assertTrue("the late/honored distinction must be on the record", rows[1].payloadJson.contains("lateAfterDeadline"))
    // Durability is the point: an approval that lived only in a callback is
    // invisible to the fold — it can be neither audited nor re-driven.
    assertTrue("a pod event never advances the pipeline", rig.counting.calls == 0)
    assertEquals(0, rig.store.readAll().count { it.kind == LeadKinds.ESCALATED })
    rig.store.close()
  }

  @Test
  fun terminalPodEngineEventsEscalateAndSurviveADeathBeforeAnyWake() {
    val dir = tmp.newFolder()
    val a = Rig(dir, ticket = null)
    // Accept-boundary append (journal-then-return, AGENCY-021): the refusal is durable
    // when injectPodEvent returns, on the ENGINE's supervisor thread, with no loop running.
    a.daemon.injectPodEvent(
      PodEvent.ArtifactRefused("pod-1", "/ws/artifacts/plan-t1", "symlink: the pod does not choose the inode")
    )
    a.daemon.injectPodEvent(PodEvent.RestartsExhausted("pod-2", 3, "attempt 3: transport closed"))
    a.store.close()

    val b = Rig(dir, ticket = null)
    val rows = b.store.readAll()
    assertEquals(2, rows.count { it.kind == LeadKinds.POD_EVENT })
    // Terminal dispositions are legible WITHOUT reading pod-event rows (the refusal is
    // journaled, not merely refused).
    val escalations = rows.filter { it.kind == LeadKinds.ESCALATED }
    assertEquals(2, escalations.size)
    assertTrue(escalations[0].payloadJson.contains("artifact refused"))
    assertTrue(escalations[1].payloadJson.contains("exhausted its restart cap"))
    b.store.close()
  }

  @Test
  fun podEventFreeTextIsBoundedSoAnUntrustedPodCannotGrowTheJournal() {
    val dir = tmp.newFolder()
    val rig = Rig(dir, ticket = null)
    // Restart causes carry the pod's OWN stderr tail. The engine bounds it, but the journal
    // must not depend on an upstream bound: this is the same append-only chain a cognition
    // proposal is bounded against, re-folded into memory on every adopt, forever.
    rig.daemon.injectPodEvent(PodEvent.RestartsExhausted("pod-1", 3, "x".repeat(50_000)))

    val row = rig.store.readAll().single { it.kind == LeadKinds.POD_EVENT }
    assertTrue(
      "untrusted cause must be bounded (was ${row.payloadJson.length} chars)",
      row.payloadJson.length < 6_000,
    )
    rig.store.close()
  }

  @Test
  fun acceptDoesNotFalselyRefuseOnAPreInterruptedCaller() {
    val dir = tmp.newFolder()
    val rig = Rig(dir, ticket = null)
    // A caller thread arriving with its interrupt flag set must not be REFUSED after the
    // append committed (queue.put would throw here; offer does not) — a false refusal of
    // a durably-accepted event invites a retry duplicate.
    Thread.currentThread().interrupt()
    try {
      rig.daemon.injectMail("accepted despite interrupt flag")
    } finally {
      Thread.interrupted() // clear the flag regardless, so later cells are unaffected
    }
    assertEquals(1, rig.store.readAll().count { it.kind == "mailbox-appended" })
    val folded = rig.daemon.driveUntilQuiescent()
    assertTrue(folded.shared.undeliveredMail.isEmpty())
    rig.store.close()
  }

  @Test
  fun oversizeMailIsRefusedAtAcceptWithNothingJournaled() {
    val dir = tmp.newFolder()
    val rig = Rig(dir, ticket = null)
    val oversize = "x".repeat(64_001) // one past MAX_ACCEPTED_MAIL_CHARS
    try {
      rig.daemon.injectMail(oversize)
      throw AssertionError("oversize mail was accepted")
    } catch (expected: IllegalArgumentException) {
      // refused whole — thrown to the caller, never truncated
    }
    assertEquals(0, rig.store.readAll().count { it.kind == "mailbox-appended" })
    rig.store.close()
  }

  @Test
  fun concurrentMailAcceptsKeepTheChainIntactAndLoseNothing() {
    val dir = tmp.newFolder()
    val rig = Rig(dir, ticket = null)
    val loop = Thread { rig.daemon.runLoop() }
    loop.start()
    awaitTrue("adopt wake consulted cognition") { rig.counting.calls >= 1 }

    // Four accept threads race each other AND the loop thread's own appends: seq
    // assignment + prevHash linkage must serialize (the store's internal lock), or
    // readAll() below throws ChainBrokenException.
    val injectors =
      (1..4).map { t -> Thread { for (i in 1..25) rig.daemon.injectMail("mail t$t-$i") } }
    injectors.forEach { it.start() }
    injectors.forEach { it.join(10_000) }
    rig.daemon.shutdown()
    loop.join(10_000)
    assertTrue(!loop.isAlive)

    val entries = rig.store.readAll() // verifies the hash chain end to end
    assertEquals(100, entries.count { it.kind == "mailbox-appended" })
    val folded = rig.daemon.refold()
    assertEquals(100, folded.shared.mailboxAppended.size)
    assertEquals(100, folded.shared.mailboxAppended.values.toSet().size) // distinct: none lost, none duplicated
    assertTrue("every accepted mail was delivered", folded.shared.undeliveredMail.isEmpty())
    rig.store.close()
  }

  @Test
  fun adoptReArmsPendingTimersAndFiresThemOnce() {
    val dir = tmp.newFolder()
    val seed = SqliteStore(dir.absolutePath, componentId = "lead")
    seed.append(
      "timer-armed",
      buildJsonObject {
        put("id", "t-timer")
        put("fireAtEpochMs", 1L)
        put("action", "noop")
      },
      origin = ORIGIN_SUBSTRATE,
    )
    seed.close()

    val rig = Rig(dir, ticket = null)
    rig.daemon.driveUntilQuiescent()
    assertEquals(listOf("t-timer"), rig.armed) // adopt re-armed it from the fold

    rig.daemon.injectTimerDue("t-timer")
    val folded = rig.daemon.driveUntilQuiescent()
    assertTrue("t-timer" in folded.shared.firedTimers)

    // A duplicate due signal does not double-journal the fire.
    rig.daemon.injectTimerDue("t-timer")
    val again = rig.daemon.driveUntilQuiescent()
    assertEquals(1, rig.store.readAll().count { it.kind == "timer-fired" })
    assertTrue("t-timer" in again.shared.firedTimers)
    rig.store.close()
  }

  @Test
  fun heldPodStaysActiveAndAdoptAbandonsThenReSpawns() {
    val dir = tmp.newFolder()
    val rig = Rig(dir, hold = true)
    val f1 = rig.daemon.driveUntilQuiescent()
    assertEquals(TicketPhase.PLANNING, f1.lead.phase)
    assertEquals(1, f1.lead.activePods.size) // planner outstanding, completion parked

    // A fresh drive adopts: the in-flight pod is abandoned visibly and re-proposed
    // (re-spawn, not resume); this rig's runner still holds, so it is active again.
    val f2 = rig.daemon.driveUntilQuiescent()
    assertEquals(1, f2.lead.activePods.size)
    assertTrue(f2.lead.pods.values.any { it.abandonedReason == "lead-restart" })
    assertEquals(2, rig.runner.spawnedTaskRefs.size)
    rig.store.close()
  }

  @Test
  fun runnerHealthFaultsAreDrainedAndEscalatedOnceAtTheNextWake() {
    val dir = tmp.newFolder()
    // AGENCY-028: the engine COUNTS reports its event sink refused;
    // a counter nobody reads is silence with extra steps. The daemon must DRAIN the
    // runner's health surface at every wake and escalate each fault exactly once — the
    // idle adopt wake alone suffices, and an empty drain appends nothing.
    val faulty =
      object : PodRunner {
        private var drained = false

        override fun spawn(
          spec: PodSpec,
          taskRef: String,
          workdir: File,
          artifactPath: String,
          onComplete: (PodCompletion) -> Unit,
        ): PodSpawned = throw AssertionError("this cell never spawns")

        override fun drainHealthFaults(): List<String> =
          if (drained) emptyList()
          else {
            drained = true
            listOf("pod-event reports refused: 2 events missing from the journal (AGENCY-028)")
          }
      }
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val daemon =
      LeadDaemon(
        store = store,
        cognition = ScriptedCognition(),
        podRunner = faulty,
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")), // absent: pure idle
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
      )
    val folded = daemon.driveUntilQuiescent()
    assertTrue(
      "the runner's fault reached the journal",
      folded.lead.escalations.any { it.contains("AGENCY-028") },
    )
    assertEquals(1, store.readAll().count { it.kind == LeadKinds.ESCALATED })

    // Idempotent-when-empty: a later wake drains nothing and re-escalates nothing.
    daemon.injectMail("wake again")
    daemon.driveUntilQuiescent()
    assertEquals(1, store.readAll().count { it.kind == LeadKinds.ESCALATED })
    store.close()
  }

  @Test
  fun terminalEngineDispositionAbandonsTheActivePodAndTheSameLoopReProposes() {
    val dir = tmp.newFolder()
    // The terminal-disposition reaction seam: a terminal engine disposition means the pod is DEAD with no
    // completion ever coming. The adopt-only shape waited for the next adopt — a wedge for the
    // daemon's whole lifetime. The doorbell must abandon the corpse on the loop thread and
    // the evidence-based playbook re-proposes in the same running process.
    val rig = Rig(dir, hold = true)
    val loop = Thread { rig.daemon.runLoop() }
    loop.start()
    awaitTrue("planner pod spawned") {
      rig.store.readAll().any { it.kind == LeadKinds.POD_SPAWNED }
    }
    val podId = rig.daemon.refold().lead.activePods.single().podId

    rig.daemon.injectPodEvent(PodEvent.RestartsExhausted(podId, 2, "attempt 2: transport closed"))
    awaitTrue("the corpse was abandoned and the playbook re-proposed") {
      rig.store.readAll().count { it.kind == LeadKinds.POD_SPAWNED } == 2
    }
    rig.daemon.shutdown()
    loop.join(5_000)
    assertTrue(!loop.isAlive)

    val folded = rig.daemon.refold()
    assertEquals(
      "the abandon carries the engine's own disposition",
      "engine-terminal: restarts-exhausted",
      folded.lead.pods[podId]?.abandonedReason,
    )
    assertTrue(folded.lead.escalations.any { it.contains("exhausted its restart cap") })
    assertEquals(1, folded.lead.activePods.size) // the respawn (held again) is the only live pod
    rig.store.close()
  }

  @Test
  fun podDisposedReactionSurvivesARefusedEscalationAppend() {
    val dir = tmp.newFolder()
    // The POD_EVENT row alone is the durable fact journal-then-doorbell requires; the
    // escalation row beside it is legibility. When the store refuses THAT second append
    // (accept convention: the failure throws to the reporting caller), the terminal
    // reaction must still fire — otherwise the pod degrades to a corpse-until-adopt for
    // the daemon's lifetime even though the disposition IS on the record.
    val sqlite = SqliteStore(dir.absolutePath, componentId = "lead")
    val store = RefusingStore(sqlite)
    val runner = FakePodRunner(holdCompletions = true)
    File(dir, "ticket.txt").writeText("t1\n")
    val daemon =
      LeadDaemon(
        store = store,
        cognition = ScriptedCognition(),
        podRunner = runner,
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
      )
    val loop = Thread { daemon.runLoop() }
    loop.start()
    awaitTrue("planner pod spawned") {
      sqlite.readAll().any { it.kind == LeadKinds.POD_SPAWNED }
    }
    val podId = daemon.refold().lead.activePods.single().podId

    store.refuse = { it == LeadKinds.ESCALATED }
    try {
      daemon.injectPodEvent(PodEvent.RestartsExhausted(podId, 2, "attempt 2: transport closed"))
      throw AssertionError("the refused escalation append must throw to the caller")
    } catch (expected: RuntimeException) {
      // accept means durable, so failure is refusal — thrown to the reporting engine,
      // which defends the seam and counts it (drainHealthFaults's job, not this cell's)
    }
    store.refuse = { false }

    awaitTrue("the corpse was abandoned and re-proposed despite the refused escalation") {
      sqlite.readAll().count { it.kind == LeadKinds.POD_SPAWNED } == 2
    }
    daemon.shutdown()
    loop.join(5_000)
    assertTrue(!loop.isAlive)
    val folded = daemon.refold()
    assertEquals("engine-terminal: restarts-exhausted", folded.lead.pods[podId]?.abandonedReason)
    assertTrue(
      "the refused escalation never reached the journal",
      folded.lead.escalations.none { it.contains("exhausted its restart cap") },
    )
    sqlite.close()
  }

  @Test
  fun boundWriteFailuresCapReProposalsAtThreeAttemptsWithNoResultRecorded() {
    val dir = tmp.newFolder()
    // The livelock guard, unit-shaped (the kill-recovery mirror lives in
    // LeadScenarioTest): a plain FILE where the bound store's directory must go makes
    // every bound write fail — a PERSISTENT fault. Each completion fail-closes (no result
    // row), abandons, and re-proposes; without the process-scoped cap that loop never
    // drains. The cap must end it at 3 attempts with a visible refusal.
    assertTrue(File(dir, "artifacts-bound").createNewFile())
    val rig = Rig(dir)
    val folded = rig.daemon.driveUntilQuiescent()
    assertEquals(3, rig.runner.spawnedTaskRefs.size)
    assertEquals(0, rig.store.readAll().count { it.kind == LeadKinds.POD_RESULT_RECORDED })
    assertTrue(
      "the refusal names the cap",
      folded.lead.escalations.any { it.contains("cap 3") },
    )
    assertEquals(TicketPhase.PLANNING, folded.lead.phase) // wedged VISIBLY, never advanced
    assertTrue("no live pod remains", folded.lead.activePods.isEmpty())

    // Later proposing wakes replay the refusal, not the escalation row: the wedge is
    // announced once per taskRef per process, and the journal does not accrete an
    // identical row per wake for as long as the daemon lives.
    rig.daemon.injectMail("wake again")
    rig.daemon.driveUntilQuiescent()
    assertEquals(
      1,
      rig.store.readAll().count {
        it.kind == LeadKinds.ESCALATED && it.payloadJson.contains("cap 3")
      },
    )
    rig.store.close()
  }

  @Test
  fun aThrowingWakeHandlerIsJournaledBeforeTheLoopStops() {
    val dir = tmp.newFolder()
    // A pod launcher that throws mid-spawn kills the wake handler. The production loop must
    // record the fault (never die silently) and then stop for a
    // supervisor to restart; adopt() on the next process reclaims the orphaned spawn intent
    // (already covered by the adopt tests). Here we assert the visibility half: the fault
    // lands in the journal, and the loop terminates rather than hanging or hot-looping.
    val boom =
      object : PodRunner {
        override fun spawn(
          spec: PodSpec,
          taskRef: String,
          workdir: File,
          artifactPath: String,
          onComplete: (PodCompletion) -> Unit,
        ): PodSpawned = throw RuntimeException("pod launcher blew up")
      }
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    File(dir, "ticket.txt").writeText("t1\n")
    val daemon =
      LeadDaemon(
        store = store,
        cognition = ScriptedCognition(),
        podRunner = boom,
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
      )
    // runLoop adopts → claims t1 → the scripted playbook proposes the planner pod → boom.spawn
    // throws → the loop journals the fault and rethrows, ending the thread.
    val thrown = java.util.concurrent.atomic.AtomicReference<Throwable?>(null)
    val loop = Thread { try { daemon.runLoop() } catch (t: Throwable) { thrown.set(t) } }
    loop.start()
    loop.join(5_000)
    assertTrue("the loop terminated rather than hanging", !loop.isAlive)
    val escalations = store.readAll().filter { it.kind == LeadKinds.ESCALATED }
    assertTrue(
      "the wake fault is journaled before the loop stops",
      escalations.any {
        it.payloadJson.contains("wake-fault") && it.payloadJson.contains("pod launcher blew up")
      },
    )
    assertTrue(
      "the original fault propagated out of the loop",
      thrown.get()?.message?.contains("pod launcher blew up") == true,
    )
    store.close()
  }

  @Test
  fun unmeasuredPodCostJournalsAsAbsentAndFoldsAsNullNotZero() {
    val dir = tmp.newFolder()
    // A pod whose transport surfaces no cost measurement: the completion carries
    // costUsd = null (null-not-zero — unmeasured must stay distinguishable from a
    // measured $0). The journal entry omits the field entirely, the fold reads it back as
    // null, and the pipeline still advances on the result.
    val uncosted =
      object : PodRunner {
        override fun spawn(
          spec: PodSpec,
          taskRef: String,
          workdir: File,
          artifactPath: String,
          onComplete: (PodCompletion) -> Unit,
        ): PodSpawned {
          val content = "plan without a cost\n"
          File(artifactPath).also { it.parentFile?.mkdirs() }.writeText(content)
          onComplete(
            PodCompletion("pod-nc", artifactPath, sha256Hex(content), null, content.toByteArray())
          )
          return PodSpawned("pod-nc", "sess-nc")
        }
      }
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    File(dir, "ticket.txt").writeText("t1\n")
    val daemon =
      LeadDaemon(
        store = store,
        cognition = ScriptedCognition(),
        podRunner = uncosted,
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
      )
    val folded = daemon.driveUntilQuiescent()
    val result = store.readAll().first { it.kind == LeadKinds.POD_RESULT_RECORDED }
    assertTrue(
      "unmeasured cost is journaled as ABSENT, never a fabricated 0.0",
      !result.payloadJson.contains("costUsd"),
    )
    assertEquals(null, folded.lead.podFor("plan:t1")!!.costUsd)
    assertTrue("the pipeline advanced on the uncosted result", folded.lead.planArtifactSha != null)
    store.close()
  }

  @Test
  fun nonFiniteRunnerCostIsJournaledAsUnmeasuredAndEscalatedNeverAsMalformedJson() {
    val dir = tmp.newFolder()
    // A runner reporting NaN (reachable because the engine parses costs out of adapter
    // output): journaling it raw would commit a literal NaN token — MALFORMED JSON —
    // irrevocably to the append-only chain, and the fold's toDouble would then read it
    // back silently. The daemon must journal the result as UNMEASURED (field
    // absent), surface the rejection visibly, and the pipeline must still advance.
    val nanCost =
      object : PodRunner {
        override fun spawn(
          spec: PodSpec,
          taskRef: String,
          workdir: File,
          artifactPath: String,
          onComplete: (PodCompletion) -> Unit,
        ): PodSpawned {
          val content = "plan with a garbage cost\n"
          File(artifactPath).also { it.parentFile?.mkdirs() }.writeText(content)
          onComplete(
            PodCompletion(
              "pod-nan",
              artifactPath,
              sha256Hex(content),
              Double.NaN,
              content.toByteArray(),
            )
          )
          return PodSpawned("pod-nan", "sess-nan")
        }
      }
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    File(dir, "ticket.txt").writeText("t1\n")
    val daemon =
      LeadDaemon(
        store = store,
        cognition = ScriptedCognition(),
        podRunner = nanCost,
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
      )
    val folded = daemon.driveUntilQuiescent()
    val result = store.readAll().first { it.kind == LeadKinds.POD_RESULT_RECORDED }
    assertTrue("the garbage cost never reaches the chain", !result.payloadJson.contains("costUsd"))
    assertTrue(folded.lead.escalations.any { it.contains("costUsd rejected") })
    assertEquals(null, folded.lead.podFor("plan:t1")!!.costUsd)
    assertTrue("the pipeline advanced on the result", folded.lead.planArtifactSha != null)
    store.close()
  }

  private fun awaitTrue(what: String, timeoutMs: Long = 5_000, cond: () -> Boolean) {
    val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
      if (cond()) return
      Thread.sleep(10)
    }
    throw AssertionError("timed out waiting for: $what")
  }
}
