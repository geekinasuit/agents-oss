package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodAuthMode
import com.geekinasuit.agency.pod.PodCompletion
import com.geekinasuit.agency.pod.PodProvider
import com.geekinasuit.agency.pod.PodSpawned
import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.pod.PodTransport
import com.geekinasuit.agency.pod.sha256Hex
import com.geekinasuit.agency.pod.sha256HexBytes
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.JournalState
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The untrusted-cognition boundary: the
 * substrate treats a cognition strategy's output as UNTRUSTED input, not commands. These
 * cells drive a programmable [ProgrammedCognition] emitting exactly what a prompt-injected
 * or buggy model would, and assert the substrate holds the line — deterministic, no-model
 * coverage of the boundary the scripted walk (honest by construction) cannot exercise.
 */
class GuardsTest {

  @get:Rule val tmp = TemporaryFolder()

  /** Emits a scripted queue of outputs, one per wake, then idles. Records the spend total
   * visible in each call's context — a real strategy reads that to enforce its budget cap —
   * and the mail each call was offered, which is how a turn's view of the work queue is
   * observable from outside the daemon. */
  private class ProgrammedCognition(private val script: MutableList<CognitionOutput>) :
    CognitionStrategy {
    override val name = "programmed"
    val spendSeen = mutableListOf<Double>()
    val mailSeen = mutableListOf<List<String>>()

    override fun decide(context: WakeContext): CognitionOutput {
      spendSeen += context.lead.cognitionSpendUsd
      mailSeen += context.undeliveredMail.map { it.second }
      return if (script.isEmpty()) CognitionOutput.IDLE else script.removeAt(0)
    }
  }

  private class Rig(
    dir: File,
    script: MutableList<CognitionOutput>,
    ticket: String? = "t1",
    hold: Boolean = true,
    spec: PodSpec = PodSpec.fixture(),
    maxAttempts: Int = 2,
  ) {
    val cognition = ProgrammedCognition(script)
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val runner = FakePodRunner(holdCompletions = hold)
    val ticketFile = File(dir, "ticket.txt").also { if (ticket != null) it.writeText(ticket + "\n") }
    val daemon =
      LeadDaemon(
        store = store,
        cognition = cognition,
        podRunner = runner,
        podSpec = spec,
        ticketSource = FileTicketSource(ticketFile),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        leadAuth = LeadAuth.DENY_ALL, // guard mechanics; releases are nonce-less
        timers = TimerService.NOOP,
        cognitionRetryBackoffMs = 0, // no wall-clock wait in tests; the CAP is the property
        maxCognitionAttempts = maxAttempts,
      )
  }

  /** Reads the attempt number as a NUMBER: a substring match on `"attempt":1` also matches
   * `"attempt":10`, which a higher cap would silently make reachable. */
  private fun attemptOf(payloadJson: String): Int =
    Regex("\"attempt\":(\\d+)").find(payloadJson)!!.groupValues[1].toInt()

  /** A daemon on [store] for the ticket in [dir]'s ticket.txt, under [auth]: DENY_ALL, where a
   * release needs no nonce, unless a cell needs a ceremony. The cells that hand one journal to
   * several daemons, each with its own cognition and runner, build them with this. Its timers fire
   * nothing, and are not [TimerService.NOOP], which a daemon under a ceremony auth refuses. */
  private fun leadDaemon(
    dir: File,
    store: SqliteStore,
    cognition: CognitionStrategy,
    runner: PodRunner,
    auth: LeadAuth = LeadAuth.DENY_ALL,
    faults: FaultInjector = FaultInjector.NONE,
  ) =
    LeadDaemon(
      store = store,
      cognition = cognition,
      podRunner = runner,
      podSpec = PodSpec.fixture(),
      ticketSource = FileTicketSource(File(dir, "ticket.txt")),
      workdir = dir,
      effects = EffectReceiver(dir.absolutePath),
      leadAuth = auth,
      timers = TimerService { _, _ -> },
      faults = faults,
    )

  /** A gate-open row with the substrate's origin, as a journal the lead did not write can hold. */
  private fun SqliteStore.gateOpened(gateId: String, gateKind: String, payloadDigest: String) =
    append(
      LeadKinds.GATE_OPENED,
      buildJsonObject {
        put("gateId", gateId)
        put("gateKind", gateKind)
        put("payloadDigest", payloadDigest)
      },
      ORIGIN_SUBSTRATE,
    )

  @Test
  fun gateOpenWithNoSubstrateEvidenceIsRejectedAndEscalated() {
    val dir = tmp.newFolder()
    // No plan artifact has been recorded — the substrate has NO evidence for a
    // plan-approval gate. A hostile open on any digest must be refused, not honored.
    val script =
      mutableListOf(
        CognitionOutput(
          listOf(Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, "deadbeef".repeat(8))),
          "hostile: open a gate on evidence that does not exist",
        )
      )
    val rig = Rig(dir, script)
    val folded = rig.daemon.driveUntilQuiescent()
    assertTrue("no gate should have opened", folded.lead.openGates.isEmpty())
    // The refused digest is the proposal's own text, so the reason gives its length alone.
    assertEquals(
      "gate-open rejected for plan-approval:t1: a proposed digest of 64 chars " +
        "does not match substrate evidence (none recorded)",
      folded.lead.escalations.single { it.startsWith("gate-open rejected") },
    )
    assertTrue(folded.lead.escalations.none { "deadbeef" in it })
    rig.store.close()
  }

  @Test
  fun gateOpenOfAKindThePipelineDoesNotHaveIsRejectedWithoutQuotingIt() {
    val dir = tmp.newFolder()
    // The parser refuses an unknown gate kind, but a strategy can hand the daemon a proposal the
    // parser never saw, as this one does. The kind is the proposal's own text, and a gate id
    // built from it would carry that text into the reason.
    val script =
      mutableListOf(
        CognitionOutput(
          listOf(Proposal.ProposeGateOpen("Qx7-kind", "0".repeat(64))),
          "hostile: open a gate of a kind the pipeline does not have",
        )
      )
    val rig = Rig(dir, script)
    val folded = rig.daemon.driveUntilQuiescent()
    assertTrue("no gate should have opened", folded.lead.openGates.isEmpty())
    assertEquals(
      "gate-open rejected: a proposed gate kind of 8 chars is not one the lead opens",
      folded.lead.escalations.single { it.startsWith("gate-open rejected") },
    )
    assertTrue(folded.lead.escalations.none { "Qx7" in it })
    rig.store.close()
  }

  @Test
  fun gateOpenOnAMismatchedDigestBindsNothingWhenRealEvidenceExists() {
    val dir = tmp.newFolder()
    // Wake 1: spawn a real (non-held) planner → it completes and its plan is recorded.
    // Wake 2 (the PodDone wake): hostile open on a digest ≠ the recorded plan sha.
    val script =
      mutableListOf(
        CognitionOutput(listOf(Proposal.ProposePodSpawn("plan:t1")), "spawn the planner"),
        CognitionOutput(
          listOf(Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, "0".repeat(64))),
          "hostile: bind approval to a digest of my choosing",
        ),
      )
    val rig = Rig(dir, script, hold = false)
    val folded = rig.daemon.driveUntilQuiescent()
    val recorded = folded.lead.planArtifactSha
    assertTrue("a real plan sha was recorded", recorded != null)
    assertTrue("no gate should have opened on the wrong digest", folded.lead.openGates.isEmpty())
    assertEquals(
      "gate-open rejected for plan-approval:t1: a proposed digest of 64 chars " +
        "does not match substrate evidence ${recorded!!.take(16)}",
      folded.lead.escalations.single { it.startsWith("gate-open rejected") },
    )
    assertTrue(folded.lead.escalations.none { "0".repeat(16) in it })
    rig.store.close()
  }

  @Test
  fun podSpawnWithPathTraversalTaskRefIsRejected() {
    val dir = tmp.newFolder()
    val script =
      mutableListOf(
        CognitionOutput(
          listOf(Proposal.ProposePodSpawn("plan:../../../../etc/pwned")),
          "hostile: escape the workspace via the artifact path",
        )
      )
    val rig = Rig(dir, script)
    val folded = rig.daemon.driveUntilQuiescent()
    assertTrue("never launched", rig.runner.spawnedTaskRefs.isEmpty())
    assertEquals(
      "pod-spawn rejected: a proposed taskRef of 26 chars is not plan:/execute: " +
        "for the current ticket 't1'",
      folded.lead.escalations.single { it.startsWith("pod-spawn rejected") },
    )
    assertTrue(folded.lead.escalations.none { "../" in it })
    assertFalse(File("/etc/pwned").exists())
    rig.store.close()
  }

  @Test
  fun duplicateProposalsWithinOneOutputExecuteOnce() {
    val dir = tmp.newFolder()
    val script =
      mutableListOf(
        CognitionOutput(
          listOf(
            Proposal.ProposePodSpawn("plan:t1"),
            Proposal.ProposePodSpawn("plan:t1"), // same batch — the snapshot guard can't see this
          ),
          "buggy: emitted the same spawn twice",
        )
      )
    val rig = Rig(dir, script)
    rig.daemon.driveUntilQuiescent()
    assertEquals(1, rig.runner.spawnedTaskRefs.count { it == "plan:t1" })
    rig.store.close()
  }

  @Test
  fun redundantLegalRespawnAfterEvidenceIsRecordedIsRefusedAndEscalatedOnce() {
    val dir = tmp.newFolder()
    // The success-side livelock shape, which the intra-batch cell above cannot observe:
    // wake 1 spawns a real (non-held) planner, and its completion IS wake 2 — where the
    // plan sha is recorded and the active-pod guard has cleared. A strategy re-proposing
    // the same legal ref there would buy one real pod per wake, self-sustaining through
    // the wait-on-human gate phases; the evidence guard must refuse it, visibly.
    val script =
      mutableListOf(
        CognitionOutput(listOf(Proposal.ProposePodSpawn("plan:t1")), "spawn the planner"),
        CognitionOutput(
          listOf(Proposal.ProposePodSpawn("plan:t1")),
          "buggy/hostile: re-run the planner whose plan is already recorded",
        ),
      )
    val rig = Rig(dir, script, hold = false)
    val folded = rig.daemon.driveUntilQuiescent()
    assertTrue(
      "positive control: the first spawn was legal and its evidence was recorded",
      folded.lead.planArtifactSha != null,
    )
    assertEquals(1, rig.runner.spawnedTaskRefs.count { it == "plan:t1" })
    assertTrue(folded.lead.escalations.any { it.contains("already recorded") })

    // A later wake re-proposing AGAIN is still refused, but the escalation is not
    // repeated: the refusal replays deterministically from folded evidence, and the row
    // announcing the misbehaving strategy is appended once per taskRef per process.
    script +=
      CognitionOutput(
        listOf(Proposal.ProposePodSpawn("plan:t1")),
        "buggy/hostile: still re-proposing the completed planner",
      )
    val again = rig.daemon.driveUntilQuiescent()
    assertTrue("the further re-proposal was actually consumed", script.isEmpty())
    assertEquals(1, rig.runner.spawnedTaskRefs.count { it == "plan:t1" })
    assertEquals(1, again.lead.escalations.count { it.contains("already recorded") })
    rig.store.close()
  }

  @Test
  fun redundantExecuteRespawnAfterManifestIsRecordedIsRefused() {
    val dir = tmp.newFolder()
    // Walk the honest pipeline to a recorded commit manifest — the phase where the plan
    // gate is RELEASED, so the execute-ordering guard alone no longer blocks an execute
    // spawn — then hand the same journal to a daemon whose cognition re-proposes the
    // executor. The manifest evidence must refuse it: no pod, escalated.
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    File(dir, "ticket.txt").writeText("t1\n")
    val honest = leadDaemon(dir, store, ScriptedCognition(), FakePodRunner())
    val f1 = honest.driveUntilQuiescent() // planner ran, plan gate open
    honest.injectAuthRelease(gateIdFor(GateKinds.PLAN_APPROVAL, "t1"), f1.lead.planArtifactSha!!)
    val f2 = honest.driveUntilQuiescent() // executor ran, manifest recorded, commit gate open
    assertTrue("positive control: the manifest is recorded", f2.lead.commitManifestDigest != null)

    val hostileRunner = FakePodRunner()
    val hostile =
      leadDaemon(
        dir,
        store,
        ProgrammedCognition(
          mutableListOf(
            CognitionOutput(
              listOf(Proposal.ProposePodSpawn("execute:t1")),
              "buggy/hostile: re-run the executor whose manifest is already recorded",
            )
          )
        ),
        hostileRunner,
      )
    val f3 = hostile.driveUntilQuiescent()
    assertTrue("nothing launched", hostileRunner.spawnedTaskRefs.isEmpty())
    assertTrue(f3.lead.escalations.any { it.contains("already recorded") })
    store.close()
  }

  @Test
  fun scriptedCognitionDoesNotExecuteOnAPlanReOpenedPastItsApproval() {
    // AGENCY #28: the scripted playbook must ask "is the digest the plan gate is open on
    // NOW approved?", not the epoch-blind "was this gate released at all this ticket?". A
    // gate released on d1 and then re-opened on a NEW digest d2 is a fresh authorization
    // surface that d1's release does not cover, so cognition must NOT treat the plan as
    // approved and spawn the executor. Pure decide() cell: this state is exactly what
    // leadFold yields for GATE_OPENED(d1) -> release(d1) -> GATE_OPENED(d2) (proven in
    // AuthFoldTest), built directly here to isolate the consumer decision.
    val ticket = "t1"
    val planGateId = gateIdFor(GateKinds.PLAN_APPROVAL, ticket)
    val reOpenedPastApproval =
      LeadState(
        currentTicket = ticket,
        planArtifactSha = "d1",
        openGates = mapOf(planGateId to OpenGate(planGateId, GateKinds.PLAN_APPROVAL, "d2", 9L)),
        releasedGates = setOf(planGateId), // epoch-blind: released at all this ticket
        releasedDigests = mapOf(planGateId to setOf("d1")), // but only ON d1, not the open d2
      )
    fun executeProposed(lead: LeadState): Boolean =
      ScriptedCognition()
        .decide(WakeContext(WakeReason.Adopted, lead, JournalState(), emptyList()))
        .proposals
        .any { it is Proposal.ProposePodSpawn && it.taskRef == "execute:$ticket" }

    assertFalse(
      "no executor on a plan re-opened past its approval",
      executeProposed(reOpenedPastApproval),
    )
    // Positive control: approve the CURRENT digest too and the executor IS spawned — so the
    // refusal above is about the epoch, not some unrelated branch, and the fix has not simply
    // wedged the pipeline shut.
    assertTrue(
      "with the current digest approved, the executor is spawned",
      executeProposed(
        reOpenedPastApproval.copy(releasedDigests = mapOf(planGateId to setOf("d1", "d2")))
      ),
    )
  }

  @Test
  fun executeSpawnIsRefusedWhenThePlanGateWasReOpenedPastItsApproval() {
    val dir = tmp.newFolder()
    // AGENCY #28 end to end at the highest-severity consumer: the execute-ordering guard
    // must refuse to LAUNCH the executor when the plan gate is open on an unapproved digest,
    // even when a buggy/prompt-injected cognition forces the spawn. Drive the honest pipeline
    // to a plan gate open on d1, release it nonce-less on d1, then re-open the SAME gate on a
    // new digest d2 — a journal-level surface the daemon's own seen-gate guard will not
    // produce (LeadState.foldRelease KDoc), injected here as the raw event a future re-open
    // path would emit.
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    File(dir, "ticket.txt").writeText("t1\n")
    val honest = leadDaemon(dir, store, ScriptedCognition(), FakePodRunner())
    val f1 = honest.driveUntilQuiescent() // planner ran, plan gate open on d1
    val planGateId = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    honest.injectAuthRelease(planGateId, f1.lead.planArtifactSha!!) // append-only, no drive
    // a new, unapproved authorization surface
    store.gateOpened(planGateId, GateKinds.PLAN_APPROVAL, "d2-reopen")

    val hostileRunner = FakePodRunner()
    val hostile =
      leadDaemon(
        dir,
        store,
        ProgrammedCognition(
          mutableListOf(
            CognitionOutput(
              listOf(Proposal.ProposePodSpawn("execute:t1")),
              "buggy/hostile: launch the executor on a plan re-opened past its approval",
            )
          )
        ),
        hostileRunner,
      )
    val f3 = hostile.driveUntilQuiescent()
    assertTrue("no execute pod launched", hostileRunner.spawnedTaskRefs.isEmpty())
    assertTrue(
      "the execute-ordering guard escalated",
      f3.lead.escalations.any { it.contains("execute") && it.contains("plan") },
    )
    store.close()
  }

  @Test
  fun executeSpawnIsRefusedWhenThePlanGateIsApprovedOnADigestThatIsNotTheRecordedPlan() {
    val dir = tmp.newFolder()
    // The lead opens the plan gate only on the recorded plan's digest, so a plan gate open on any
    // other digest reaches the fold only from a journal the lead did not write. Here that journal
    // re-opens the gate on another digest and releases it there, so the gate is approved on the
    // digest it is open on. That release approves no plan the substrate recorded, so the executor
    // must not launch on it, even when cognition proposes it.
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    File(dir, "ticket.txt").writeText("t1\n")
    val honest = leadDaemon(dir, store, ScriptedCognition(), FakePodRunner())
    honest.driveUntilQuiescent() // planner ran, plan gate open on the recorded plan
    val planGateId = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    val notThePlan = "0".repeat(64)
    store.gateOpened(planGateId, GateKinds.PLAN_APPROVAL, notThePlan)
    honest.injectAuthRelease(planGateId, notThePlan) // append-only, no drive

    val hostileRunner = FakePodRunner()
    val hostile =
      leadDaemon(
        dir,
        store,
        ProgrammedCognition(
          mutableListOf(
            CognitionOutput(
              listOf(Proposal.ProposePodSpawn("execute:t1")),
              "buggy/hostile: launch the executor on a plan gate approved on another digest",
            )
          )
        ),
        hostileRunner,
      )
    val f = hostile.driveUntilQuiescent()
    assertTrue(
      "the plan gate is approved on the digest it is open on",
      f.lead.approvedOnCurrentDigest(planGateId),
    )
    assertTrue(
      "a plan is recorded, and it is not that digest",
      f.lead.planArtifactSha.let { it != null && it != notThePlan },
    )
    assertTrue("no execute pod launched", hostileRunner.spawnedTaskRefs.isEmpty())
    assertTrue(
      "the execute-ordering guard escalated",
      f.lead.escalations.any { it.startsWith("pod-spawn rejected: execute pod for 't1'") },
    )
    store.close()
  }

  @Test
  fun executeSpawnIsRefusedWhileThePlanGateIsOpenOnTheRecordedPlanAndNotReleased() {
    val dir = tmp.newFolder()
    // The spawn check asks two things: that the plan gate is open on the recorded plan, and that a
    // release approved it on that digest. Here only the first holds: the honest walk leaves the
    // plan gate open on the recorded plan, and nothing has released it. The executor must not
    // launch before the plan is approved, even when cognition proposes it.
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    File(dir, "ticket.txt").writeText("t1\n")
    val f1 = leadDaemon(dir, store, ScriptedCognition(), FakePodRunner()).driveUntilQuiescent()
    val planGateId = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")

    val hostileRunner = FakePodRunner()
    val hostile =
      leadDaemon(
        dir,
        store,
        ProgrammedCognition(
          mutableListOf(
            CognitionOutput(
              listOf(Proposal.ProposePodSpawn("execute:t1")),
              "buggy/hostile: launch the executor before the plan is approved",
            )
          )
        ),
        hostileRunner,
      )
    val f = hostile.driveUntilQuiescent()
    assertTrue("positive control: the honest walk recorded a plan", f1.lead.planArtifactSha != null)
    assertEquals(
      "the plan gate is open on the recorded plan",
      f1.lead.planArtifactSha,
      f.lead.openGates[planGateId]?.payloadDigest,
    )
    assertFalse("no release has approved it", f.lead.approvedOnCurrentDigest(planGateId))
    assertTrue("no execute pod launched", hostileRunner.spawnedTaskRefs.isEmpty())
    assertTrue(
      "the execute-ordering guard escalated",
      f.lead.escalations.any { it.startsWith("pod-spawn rejected: execute pod for 't1'") },
    )
    store.close()
  }

  @Test
  fun noCommitIsProposedWhileThePlanGateIsApprovedOnADigestThatIsNotTheRecordedPlan() {
    val dir = tmp.newFolder()
    // Under DENY_ALL a gate is released without a nonce at most once a ticket, so this cell runs
    // under a ceremony auth. The executor runs on the plan approved on its recorded digest, and a
    // crash lands right after its result is recorded, before the pass that proposes its manifest as
    // the commit. A journal the lead did not write then re-opens the plan gate on another digest,
    // with a nonce bound to it, and that nonce is approved and released, so the gate is approved on
    // the digest it is open on, which is not the recorded plan. The restarted lead must not propose
    // the manifest as the commit.
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    File(dir, "ticket.txt").writeText("t1\n")
    val auth = ceremonyAuth()
    val f1 = leadDaemon(dir, store, ScriptedCognition(), FakePodRunner(), auth).driveUntilQuiescent()
    val planGateId = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    store.approveAndRelease(f1.lead.issuedNonces.values.single())
    val crash = FaultInjector {
      if (it == "after-pod-result") throw RuntimeException("crash after the executor's result")
    }
    val d2 = leadDaemon(dir, store, ScriptedCognition(), FakePodRunner(), auth, crash)
    assertThrows(RuntimeException::class.java) { d2.driveUntilQuiescent() }
    val afterCrash = d2.refold().lead
    assertTrue(
      "the executor's result is recorded",
      afterCrash.podFor("execute:t1")?.resultDigest != null,
    )
    assertEquals("and no commit is proposed yet", null, afterCrash.commitManifestDigest)
    val notThePlan = "0".repeat(64)
    val foreignNonce = "1".repeat(64)
    store.gateOpened(planGateId, GateKinds.PLAN_APPROVAL, notThePlan)
    store.append(
      LeadKinds.NONCE_ISSUED,
      buildJsonObject {
        put("nonce", foreignNonce)
        put("gateId", planGateId)
        put("payloadDigest", notThePlan)
      },
      ORIGIN_SUBSTRATE,
    )
    store.approveAndRelease(planGateId, notThePlan, foreignNonce)

    // The restarted lead's cognition proposes nothing, so only the mechanical pass acts.
    val idle = ProgrammedCognition(mutableListOf())
    val f = leadDaemon(dir, store, idle, FakePodRunner(), auth).driveUntilQuiescent()
    assertEquals("no commit is proposed", null, f.lead.commitManifestDigest)
    assertTrue(
      "the plan gate is approved on the digest it is open on",
      f.lead.approvedOnCurrentDigest(planGateId),
    )
    store.close()
  }

  @Test
  fun theCommitEffectDoesNotFireOnACommitGateApprovedOnADigestThatIsNotTheRecordedManifest() {
    val dir = tmp.newFolder()
    // The lead opens the commit gate only on the recorded manifest's digest. Here a journal the lead
    // did not write opens it first, on another digest, so the lead's own gate-open is skipped: that
    // gate id is already open. A release on that digest approves no manifest the substrate
    // recorded, so the commit effect, which names the recorded manifest, must not fire.
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    File(dir, "ticket.txt").writeText("t1\n")
    val d = leadDaemon(dir, store, ScriptedCognition(), FakePodRunner())
    val f1 = d.driveUntilQuiescent() // planner ran, plan gate open on the recorded plan
    val commitGateId = gateIdFor(GateKinds.COMMIT_APPROVAL, "t1")
    val notTheManifest = "0".repeat(64)
    store.gateOpened(commitGateId, GateKinds.COMMIT_APPROVAL, notTheManifest)
    d.injectAuthRelease(gateIdFor(GateKinds.PLAN_APPROVAL, "t1"), f1.lead.planArtifactSha!!)
    val f2 = d.driveUntilQuiescent() // executor ran, manifest recorded
    assertTrue(
      "a manifest is recorded, and it is not the commit gate's digest",
      f2.lead.commitManifestDigest.let { it != null && it != notTheManifest },
    )
    assertEquals(
      "the commit gate is still open on the digest the journal chose",
      notTheManifest,
      f2.lead.openGates[commitGateId]?.payloadDigest,
    )

    d.injectAuthRelease(commitGateId, notTheManifest)
    val f = d.driveUntilQuiescent()
    assertFalse("no commit intent is journaled", "apply-commit:t1" in f.shared.intents)
    assertEquals(
      "the commit effect did not fire",
      0,
      EffectReceiver(dir.absolutePath).lineCountFor("apply-commit:t1"),
    )
    assertTrue("the ticket is not done", f.lead.doneTickets.isEmpty())
    assertTrue(
      "the commit gate is approved on the digest it is open on",
      f.lead.approvedOnCurrentDigest(commitGateId),
    )
    store.close()
  }

  @Test
  fun podSelfReportingAWrongDigestIsCrossCheckedAndTheRecomputedDigestBinds() {
    val dir = tmp.newFolder()
    // A lying pod: real snapshot bytes, but a self-reported digest that doesn't match
    // them. Bind-once: the lead recomputes from the SNAPSHOT at result-record time,
    // escalates the lie, and binds the recomputed digest — gates open on the bytes as
    // they exist, not as described.
    val lying =
      object : PodRunner {
        override fun spawn(
          spec: PodSpec,
          taskRef: String,
          workdir: File,
          artifactPath: String,
          onComplete: (PodCompletion) -> Unit,
        ): PodSpawned {
          val content = "real plan content\n"
          File(artifactPath).also { it.parentFile?.mkdirs() }.writeText(content)
          onComplete(
            PodCompletion("pod-x", artifactPath, "a-lie".repeat(12), 0.0, content.toByteArray())
          )
          return PodSpawned("pod-x", "sess-x")
        }
      }
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    File(dir, "ticket.txt").writeText("t1\n")
    val daemon =
      LeadDaemon(
        store = store,
        cognition = ScriptedCognition(),
        podRunner = lying,
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        leadAuth = LeadAuth.DENY_ALL, // guard mechanics; releases are nonce-less
        timers = TimerService.NOOP,
      )
    val folded = daemon.driveUntilQuiescent()
    // The plan was recorded on the RECOMPUTED digest, not the lie, and the mismatch is visible.
    val realDigest = sha256Hex("real plan content\n")
    assertEquals(realDigest, folded.lead.planArtifactSha)
    assertEquals(
      "pod-completion digest mismatch for pod 'pod-x': the runner reported a digest of 60 chars, " +
        "and the snapshot hashes to ${realDigest.take(16)} — binding the recomputed digest",
      folded.lead.escalations.single { "digest mismatch" in it },
    )
    assertTrue("the overridden digest is not quoted", folded.lead.escalations.none { "a-lie" in it })
    // And the gate that opened binds to the real digest.
    assertEquals(realDigest, folded.lead.pendingGates.single().payloadDigest)
    store.close()
  }

  @Test
  fun modelIdleTurnWithMetaIsJournaledForCostEvenWithNoProposals() {
    val dir = tmp.newFolder()
    val script =
      mutableListOf(
        CognitionOutput(
          emptyList(),
          "idle but I cost money",
          meta = mapOf("sessionId" to "sess-idle", "costUsd" to "0.02"),
        )
      )
    val rig = Rig(dir, script, ticket = null) // nothing to claim: the wake is pure idle
    val folded = rig.daemon.driveUntilQuiescent()
    val cog = rig.store.readAll().filter { it.kind == LeadKinds.COGNITION_PROPOSED }
    assertEquals(1, cog.size)
    assertEquals(ORIGIN_COGNITION, cog.single().origin)
    assertTrue(cog.single().payloadJson.contains("sess-idle"))
    assertEquals(0.02, folded.lead.cognitionSpendUsd, 1e-9) // spend accrues from the journal
    rig.store.close()
  }

  @Test
  fun malformedTurnIsJournaledDistinctlyRetriedAndNeverExecuted() {
    val dir = tmp.newFolder()
    // Both attempts come back unusable — and each carries a proposal the substrate must NOT
    // act on, because a batch that failed structural validation is untrusted input.
    val junk =
      CognitionOutput(
        listOf(Proposal.ProposeStatus("should never be executed")),
        meta = mapOf("sessionId" to "sess-bad", "costUsd" to "0.01"),
        malformed = "unknown proposal type 'delete-everything'",
      )
    val rig = Rig(dir, mutableListOf(junk, junk.copy()), ticket = null)
    val folded = rig.daemon.driveUntilQuiescent()

    val malformed = rig.store.readAll().filter { it.kind == LeadKinds.COGNITION_MALFORMED }
    assertEquals("the cap bounds attempts per wake", 2, malformed.size)
    // Substrate-authored: this row is OUR classification of what arrived, not a decision.
    assertTrue(malformed.all { it.origin == ORIGIN_SUBSTRATE })
    assertEquals(listOf(1, 2), malformed.map { attemptOf(it.payloadJson) })

    // The retry reads the spend its own predecessor just incurred. Handing it the
    // pre-attempt state would let one wake bill past a strategy's budget cap per attempt.
    assertEquals(0.0, rig.cognition.spendSeen[0], 1e-9)
    assertEquals(0.01, rig.cognition.spendSeen[1], 1e-9)

    // Nothing the malformed batch proposed was executed, and no decision row was written.
    assertTrue(rig.store.readAll().none { it.kind == LeadKinds.COGNITION_PROPOSED })
    assertTrue(folded.lead.statusTail.none { it.contains("should never be executed") })

    // Distinct in the fold — the whole point of the malformed classification. The escalation is the cap being
    // exhausted (one), NOT one per malformed turn: a degrading model must stay countable
    // in malformedCognition rather than drowning the escalation channel.
    assertEquals(2, folded.lead.malformedCognition.size)
    assertTrue(folded.lead.malformedCognition.all { it.second.contains("unknown proposal type") })
    assertEquals(1, folded.lead.escalations.count { it.contains("unusable output") })

    // A billed turn is a billed turn: spend accrues even though nothing was decided.
    assertEquals(0.02, folded.lead.cognitionSpendUsd, 1e-9)
    rig.store.close()
  }

  @Test
  fun aRetryThatParsesIsExecutedNormally() {
    val dir = tmp.newFolder()
    val script =
      mutableListOf(
        CognitionOutput(malformed = "cognition output was not JSON"),
        CognitionOutput(listOf(Proposal.ProposeStatus("recovered")), "second attempt parsed"),
      )
    val rig = Rig(dir, script, ticket = null)
    val folded = rig.daemon.driveUntilQuiescent()

    assertEquals(1, rig.store.readAll().count { it.kind == LeadKinds.COGNITION_MALFORMED })
    assertEquals(1, rig.store.readAll().count { it.kind == LeadKinds.COGNITION_PROPOSED })
    assertTrue(folded.lead.statusTail.contains("recovered"))
    // The failed attempt stays visible; recovering does not erase that the model missed once.
    assertEquals(1, folded.lead.malformedCognition.size)
    assertTrue(folded.lead.escalations.none { it.contains("unusable output") })
    rig.store.close()
  }

  @Test
  fun aProposalFromARetryIsExecutedAgainstTheStateThatRetrySaw() {
    val dir = tmp.newFolder()
    // A retry re-folds, so the decision and the state it is judged against must come from
    // the SAME fold. Ticket-scoped execute checks (ref must equal the claimed ticket) are
    // only reachable with a real ticket, which is what makes the pairing observable here:
    // executing against a fold the winning attempt never saw would fail the ref check and
    // the spawn would be refused rather than launched.
    val script =
      mutableListOf(
        CognitionOutput(malformed = "cognition output was not JSON"),
        CognitionOutput(listOf(Proposal.ProposePodSpawn("plan:t1")), "second attempt parsed"),
      )
    val rig = Rig(dir, script, ticket = "t1", hold = false)
    val folded = rig.daemon.driveUntilQuiescent()

    assertTrue("the retry's spawn must reach the runner", "plan:t1" in rig.runner.spawnedTaskRefs)
    assertTrue(folded.lead.escalations.none { it.contains("pod-spawn rejected") })
    assertEquals(1, folded.lead.malformedCognition.size)
    rig.store.close()
  }

  @Test
  fun malformedRowMetaCannotOverwriteTheSubstratesOwnAccount() {
    val dir = tmp.newFolder()
    // Provenance meta shares a namespace with our classification in the journaled row. A
    // colliding key must lose: the row is the substrate saying what it saw.
    val junk =
      CognitionOutput(
        meta = mapOf("reason" to "I decided to escalate", "attempt" to "99", "strategy" to "other"),
        malformed = "cognition output was not JSON",
      )
    val rig = Rig(dir, mutableListOf(junk), ticket = null, maxAttempts = 1)
    rig.daemon.driveUntilQuiescent()

    val row = rig.store.readAll().single { it.kind == LeadKinds.COGNITION_MALFORMED }
    assertTrue(row.payloadJson.contains("cognition output was not JSON"))
    assertFalse(row.payloadJson.contains("I decided to escalate"))
    assertEquals(1, attemptOf(row.payloadJson))
    rig.store.close()
  }

  @Test
  fun proposedRowMetaCannotOverwriteTheSubstratesOwnAccount() {
    val dir = tmp.newFolder()
    // COGNITION_PROPOSED is a cognition-origin row, but its top-level strategy / reasoning /
    // proposals are still the substrate's structured account of the turn. A strategy's free-form
    // meta must not be able to redefine them by colliding on a key.
    val junk =
      CognitionOutput(
        listOf(Proposal.ProposeStatus("real work")),
        "the substrate's own reasoning record",
        meta = mapOf("strategy" to "spoofed", "reasoning" to "spoofed provenance"),
      )
    val rig = Rig(dir, mutableListOf(junk), ticket = null)
    rig.daemon.driveUntilQuiescent()

    val row = rig.store.readAll().single { it.kind == LeadKinds.COGNITION_PROPOSED }
    assertTrue("substrate strategy name survives", row.payloadJson.contains("programmed"))
    assertTrue(
      "substrate reasoning survives",
      row.payloadJson.contains("the substrate's own reasoning record"),
    )
    assertFalse("colliding meta values are dropped", row.payloadJson.contains("spoofed"))
    rig.store.close()
  }

  @Test
  fun anAttemptCapBelowOneIsRefusedAtConstruction() {
    val dir = tmp.newFolder()
    // Zero would skip cognition entirely and then escalate as though it had asked — a
    // silently model-free daemon reporting a model failure.
    try {
      Rig(dir, mutableListOf(), maxAttempts = 0)
      throw AssertionError("expected construction to fail on a sub-1 attempt cap")
    } catch (e: IllegalArgumentException) {
      assertTrue(e.message!!.contains("maxCognitionAttempts"))
    }
  }

  @Test
  fun anAttemptCapAboveTheCeilingIsRefusedAtConstruction() {
    val dir = tmp.newFolder()
    // Attempts run in series on the loop thread, each costing a whole harness turn plus its
    // backoff, and shutdown is only observed between wakes — so an outsized cap is not a more
    // patient daemon, it is one that stops answering for as long as it takes to give up.
    try {
      Rig(dir, mutableListOf(), maxAttempts = 6)
      throw AssertionError("expected construction to fail on an over-ceiling attempt cap")
    } catch (e: IllegalArgumentException) {
      assertTrue(e.message!!.contains("maxCognitionAttempts"))
    }
  }

  @Test
  fun anExhaustedWakeLeavesItsMailForTheNextTurn() {
    val dir = tmp.newFolder()
    // Mail is the daemon's real work queue, and the delivered set has no inverse: once a seq
    // is marked, `undeliveredMail` never offers it again. An idle turn was SHOWN the mail and
    // chose not to act, so consuming it is right — but an exhausted wake judged nothing, and
    // retiring its mail would discard a work item no turn ever decided about. The mail wake
    // burns both attempts; the turn AFTER it must still be offered "m1".
    val script =
      mutableListOf(
        CognitionOutput(malformed = "cognition output was not JSON"),
        CognitionOutput(malformed = "cognition output was not JSON"),
      )
    val rig = Rig(dir, script, ticket = null)
    rig.daemon.injectMail("m1")
    val folded = rig.daemon.driveUntilQuiescent()

    assertTrue(folded.lead.escalations.any { it.contains("unusable output") })
    assertEquals(2, folded.lead.malformedCognition.size)
    assertTrue(
      "the exhausted wake spent both attempts before any later turn ran",
      rig.cognition.mailSeen.size >= 3,
    )
    assertEquals(
      "the turn after the exhausted wake is still offered the mail nothing ever judged",
      listOf("m1"),
      rig.cognition.mailSeen[2],
    )
    rig.store.close()
  }

  @Test
  fun aStrategyWiredForASingleAttemptIsNotRetried() {
    val dir = tmp.newFolder()
    // Same script as the cell above, cap of 1 instead of 2: the second output is never
    // reached, so the wake escalates where the retrying cap recovered. Whether a resample
    // can help is the strategy's property — a deterministic one pays twice for one answer.
    val script =
      mutableListOf(
        CognitionOutput(malformed = "cognition output was not JSON"),
        CognitionOutput(listOf(Proposal.ProposeStatus("recovered")), "would have been attempt 2"),
      )
    val rig = Rig(dir, script, ticket = null, maxAttempts = 1)
    val folded = rig.daemon.driveUntilQuiescent()

    assertEquals(1, rig.store.readAll().count { it.kind == LeadKinds.COGNITION_MALFORMED })
    assertTrue(folded.lead.escalations.any { it.contains("unusable output") })
    rig.store.close()
  }

  @Test
  fun scriptedIdleTurnIsNotJournaled() {
    val dir = tmp.newFolder()
    val rig = Rig(dir, mutableListOf(), ticket = null) // programmed cognition idles immediately
    rig.daemon.driveUntilQuiescent()
    assertTrue(rig.store.readAll().none { it.kind == LeadKinds.COGNITION_PROPOSED })
    rig.store.close()
  }

  @Test
  fun secondConcurrentRunIsRejectedByTheSingleRunGuard() {
    val dir = tmp.newFolder()
    val rig = Rig(dir, mutableListOf(), ticket = null)
    val started = java.util.concurrent.CountDownLatch(1)
    val loop =
      Thread {
        started.countDown()
        rig.daemon.runLoop()
      }
    loop.start()
    started.await()
    Thread.sleep(150) // let runLoop claim the active flag and block on the queue

    var rejected = false
    try {
      rig.daemon.driveUntilQuiescent()
    } catch (e: IllegalStateException) {
      rejected = e.message?.contains("already running") == true
    }
    rig.daemon.shutdown()
    loop.join(5_000)
    assertTrue("a concurrent run must be structurally rejected", rejected)
    rig.store.close()
  }

  @Test
  fun podSpawnForATaskRefNotBoundToTheCurrentTicketIsRejected() {
    val dir = tmp.newFolder()
    // Well-formed refs (no traversal) but for OTHER tickets / an unknown kind — a hostile
    // model amplifying into many distinct spawns. Only the current ticket's plan/execute are
    // legal, so all are rejected and nothing is launched.
    val script =
      mutableListOf(
        CognitionOutput(
          listOf(
            Proposal.ProposePodSpawn("plan:Qx7"),
            Proposal.ProposePodSpawn("execute:Qx7"),
            Proposal.ProposePodSpawn("research:t1"),
          ),
          "hostile: fan out spawns across a task namespace",
        )
      )
    val rig = Rig(dir, script) // current ticket is t1
    val folded = rig.daemon.driveUntilQuiescent()
    assertTrue("nothing launched", rig.runner.spawnedTaskRefs.isEmpty())
    // Each reason names the refused ref by its length and quotes the ticket the lead claimed.
    assertEquals(
      listOf(8, 11, 11).map {
        "pod-spawn rejected: a proposed taskRef of $it chars is not plan:/execute: " +
          "for the current ticket 't1'"
      },
      folded.lead.escalations.filter { it.startsWith("pod-spawn rejected") },
    )
    assertTrue(folded.lead.escalations.none { "Qx7" in it || "research" in it })
    rig.store.close()
  }

  @Test
  fun artifactDigestBindsRawBytesNotDecodedText() {
    val dir = tmp.newFolder()
    // A pod whose artifact holds NON-UTF8 bytes, self-reporting the RAW-BYTE sha. Had the
    // lead hashed readText() (a UTF-8 decode), the recompute would differ and it would
    // spuriously escalate a mismatch; hashing raw bytes, the recompute
    // matches the pod's report and binds cleanly.
    val rawBytes = byteArrayOf(0xff.toByte(), 0xfe.toByte(), 0x00, 0x01, 'p'.code.toByte())
    val rawSha = sha256HexBytes(rawBytes)
    val binaryPod =
      object : PodRunner {
        override fun spawn(
          spec: PodSpec,
          taskRef: String,
          workdir: File,
          artifactPath: String,
          onComplete: (PodCompletion) -> Unit,
        ): PodSpawned {
          File(artifactPath).also { it.parentFile?.mkdirs() }.writeBytes(rawBytes)
          onComplete(PodCompletion("pod-bin", artifactPath, rawSha, 0.0, rawBytes))
          return PodSpawned("pod-bin", "sess-bin")
        }
      }
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    File(dir, "ticket.txt").writeText("t1\n")
    val daemon =
      LeadDaemon(
        store = store,
        cognition = ScriptedCognition(),
        podRunner = binaryPod,
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        leadAuth = LeadAuth.DENY_ALL, // guard mechanics; releases are nonce-less
        timers = TimerService.NOOP,
      )
    val folded = daemon.driveUntilQuiescent()
    assertEquals("the plan binds the raw-byte digest", rawSha, folded.lead.planArtifactSha)
    assertTrue(
      "no spurious digest mismatch on binary content",
      folded.lead.escalations.none { it.contains("digest mismatch") },
    )
    store.close()
  }

  @Test
  fun executePodProposedBeforePlanApprovalIsRejected() {
    val dir = tmp.newFolder()
    // A hostile/buggy strategy proposes the execute pod on the first wake — before any plan
    // has been approved (indeed before a plan artifact exists). The plan-approval gate must
    // gate execution: the substrate escalates and launches nothing. Without this, cognition
    // could get the executor running on an unapproved plan, and the human gate would gate
    // nothing.
    val script =
      mutableListOf(
        CognitionOutput(
          listOf(Proposal.ProposePodSpawn("execute:t1")),
          "hostile: run the executor before the plan is approved",
        )
      )
    val rig = Rig(dir, script)
    val folded = rig.daemon.driveUntilQuiescent()
    assertTrue("nothing launched before approval", rig.runner.spawnedTaskRefs.isEmpty())
    assertTrue(
      folded.lead.escalations.any {
        it.contains("before the plan-approval") || it.contains("plan must be approved")
      }
    )
    rig.store.close()
  }

  @Test
  fun malformedTicketRefIsRejectedAtClaimAndNotClaimed() {
    val dir = tmp.newFolder()
    // The ticket source offers an untrusted ref that forges the task namespace and traverses
    // a path. The substrate must refuse to claim it (charset), escalate, and stay idle —
    // never let it flow into this ticket's plan:/execute: refs, gate ids, or effect keys.
    val rig = Rig(dir, mutableListOf(), ticket = "plan:../../etc")
    val folded = rig.daemon.driveUntilQuiescent()
    assertEquals(null, folded.lead.currentTicket)
    assertTrue("nothing was claimed", folded.lead.doneTickets.isEmpty())
    assertEquals(
      "ticket claim rejected: an offered ref of 14 chars is malformed (charset/length)",
      folded.lead.escalations.single { it.startsWith("ticket claim rejected") },
    )
    assertTrue(folded.lead.escalations.none { "../" in it })
    rig.store.close()
  }

  @Test
  fun aClaimOfEveryShapeTheClaimAcceptsIsFolded() {
    // The fold refuses a claimed ref the claim would refuse, so the two checks must agree: a fold
    // stricter than the claim would refuse a journal the lead wrote itself, and the lead would not
    // run on it again.
    for (ticket in listOf("Az09._-", "a".repeat(128))) {
      val rig = Rig(tmp.newFolder(), mutableListOf(), ticket = ticket)
      val folded = rig.daemon.driveUntilQuiescent()
      assertEquals("a ref of ${ticket.length} chars is claimed and folded", ticket, folded.lead.currentTicket)
      rig.store.close()
    }
  }

  @Test
  fun oversizedCognitionOutputIsCappedInTheAuditEntry() {
    val dir = tmp.newFolder()
    // A hostile/buggy strategy returns a huge reasoning string, a huge meta value, and far
    // more proposals than a wake executes. The audit entry (origin = cognition) must be
    // bounded exactly as execution is: each string ≤ MAX_JOURNALED_STRING and no more than
    // MAX_PROPOSALS_PER_WAKE proposals recorded — the audit must not journal more than the
    // substrate would act on.
    val huge = "x".repeat(50_000)
    val manyProposals = (1..500).map { Proposal.ProposeStatus("status-$it") }
    val script = mutableListOf(CognitionOutput(manyProposals, huge, meta = mapOf("blob" to huge)))
    val rig = Rig(dir, script, ticket = null) // pure idle wake: nothing to claim
    rig.daemon.driveUntilQuiescent()
    val cog = rig.store.readAll().single { it.kind == LeadKinds.COGNITION_PROPOSED }
    // Raw, this payload would exceed 100k chars (two 50k strings + 500 proposals). Capped, it
    // is a small multiple of the 4000-char bound: reasoning + one meta blob + 16 short props.
    assertTrue(
      "audit payload is bounded, not the raw 100k+ blob (was ${cog.payloadJson.length} chars)",
      cog.payloadJson.length < 20_000,
    )
    rig.store.close()
  }

  @Test
  fun nonFiniteOrNegativeCognitionCostDoesNotCorruptSpend() {
    val dir = tmp.newFolder()
    // Model-supplied cost is untrusted. A NaN would make every budget `spend >= cap` check
    // false (cap never trips → unbounded spend); a negative would understate spend. Both must
    // contribute 0 to the journal-derived total, leaving it finite and non-decreasing — only
    // the one real cost accrues.
    val script =
      mutableListOf(
        CognitionOutput(emptyList(), "nan", meta = mapOf("sessionId" to "s1", "costUsd" to "NaN")),
        CognitionOutput(emptyList(), "neg", meta = mapOf("sessionId" to "s2", "costUsd" to "-9.5")),
        CognitionOutput(emptyList(), "real", meta = mapOf("sessionId" to "s3", "costUsd" to "0.03")),
      )
    val rig = Rig(dir, script, ticket = null)
    // Two pre-injected mails + adopt's own Adopted wake = three idle wakes, consuming the
    // three scripted outputs in FIFO order (mail, mail, then Adopted).
    rig.daemon.injectMail("m1")
    rig.daemon.injectMail("m2")
    val folded = rig.daemon.driveUntilQuiescent()
    assertTrue("spend stays finite", folded.lead.cognitionSpendUsd.isFinite())
    assertEquals(0.03, folded.lead.cognitionSpendUsd, 1e-9)
    rig.store.close()
  }

  @Test
  fun fencedAcpNonClaudeProfileThrowsAtSpawnWithNoSideEffect() {
    val dir = tmp.newFolder()
    // A lead misconfigured with a fenced profile (transport=acp,
    // provider≠claude): the spawn must THROW fail-closed, with NOTHING launched and NOTHING journaled
    // for the spawn — not even the intent record. No egress-enforcement capability exists
    // today (EgressEnforcement is unconstructible), so the throw is unconditional.
    val fenced =
      PodSpec(
        provider = PodProvider.GROK,
        model = "grok-code-1",
        authMode = PodAuthMode.API_KEY_FILE,
        transport = PodTransport.ACP,
        pinnedVersion = "unpinned",
      )
    val script =
      mutableListOf(
        CognitionOutput(listOf(Proposal.ProposePodSpawn("plan:t1")), "spawn via a fenced profile")
      )
    val rig = Rig(dir, script, spec = fenced)
    var thrown = false
    try {
      rig.daemon.driveUntilQuiescent()
    } catch (e: IllegalStateException) {
      thrown = e.message?.contains("fenced pod profile") == true
    }
    assertTrue("the fenced spawn must throw, naming the fence", thrown)
    assertTrue("nothing launched", rig.runner.spawnedTaskRefs.isEmpty())
    assertTrue(
      "fail-closed BEFORE the substrate commits: no spawn intent journaled",
      rig.store.readAll().none { it.kind == LeadKinds.POD_SPAWN_INTENDED },
    )
    rig.store.close()
  }

  @Test
  fun podSpawnsWithTheLeadOwnedSpecNeverACognitionSuppliedOne() {
    val dir = tmp.newFolder()
    // Substrate-constructed provenance: the descriptor is lead-owned config;
    // cognition proposes a TASK. The proposal type carries only a taskRef (compile-time —
    // ProposePodSpawn has no descriptor fields; CognitionParsingTest pins the parse side),
    // and this cell pins the runtime half: what reaches the runner is exactly the spec the
    // substrate was constructed with.
    val script =
      mutableListOf(CognitionOutput(listOf(Proposal.ProposePodSpawn("plan:t1")), "spawn the planner"))
    val rig = Rig(dir, script)
    rig.daemon.driveUntilQuiescent()
    assertEquals(listOf(PodSpec.fixture()), rig.runner.spawnedSpecs)
    rig.store.close()
  }
}
