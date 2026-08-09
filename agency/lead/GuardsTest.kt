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
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
        cognitionRetryBackoffMs = 0, // no wall-clock wait in tests; the CAP is the property
        maxCognitionAttempts = maxAttempts,
      )
  }

  /** Reads the attempt number as a NUMBER: a substring match on `"attempt":1` also matches
   * `"attempt":10`, which a higher cap would silently make reachable. */
  private fun attemptOf(payloadJson: String): Int =
    Regex("\"attempt\":(\\d+)").find(payloadJson)!!.groupValues[1].toInt()

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
    assertTrue(folded.lead.escalations.any { it.contains("gate-open rejected") })
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
    assertTrue("a real plan sha was recorded", folded.lead.planArtifactSha != null)
    assertTrue("no gate should have opened on the wrong digest", folded.lead.openGates.isEmpty())
    assertTrue(folded.lead.escalations.any { it.contains("gate-open rejected") })
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
    assertTrue(folded.lead.escalations.any { it.contains("pod-spawn rejected") })
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
    fun daemon(cognition: CognitionStrategy, runner: PodRunner) =
      LeadDaemon(
        store = store,
        cognition = cognition,
        podRunner = runner,
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
      )
    val honest = daemon(ScriptedCognition(), FakePodRunner())
    val f1 = honest.driveUntilQuiescent() // planner ran, plan gate open
    honest.injectAuthRelease(gateIdFor(GateKinds.PLAN_APPROVAL, "t1"), f1.lead.planArtifactSha!!)
    val f2 = honest.driveUntilQuiescent() // executor ran, manifest recorded, commit gate open
    assertTrue("positive control: the manifest is recorded", f2.lead.commitManifestDigest != null)

    val hostileRunner = FakePodRunner()
    val hostile =
      daemon(
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
      )
    val folded = daemon.driveUntilQuiescent()
    // The plan was recorded on the RECOMPUTED digest, not the lie, and the mismatch is visible.
    val realDigest = sha256Hex("real plan content\n")
    assertEquals(realDigest, folded.lead.planArtifactSha)
    assertTrue(folded.lead.escalations.any { it.contains("digest mismatch") })
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
            Proposal.ProposePodSpawn("plan:other"),
            Proposal.ProposePodSpawn("execute:other"),
            Proposal.ProposePodSpawn("research:t1"),
          ),
          "hostile: fan out spawns across a task namespace",
        )
      )
    val rig = Rig(dir, script) // current ticket is t1
    val folded = rig.daemon.driveUntilQuiescent()
    assertTrue("nothing launched", rig.runner.spawnedTaskRefs.isEmpty())
    assertTrue(folded.lead.escalations.any { it.contains("pod-spawn rejected") })
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
    assertTrue(folded.lead.escalations.any { it.contains("ticket claim rejected") })
    rig.store.close()
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
