package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * How the daemon executes the pod-spawn proposals of a cognition turn that repeat or re-propose a
 * task. A proposal the namespace or plan-approval guard refuses is refused, and escalated, each
 * time it appears, since those guards run before the per-turn de-duplication and the active-pod
 * skip. A task with a pod in flight, and nothing else wrong, gets no second pod and no escalation. A task whose evidence is recorded is refused,
 * and escalated once.
 */
class PodSpawnBatchTest {

  @get:Rule val tmp = TemporaryFolder()

  /** A strategy whose turns are built from the context each wake presents. Idles once its turns
   * run out. */
  private class TurnCognition(
    val turns: MutableList<(AgentWakeContext<LeadState>) -> List<Proposal>>
  ) : AgentCognition<LeadState> {
    override val name = "turns"

    override fun decide(context: AgentWakeContext<LeadState>): CognitionOutput {
      val turn = turns.removeFirstOrNull() ?: return CognitionOutput(presentation = ContextPresentation.PRESENTED)
      return CognitionOutput(turn(context), "turn", presentation = ContextPresentation.PRESENTED)
    }
  }

  private class Run(val store: SqliteStore, val lead: LeadState, val runner: FakePodRunner)

  /** Runs [turns] for ticket t1, one per wake, with pods that complete at once. Each of [drives]
   * adopts afresh, so a later drive's adopt wake runs the next turn. Fails unless
   * every turn ran. */
  private fun run(vararg turns: (AgentWakeContext<LeadState>) -> List<Proposal>, drives: Int = 1): Run {
    val dir = tmp.newFolder()
    File(dir, "ticket.txt").writeText("t1\n")
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val cognition = TurnCognition(turns.toMutableList())
    val runner = FakePodRunner(holdCompletions = false)
    val daemon =
      ticketLead(
        store = store,
        cognition = cognition,
        podRunner = runner,
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        leadAuth = LeadAuth.DENY_ALL,
        timers = TimerService.NOOP,
      )
    var lead = daemon.driveUntilQuiescent().lead
    repeat(drives - 1) { lead = daemon.driveUntilQuiescent().lead }
    assertEquals("turns left unrun", 0, cognition.turns.size)
    return Run(store, lead, runner)
  }

  private fun spawn(taskRef: String) = Proposal.ProposePodSpawn(taskRef)

  @Test
  fun aTaskWithAPodInFlightGetsNoSecondPodAndNoEscalation() {
    // Mail injected before the drive gives it two wakes, so the second turn runs while the held
    // planner the first turn spawned is still in flight. A restart would abandon that pod, so
    // both turns run in one drive.
    val dir = tmp.newFolder()
    File(dir, "ticket.txt").writeText("t1\n")
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val cognition = TurnCognition(mutableListOf({ listOf(spawn("plan:t1")) }, { listOf(spawn("plan:t1")) }))
    val runner = FakePodRunner(holdCompletions = true)
    val daemon =
      ticketLead(
        store = store,
        cognition = cognition,
        podRunner = runner,
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        leadAuth = LeadAuth.DENY_ALL,
        timers = TimerService.NOOP,
      )
    daemon.injectMail("a second wake")
    val lead = daemon.driveUntilQuiescent().lead
    assertEquals("turns left unrun", 0, cognition.turns.size)
    assertEquals(listOf("plan:t1"), runner.spawnedTaskRefs)
    assertEquals(1, lead.activePods.size)
    assertEquals(emptyList<String>(), lead.escalations)
    store.close()
  }

  @Test
  fun anExecutorInFlightIsRefusedOnAPlanGateReOpenedOffItsEvidenceNotSkipped() {
    // The plan-approval guard runs before the active-pod skip: an executor proposed while one is in
    // flight, after the plan gate was re-opened on a digest that is not the recorded plan, is
    // escalated as off its evidence rather than skipped silently. The re-open is a row a journal
    // the lead did not write can hold, appended while the first turn decides.
    val dir = tmp.newFolder()
    File(dir, "ticket.txt").writeText("t1\n")
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    fun daemon(cognition: AgentCognition<LeadState>, runner: FakePodRunner) =
      ticketLead(
        store = store,
        cognition = cognition,
        podRunner = runner,
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        leadAuth = LeadAuth.DENY_ALL,
        timers = TimerService.NOOP,
      )
    val gated = daemon(ScriptedCognition(), FakePodRunner(holdCompletions = false)).driveUntilQuiescent().lead
    assertEquals(TicketPhase.PLAN_GATED, gated.phase)
    val plan = gated.planArtifactSha!!
    val planGate = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    val badDigest = "0".repeat(64)

    val cognition =
      TurnCognition(
        mutableListOf(
          {
            store.append(
              LeadKinds.GATE_OPENED,
              buildJsonObject {
                put("gateId", planGate)
                put("gateKind", GateKinds.PLAN_APPROVAL)
                put("payloadDigest", badDigest)
              },
              ORIGIN_SUBSTRATE,
            )
            listOf(spawn("execute:t1"))
          },
          { listOf(spawn("execute:t1")) },
        )
      )
    val runner = FakePodRunner(holdCompletions = true)
    val hostile = daemon(cognition, runner)
    hostile.injectAuthRelease(planGate, plan) // the first wake: the plan is approved, the executor spawns
    hostile.injectMail("a second wake") // the second: the executor is in flight, the gate re-opened
    val lead = hostile.driveUntilQuiescent().lead
    assertEquals("turns left unrun", 0, cognition.turns.size)
    assertEquals(listOf("execute:t1"), runner.spawnedTaskRefs)
    assertEquals(1, lead.activePods.size)
    assertEquals(
      listOf(
        "pod-spawn rejected: execute pod for 't1' proposed while $planGate is open off its " +
          "evidence: its digest of 64 chars is not the recorded evidence ${plan.take(16)} — no " +
          "approval on that digest lets the executor run"
      ),
      lead.escalations,
    )
    store.close()
  }

  @Test
  fun anExecutorProposedTwiceBeforeThePlanIsApprovedIsRefusedAndEscalatedTwice() {
    val r = run({ listOf(spawn("execute:t1"), spawn("execute:t1")) })
    val refusal =
      "pod-spawn rejected: execute pod for 't1' proposed before the plan-approval gate is " +
        "approved on the recorded plan — the plan must be approved before execution runs"
    assertEquals(emptyList<String>(), r.runner.spawnedTaskRefs)
    assertEquals(listOf(refusal, refusal), r.lead.escalations)
    r.store.close()
  }

  @Test
  fun aTaskOutsideTheTicketsNamespaceProposedTwiceIsRefusedAndEscalatedTwice() {
    val r = run({ listOf(spawn("plan:other"), spawn("plan:other")) })
    val refusal = "pod-spawn rejected: a proposed taskRef of 10 chars is not plan:/execute: for the current ticket 't1'"
    assertEquals(emptyList<String>(), r.runner.spawnedTaskRefs)
    assertEquals(listOf(refusal, refusal), r.lead.escalations)
    r.store.close()
  }

  @Test
  fun aTaskWhoseEvidenceIsRecordedIsRefusedAndEscalatedOnceAcrossTurns() {
    // The planner completes and its plan is recorded; the next turn proposes it twice, and a later
    // drive's turn proposes it again. None gets a pod, and one escalation names the refusal.
    val r =
      run(
        { listOf(spawn("plan:t1")) },
        { listOf(spawn("plan:t1"), spawn("plan:t1")) },
        { listOf(spawn("plan:t1")) },
        drives = 2,
      )
    assertEquals(listOf("plan:t1"), r.runner.spawnedTaskRefs)
    val recorded = r.lead.planArtifactSha!!
    assertEquals(
      listOf(
        "pod-spawn refused for taskRef 'plan:t1': the evidence it exists to produce is already " +
          "recorded (${recorded.take(16)}) — completed work is not re-run, and further redundant " +
          "proposals are refused without a repeat escalation"
      ),
      r.lead.escalations,
    )
    r.store.close()
  }
}
