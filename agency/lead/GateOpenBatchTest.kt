package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.SqliteStore
import com.geekinasuit.agency.shared.journal.payloadObject
import java.io.File
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * How the daemon executes the gate-open proposals of one cognition turn when they repeat a gate:
 * a gate id is acted on at most once per turn, whether the first proposal for it was opened or
 * refused, and a gate already open is never opened again, nor its proposal escalated. Under a
 * ceremony auth, a gate opened once is minted for and announced once.
 */
class GateOpenBatchTest {

  @get:Rule val tmp = TemporaryFolder()

  /** A strategy whose turns are built from the context each wake presents, so a turn can propose
   * the plan digest the substrate recorded on an earlier wake. Idles once its turns run out. */
  private class TurnCognition(
    val turns: MutableList<(AgentWakeContext<LeadState>) -> List<Proposal>>
  ) : AgentCognition<LeadState> {
    override val name = "turns"

    override fun decide(context: AgentWakeContext<LeadState>): CognitionOutput {
      val turn = turns.removeFirstOrNull() ?: return CognitionOutput(presentation = ContextPresentation.PRESENTED)
      return CognitionOutput(turn(context), "turn", presentation = ContextPresentation.PRESENTED)
    }
  }

  private val badDigest = "0".repeat(64)

  private class Run(val store: SqliteStore, val lead: LeadState, val host: HostState)

  /**
   * The first turn spawns ticket t1's planner. The planner completes at once, the mechanical pass
   * records its plan, and [planTurns] run on the wakes that follow, the first of them on the
   * planner's completion. Each of [drives] adopts afresh, so a later drive's adopt wake runs the
   * next turn. Fails unless every turn ran.
   */
  private fun run(
    vararg planTurns: (AgentWakeContext<LeadState>) -> List<Proposal>,
    drives: Int = 1,
    ceremony: Boolean = false,
  ): Run {
    val dir = tmp.newFolder()
    File(dir, "ticket.txt").writeText("t1\n")
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val cognition =
      TurnCognition(
        mutableListOf<(AgentWakeContext<LeadState>) -> List<Proposal>>({
          listOf(Proposal.ProposePodSpawn("plan:t1"))
        })
      )
    cognition.turns += planTurns
    val daemon =
      ticketLead(
        store = store,
        cognition = cognition,
        podRunner = FakePodRunner(holdCompletions = false),
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        leadAuth = if (ceremony) ceremonyAuth() else LeadAuth.DENY_ALL,
        timers = if (ceremony) TimerService { _, _ -> } else TimerService.NOOP,
      )
    var folded = daemon.driveUntilQuiescent()
    repeat(drives - 1) { folded = daemon.driveUntilQuiescent() }
    assertEquals("turns left unrun", 0, cognition.turns.size)
    return Run(store, folded.lead, folded.host)
  }

  private fun plan(ctx: AgentWakeContext<LeadState>): String = ctx.lead.planArtifactSha!!

  private fun count(store: SqliteStore, kind: String): Int = store.readAll().count { it.kind == kind }

  /** Asserts the journal holds exactly one gate-open, of t1's plan gate on the recorded plan. */
  private fun assertPlanGateOpenedOnce(r: Run) {
    val opened = r.store.readAll().filter { it.kind == LeadKinds.GATE_OPENED }
    assertEquals(1, opened.size)
    val p = payloadObject(opened.single().payloadJson)
    assertEquals(gateIdFor(GateKinds.PLAN_APPROVAL, "t1"), p["gateId"]!!.jsonPrimitive.content)
    assertEquals(GateKinds.PLAN_APPROVAL, p["gateKind"]!!.jsonPrimitive.content)
    assertEquals(r.lead.planArtifactSha, p["payloadDigest"]!!.jsonPrimitive.content)
  }

  @Test
  fun twoProposalsOfTheSameGateOpenItOnce() {
    val r =
      run({ ctx ->
        listOf(
          Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, plan(ctx)),
          Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, plan(ctx)),
        )
      })
    assertPlanGateOpenedOnce(r)
    assertEquals(emptyList<String>(), r.host.escalations)
    r.store.close()
  }

  @Test
  fun twoProposalsOfTheSameGateUnderACeremonyMintAndAnnounceOnce() {
    // The mint and the announce ride the gate-open: a gate opened once is minted for and announced
    // once. The default sink reaches no operator, so the one announce is escalated as such.
    val r =
      run(
        { ctx ->
          listOf(
            Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, plan(ctx)),
            Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, plan(ctx)),
          )
        },
        ceremony = true,
      )
    assertPlanGateOpenedOnce(r)
    assertEquals(1, count(r.store, LeadKinds.NONCE_ISSUED))
    assertEquals(1, count(r.store, LeadKinds.GATE_OPEN_NOTIFIED))
    val gateId = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    assertEquals(
      listOf(
        "gate-open notify had no sink for $gateId (${GateKinds.PLAN_APPROVAL}) — gate is open and " +
          "blocking, operator not notified"
      ),
      r.host.escalations,
    )
    r.store.close()
  }

  @Test
  fun aRefusedProposalOfAGateLeavesTheTurnsLaterProposalOfItUnexecuted() {
    // The refusal marks the gate id handled for the turn, so the valid proposal after it is not
    // acted on, and the gate stays shut until a later turn proposes it.
    val r =
      run({ ctx ->
        listOf(
          Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, badDigest),
          Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, plan(ctx)),
        )
      })
    assertEquals(0, count(r.store, LeadKinds.GATE_OPENED))
    // GuardsTest pins the refusal's wording; here it matters only that the one escalation is it.
    assertTrue(r.host.escalations.single().startsWith("gate-open rejected for plan-approval:t1:"))
    r.store.close()
  }

  @Test
  fun anOpenedGatesLaterProposalInTheSameTurnIsNotEscalated() {
    val r =
      run({ ctx ->
        listOf(
          Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, plan(ctx)),
          Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, badDigest),
        )
      })
    assertPlanGateOpenedOnce(r)
    assertEquals(emptyList<String>(), r.host.escalations)
    r.store.close()
  }

  @Test
  fun aGateAlreadyOpenIsNotOpenedAgainOrEscalatedOnALaterTurn() {
    // The second drive adopts again, and its first wake proposes the open gate on a bad digest
    // and on its own: neither is acted on.
    val r =
      run(
        { ctx -> listOf(Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, plan(ctx))) },
        { ctx ->
          listOf(
            Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, badDigest),
            Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, plan(ctx)),
          )
        },
        drives = 2,
      )
    assertPlanGateOpenedOnce(r)
    assertEquals(emptyList<String>(), r.host.escalations)
    r.store.close()
  }

  @Test
  fun aGateOpenWithNoCurrentTicketIsIgnored() {
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val cognition =
      TurnCognition(mutableListOf({ listOf(Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, badDigest)) }))
    val daemon =
      ticketLead(
        store = store,
        cognition = cognition,
        podRunner = FakePodRunner(holdCompletions = false),
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        leadAuth = LeadAuth.DENY_ALL,
        timers = TimerService.NOOP,
      )
    val host = daemon.driveUntilQuiescent().host
    assertEquals("turns left unrun", 0, cognition.turns.size)
    assertEquals(0, count(store, LeadKinds.GATE_OPENED))
    assertTrue(host.escalations.isEmpty())
    store.close()
  }
}
