package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.pod.sha256HexBytes
import com.geekinasuit.agency.shared.harness.ClaudeHarness
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.JournalState
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The host running a workflow that is not the ticket workflow, on the host's library alone: one
 * gate, opened on evidence the workflow records, with no ticket walk. The lead's state carries none
 * of the host's records, so every host and cognition decision here reads the records the host
 * folded itself.
 *
 * The scenario, in drives over one journal:
 * 1. Under a ceremony auth, a crash between the gate-open and its mint.
 * 2. Rows the host must recover from are added (a spawn intent with no pod, a running pod, an effect
 *    intent no workflow journals), and the host restarts: it declines and escalates the intent,
 *    abandons the pod and the orphaned intent, mints the gate's nonce, and announces it; the first
 *    two announces fail, and each is sent again on its own retry timer.
 * 3. A second ceremony restart: the declined intent is not escalated again.
 *
 * Then one of two endings ([Ending]):
 * - Two restarts under an auth with no approvers: the gate holds a nonce no release can now use, so
 *   it is escalated as stalled, once.
 * - The gate is approved and released on its digest, the workflow then records other evidence, and
 *   two ceremony restarts escalate the release as off its evidence, once.
 *
 * Not reached: the mint-stall escalation (a gate with no usable nonce that is not released on its
 * digest, under a ceremony auth, whose mint is refused); an announce whose bound copy could not be
 * read; and a pod event, since this workflow spawns no pods.
 */
class HostOnlyDriverTest {
  @get:Rule val tmp = TemporaryFolder()

  @Test
  fun theHostOpensMintsAndAnnouncesAGateForAWorkflowThatIsNotTheTicketWorkflow() {
    for (ending in Ending.entries) {
      val run = run(ending)
      assertEquals("$ending: one gate opened", 1, run.kinds.count { it == HostKinds.GATE_OPENED })
      assertEquals("$ending: one nonce, minted by the recovery", 1, run.kinds.count { it == HostKinds.NONCE_ISSUED })
      assertEquals("$ending: the announce sent until it was delivered", 3, run.announces)
      assertEquals("$ending: the live pod abandoned once", 1, run.kinds.count { it == HostKinds.POD_ABANDONED })
      assertEquals("$ending: the orphaned intent abandoned once", 1, run.kinds.count { it == HostKinds.POD_SPAWN_ABANDONED })
      assertEquals("$ending: the unknown effect declined once", 1, run.escalations.count { "effect re-drive declined" in it })
      val (stalls, offEvidence) = if (ending == Ending.NO_APPROVERS) 1 to 0 else 0 to 1
      assertEquals("$ending: stall escalations", stalls, run.escalations.count { "gate-open stalled" in it })
      assertEquals("$ending: off-evidence escalations", offEvidence, run.escalations.count { "released off its evidence" in it })
    }
  }

  @Test
  fun theBudgetGuardStopsATurnOnTheHostsSpendWhenTheWorkflowsStateCarriesNone() {
    // The journal's spend is past the cap, and the workflow's state carries no spend at all. The
    // guard reads the spend and the escalations the host folded, so across two drives it escalates
    // once and runs no turn.
    val dir = tmp.newFolder()
    val ran = File(dir, "ran")
    val claude =
      File(dir, "fake-claude").apply {
        writeText("#!/bin/sh\n: > '${ran.absolutePath}'\nexit 1\n")
        setExecutable(true)
      }
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    store.append(
      HostKinds.COGNITION_PROPOSED,
      buildJsonObject {
        put("costUsd", "1.5")
        put("strategy", "claude")
        put("reasoning", "an earlier turn")
        put("proposals", buildJsonArray {})
      },
      ORIGIN_COGNITION,
    )
    val cognition =
      ClaudeCognition(
        harness = ClaudeHarness(claude.absolutePath),
        workDir = dir,
        protocol = ComposedCognitionProtocol(GateProtocol),
        maxTotalUsd = 1.0,
        timeoutSec = 30,
      )
    val evidence = File(dir, "evidence.txt").apply { writeText("x\n") }
    repeat(2) { host(dir, store, evidence, cognition = cognition).driveUntilQuiescent() }
    val escalations = escalations(store.readAll())
    store.close()

    assertFalse("no turn is run past the cap", ran.exists())
    assertEquals(1, escalations.count { it.startsWith("cognition budget exhausted") })
  }

  /** How the scenario ends after its shared drives. Two endings, since a gate escalated on a digest
   * for one reason is not escalated on it again for another. */
  private enum class Ending {
    NO_APPROVERS,
    RELEASED_OFF_EVIDENCE,
  }

  private data class Run(val kinds: List<String>, val escalations: List<String>, val announces: Int)

  private fun run(ending: Ending): Run {
    val dir = tmp.newFolder()
    val evidence = File(dir, "evidence.txt").apply { writeText("approve this\n") }
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    var announces = 0
    val sink = GateOpenSink {
      announces += 1
      if (announces <= 2) AnnounceOutcome.Failed("not connected") else AnnounceOutcome.Announced("delivered")
    }
    val crash = FaultInjector { if (it == "after-gate-opened-$GATE_KIND") throw RuntimeException("crash before the mint") }
    val ceremony = ceremonyAuth()
    assertThrows(RuntimeException::class.java) {
      host(dir, store, evidence, sink, crash, ceremony).driveUntilQuiescent()
    }
    store.append(HostKinds.POD_SPAWN_INTENDED, buildJsonObject { put("taskRef", "orphan") }, ORIGIN_SUBSTRATE)
    store.append(
      HostKinds.POD_SPAWNED,
      buildJsonObject {
        put("podId", "p1")
        put("sessionId", "s1")
        put("taskRef", "live")
        put("artifactPath", "a")
      },
      ORIGIN_SUBSTRATE,
    )
    store.append("effect-intent", buildJsonObject { put("key", "unknown-effect") }, ORIGIN_SUBSTRATE, "unknown-effect")
    host(dir, store, evidence, sink, FaultInjector.NONE, ceremony).driveUntilQuiescent()
    host(dir, store, evidence, sink, FaultInjector.NONE, ceremony).driveUntilQuiescent()
    when (ending) {
      Ending.NO_APPROVERS -> repeat(2) {
        host(dir, store, evidence, sink, FaultInjector.NONE, LeadAuth.DENY_ALL).driveUntilQuiescent()
      }
      Ending.RELEASED_OFF_EVIDENCE -> {
        val issued =
          Json.parseToJsonElement(store.readAll().single { it.kind == HostKinds.NONCE_ISSUED }.payloadJson).jsonObject
        store.approveAndRelease(
          issued.getValue("gateId").jsonPrimitive.content,
          issued.getValue("payloadDigest").jsonPrimitive.content,
          issued.getValue("nonce").jsonPrimitive.content,
        )
        store.append(
          SCOPE_OPENED,
          buildJsonObject {
            put("scope", "s1")
            put("evidence", "1".repeat(64))
          },
          ORIGIN_SUBSTRATE,
        )
        repeat(2) { host(dir, store, evidence, sink, FaultInjector.NONE, ceremony).driveUntilQuiescent() }
      }
    }
    val entries = store.readAll()
    store.close()
    return Run(entries.map { it.kind }, escalations(entries), announces)
  }

  private fun escalations(entries: List<JournalEntry>) =
    entries
      .filter { it.kind == HostKinds.ESCALATED }
      .map { Json.parseToJsonElement(it.payloadJson).jsonObject.getValue("reason").jsonPrimitive.content }

  private fun host(
    dir: File,
    store: SqliteStore,
    evidence: File,
    sink: GateOpenSink = GateOpenSink { AnnounceOutcome.Announced("delivered") },
    faults: FaultInjector = FaultInjector.NONE,
    auth: LeadAuth = LeadAuth.DENY_ALL,
    cognition: AgentCognition<GateLead> = ProposeTheGate,
  ): AgentHost<GateLead> =
    AgentHost(
      store = store,
      cognition = cognition,
      podRunner = FakePodRunner(),
      podSpec = PodSpec.fixture(),
      workflow = GateWorkflow(evidence),
      workdir = dir,
      effects = EffectReceiver(dir.absolutePath),
      leadAuth = auth,
      timers = { timer, onDue -> onDue(timer.id) },
      faults = faults,
      gateOpenSink = sink,
    )

  /** The workflow's own state: the scope it opened, and the evidence it recorded for the gate. */
  private data class GateWorkflowState(val scope: String? = null, val evidence: String? = null)

  /** A lead's state for [GateWorkflow]: the workflow's own, and none of the host's records. */
  private class GateLead(val w: GateWorkflowState)

  private object GateFold : WorkflowFold<GateLead, GateWorkflowState> {
    override val substrateKinds = setOf(SCOPE_OPENED)
    override val scopeEndKinds = emptySet<String>()
    override val start = GateWorkflowState()

    override fun expectedTaskRefs(w: GateWorkflowState) = emptySet<String>()

    override fun step(w: GateWorkflowState, e: JournalEntry, outcome: HostOutcome): GateWorkflowState {
      if (e.kind != SCOPE_OPENED || outcome is HostOutcome.Rejected) return w
      val p = Json.parseToJsonElement(e.payloadJson).jsonObject
      return GateWorkflowState(p.getValue("scope").jsonPrimitive.content, p.getValue("evidence").jsonPrimitive.content)
    }

    override fun assemble(host: HostState, w: GateWorkflowState) = GateLead(w)
  }

  /** One scope, one gate: the workflow records the evidence file's digest, and the gate opens only on
   * it. Its own logic reads only its own state. */
  private class GateWorkflow(private val evidence: File) : Workflow<GateLead> {
    override val fold = GateFold
    override val gateKinds = setOf(GATE_KIND)

    override fun scopeKey(lead: GateLead) = lead.w.scope

    override fun currentScopeKey(lead: GateLead) = lead.w.scope

    override fun gateId(gateKind: String, scopeKey: String) = "$gateKind:$scopeKey"

    override fun admitGateOpen(gateKind: String, payloadDigest: String, gateId: String, lead: GateLead) =
      if (evidenceMismatch(gateKind, payloadDigest, lead) == null) {
        GateOpenDecision.Open(payloadDigest)
      } else {
        GateOpenDecision.Refuse("not the recorded evidence")
      }

    override fun admitPodSpawn(taskRef: String, lead: GateLead, turn: ProposalTurn, host: HostServices) = false

    override fun gateArtifactPath(gateKind: String, lead: GateLead) = evidence.absolutePath.takeIf { lead.w.evidence != null }

    override fun recordedEvidence(gateKind: String, lead: GateLead) = lead.w.evidence

    override fun evidenceMismatch(gateKind: String, digest: String, lead: GateLead) =
      when (lead.w.evidence) {
        null -> "no evidence recorded"
        digest -> null
        else -> "not the recorded evidence"
      }

    override fun redriveMessage(key: String, lead: GateLead): String? = null

    override fun redriveDeclineReason(key: String): String? = null

    override fun mechanicalStep(lead: GateLead, shared: JournalState, host: HostServices): Boolean {
      if (lead.w.scope != null) return false
      host.append(
        SCOPE_OPENED,
        buildJsonObject {
          put("scope", "s1")
          put("evidence", sha256HexBytes(evidence.readBytes()))
        },
      )
      return true
    }
  }

  /** Proposes the gate on the recorded evidence at every turn; the host opens it once. */
  private object ProposeTheGate : AgentCognition<GateLead> {
    override val name = "propose-the-gate"

    override fun decide(context: AgentWakeContext<GateLead>): CognitionOutput {
      val evidence = context.lead.w.evidence ?: return CognitionOutput.idle(ContextPresentation.PRESENTED)
      return CognitionOutput(
        proposals = listOf(Proposal.ProposeGateOpen(GATE_KIND, evidence)),
        presentation = ContextPresentation.PRESENTED,
      )
    }
  }

  /** [GateWorkflow]'s part of the cognition protocol: no proposals of its own, no lines of state. */
  private object GateProtocol : WorkflowProtocol<GateLead> {
    override val proposalShapes = emptyList<String>()
    override val rules = ""
    override val proposalTypes = emptySet<String>()

    override fun renderLines(lead: GateLead) = emptyList<String>()

    override fun gateReadsApproved(lead: GateLead, gate: OpenGate) = false

    override fun parseProposal(type: String, p: JSONObject): ProposalParse =
      ProposalParse.Malformed(MalformedReasons.UNKNOWN_TYPE)
  }

  private companion object {
    const val SCOPE_OPENED = "gate-scope-opened"
    const val GATE_KIND = "approval"
  }
}
