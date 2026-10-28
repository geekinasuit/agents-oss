package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.pod.sha256HexBytes
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.JournalState
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The host running a workflow that is not the ticket workflow, on the host's library alone: one
 * gate, opened on evidence the workflow records, with no ticket walk.
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
      val run = run(lie = false, ending)
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
  fun theHostDecidesTheSameWhenTheWorkflowsStateMisreportsEveryHostRecord() {
    // The workflow's own logic reads only its own fields, so a lie about the host's records changes
    // nothing the workflow decides. Each record a host decision in the scenario reads differs from
    // its lie somewhere in the scenario, so a decision that read the lie would differ: the gate
    // opened again, the mint or the announce skipped or repeated, a pod or intent left alone, an
    // escalation repeated or dropped. The class KDoc names the decisions the scenario does not reach.
    for (ending in Ending.entries) assertEquals("$ending", run(lie = false, ending), run(lie = true, ending))
  }

  /** How the scenario ends after its shared drives. Two endings, since a gate escalated on a digest
   * for one reason is not escalated on it again for another. */
  private enum class Ending {
    NO_APPROVERS,
    RELEASED_OFF_EVIDENCE,
  }

  private data class Run(val kinds: List<String>, val escalations: List<String>, val announces: Int)

  private fun run(lie: Boolean, ending: Ending): Run {
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
      host(dir, store, evidence, lie, sink, crash, ceremony).driveUntilQuiescent()
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
    host(dir, store, evidence, lie, sink, FaultInjector.NONE, ceremony).driveUntilQuiescent()
    host(dir, store, evidence, lie, sink, FaultInjector.NONE, ceremony).driveUntilQuiescent()
    when (ending) {
      Ending.NO_APPROVERS -> repeat(2) {
        host(dir, store, evidence, lie, sink, FaultInjector.NONE, LeadAuth.DENY_ALL).driveUntilQuiescent()
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
        repeat(2) { host(dir, store, evidence, lie, sink, FaultInjector.NONE, ceremony).driveUntilQuiescent() }
      }
    }
    val entries = store.readAll()
    store.close()
    val escalations =
      entries
        .filter { it.kind == HostKinds.ESCALATED }
        .map { Json.parseToJsonElement(it.payloadJson).jsonObject.getValue("reason").jsonPrimitive.content }
    return Run(entries.map { it.kind }, escalations, announces)
  }

  private fun host(
    dir: File,
    store: SqliteStore,
    evidence: File,
    lie: Boolean,
    sink: GateOpenSink,
    faults: FaultInjector,
    auth: LeadAuth,
  ): AgentHost<GateLead> =
    AgentHost(
      store = store,
      cognition = ProposeTheGate,
      podRunner = FakePodRunner(),
      podSpec = PodSpec.fixture(),
      workflow = GateWorkflow(lie, evidence),
      workdir = dir,
      effects = EffectReceiver(dir.absolutePath),
      leadAuth = auth,
      timers = { timer, onDue -> onDue(timer.id) },
      faults = faults,
      gateOpenSink = sink,
    )

  /** The workflow's own state: the scope it opened, and the evidence it recorded for the gate. */
  private data class GateWorkflowState(val scope: String? = null, val evidence: String? = null)

  /** A lead's state for [GateWorkflow]: the host's records, misreported when [lie] is set, and the
   * workflow's own. */
  private class GateLead(private val host: HostState, val w: GateWorkflowState, private val lie: Boolean) :
    HostView {
    override val openGates: Map<String, OpenGate> = if (lie) emptyMap() else host.openGates
    override val activePods: List<PodRecord> = if (lie) emptyList() else host.activePods
    override val staleReleases: List<Pair<Long, String>> = if (lie) emptyList() else host.staleReleases
    override val escalations: List<String> = if (lie) emptyList() else host.escalations
    override val cognitionSpendUsd: Double = if (lie) 0.0 else host.cognitionSpendUsd
    override val pods: Map<String, PodRecord> = if (lie) emptyMap() else host.pods
    override val pendingSpawnIntents: Map<String, Long> = if (lie) emptyMap() else host.pendingSpawnIntents
    override val declinedEffects: Set<String> = if (lie) emptySet() else host.declinedEffects
    override val escalatedStalls: Map<String, Set<String>> = if (lie) emptyMap() else host.escalatedStalls
    override val issuedNonces: Map<String, IssuedNonce> = if (lie) emptyMap() else host.issuedNonces
    override val notifiedNonces: Set<String> = if (lie) host.issuedNonces.keys else host.notifiedNonces
    override val failedAnnounces: Map<String, Int> = if (lie) emptyMap() else host.failedAnnounces
    override val notReadAnnounces: Map<String, Int> = if (lie) emptyMap() else host.notReadAnnounces

    override fun approvedOnCurrentDigest(gateId: String): Boolean = host.approvedOnCurrentDigest(gateId) != lie

    override fun openNonceFor(gate: OpenGate): IssuedNonce? {
      val truth = host.openNonceFor(gate)
      return when {
        !lie -> truth
        truth != null -> null
        else -> IssuedNonce("forged", gate.gateId, gate.payloadDigest, 0)
      }
    }
  }

  private class GateFold(private val lie: Boolean) : WorkflowFold<GateLead, GateWorkflowState> {
    override val substrateKinds = setOf(SCOPE_OPENED)
    override val scopeEndKinds = emptySet<String>()
    override val start = GateWorkflowState()

    override fun expectedTaskRefs(w: GateWorkflowState) = emptySet<String>()

    override fun step(w: GateWorkflowState, e: JournalEntry, outcome: HostOutcome): GateWorkflowState {
      if (e.kind != SCOPE_OPENED || outcome is HostOutcome.Rejected) return w
      val p = Json.parseToJsonElement(e.payloadJson).jsonObject
      return GateWorkflowState(p.getValue("scope").jsonPrimitive.content, p.getValue("evidence").jsonPrimitive.content)
    }

    override fun assemble(host: HostState, w: GateWorkflowState) = GateLead(host, w, lie)
  }

  /** One scope, one gate: the workflow records the evidence file's digest, and the gate opens only on
   * it. Its own logic reads only its own state. */
  private class GateWorkflow(lie: Boolean, private val evidence: File) : Workflow<GateLead> {
    override val fold = GateFold(lie)
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

  private companion object {
    const val SCOPE_OPENED = "gate-scope-opened"
    const val GATE_KIND = "approval"
  }
}
