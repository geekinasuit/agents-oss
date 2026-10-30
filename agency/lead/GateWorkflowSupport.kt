package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.sha256HexBytes
import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.JournalState
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.json.JSONObject

/**
 * A workflow that is not the ticket workflow, on the host's library alone: one scope, one gate,
 * opened on the digest of an evidence file the workflow records. The lead's state carries none of the
 * host's records, so every host and cognition decision over it reads the records the host folded
 * itself. Cells that must hold for any workflow run on it beside the ticket workflow.
 */
internal class GateWorkflow(private val evidence: File) : Workflow<GateLead> {
  override val fold = GateFold
  override val gateKinds = setOf(GATE_WORKFLOW_GATE_KIND)

  override fun scopeKey(lead: GateLead) = lead.w.scope

  override fun currentScopeKey(lead: GateLead) = lead.w.scope

  override fun gateId(gateKind: String, scopeKey: String) = "$gateKind:$scopeKey"

  override fun admitGateOpen(gateKind: String, payloadDigest: String, gateId: String, lead: GateLead) =
    if (evidenceMismatch(gateKind, payloadDigest, lead) == null) {
      GateOpenDecision.Open(payloadDigest)
    } else {
      GateOpenDecision.Refuse("not the recorded evidence")
    }

  override fun admitPodSpawn(
    taskRef: String,
    lead: GateLead,
    records: HostView,
    turn: ProposalTurn,
    host: HostServices,
  ) = false

  override fun gateArtifactPath(gateKind: String, lead: GateLead) = evidence.absolutePath.takeIf { lead.w.evidence != null }

  override fun recordedEvidence(gateKind: String, lead: GateLead) = lead.w.evidence

  override fun evidenceMismatch(gateKind: String, digest: String, lead: GateLead) =
    when (lead.w.evidence) {
      null -> "no evidence recorded"
      digest -> null
      else -> "not the recorded evidence"
    }

  override fun redriveMessage(key: String, lead: GateLead, records: HostView): String? = null

  override fun redriveDeclineReason(key: String): String? = null

  override fun mechanicalStep(lead: GateLead, records: HostView, shared: JournalState, host: HostServices): Boolean {
    if (lead.w.scope != null) return false
    host.append(
      GATE_WORKFLOW_SCOPE_OPENED,
      buildJsonObject {
        put("scope", "s1")
        put("evidence", sha256HexBytes(evidence.readBytes()))
      },
    )
    return true
  }
}

/** [GateWorkflow]'s own state: the scope it opened, and the evidence it recorded for the gate. */
internal data class GateWorkflowState(val scope: String? = null, val evidence: String? = null)

/** A lead's state for [GateWorkflow]: the workflow's own, and none of the host's records. */
internal class GateLead(val w: GateWorkflowState)

internal object GateFold : WorkflowFold<GateLead, GateWorkflowState> {
  override val substrateKinds = setOf(GATE_WORKFLOW_SCOPE_OPENED)
  override val scopeEndKinds = emptySet<String>()
  override val start = GateWorkflowState()

  override fun expectedTaskRefs(w: GateWorkflowState) = emptySet<String>()

  override fun step(w: GateWorkflowState, e: JournalEntry, outcome: HostOutcome): GateWorkflowState {
    if (e.kind != GATE_WORKFLOW_SCOPE_OPENED || outcome is HostOutcome.Rejected) return w
    val p = Json.parseToJsonElement(e.payloadJson).jsonObject
    return GateWorkflowState(p.getValue("scope").jsonPrimitive.content, p.getValue("evidence").jsonPrimitive.content)
  }

  override fun assemble(host: HostState, w: GateWorkflowState) = GateLead(w)
}

/** Proposes [GateWorkflow]'s gate on the recorded evidence at every turn; the host opens it once. */
internal object ProposeTheGate : AgentCognition<GateLead> {
  override val name = "propose-the-gate"

  override fun decide(context: AgentWakeContext<GateLead>): CognitionOutput {
    val evidence = context.lead.w.evidence ?: return CognitionOutput.idle(ContextPresentation.PRESENTED)
    return CognitionOutput(
      proposals = listOf(Proposal.ProposeGateOpen(GATE_WORKFLOW_GATE_KIND, evidence)),
      presentation = ContextPresentation.PRESENTED,
    )
  }
}

/** [GateWorkflow]'s part of the cognition protocol: no proposals of its own, no lines of state. */
internal object GateProtocol : WorkflowProtocol<GateLead> {
  override val proposalShapes = emptyList<String>()
  override val rules = ""
  override val proposalTypes = emptySet<String>()

  override fun renderLines(lead: GateLead) = emptyList<String>()

  override fun gateReadsApproved(lead: GateLead, records: HostView, gate: OpenGate) = false

  override fun parseProposal(type: String, p: JSONObject): ProposalParse =
    ProposalParse.Malformed(MalformedReasons.UNKNOWN_TYPE)
}

/** The kind of the row [GateWorkflow] opens its scope with. */
internal const val GATE_WORKFLOW_SCOPE_OPENED = "gate-scope-opened"

/** The kind of [GateWorkflow]'s one gate. */
internal const val GATE_WORKFLOW_GATE_KIND = "approval"
