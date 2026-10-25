package com.geekinasuit.agency.lead

import org.json.JSONObject

/**
 * The ticket workflow's part of the cognition protocol: its proposal types and how they parse, its
 * lines of the system prompt, and its lines of the rendered state. [CognitionProtocol] composes
 * these with the host's own parts. This object holds no state.
 */
internal object TicketWorkflowProtocol {
  /** The shapes of this workflow's proposals, which the system prompt lists ahead of the host's. */
  val PROPOSAL_SHAPES =
    listOf(
      """{"type": "pod-spawn", "taskRef": "plan:<ticket>" | "execute:<ticket>"}""",
      """{"type": "gate-open", "gateKind": "plan-approval" | "commit-approval", "payloadDigest": "<sha256 from the state>"}""",
    )

  /**
   * The rules that end the system prompt. The first line holds a host rule (an empty array means
   * idle) beside this workflow's gate rule. It sits here whole, so the prompt is a concatenation
   * of parts rather than a line split between them.
   */
  val RULES =
    """
    An empty proposals array means idle. Open a gate only on a digest shown in the state.
    Follow the pipeline: no plan artifact -> spawn planner; plan artifact and no plan
    gate -> open plan-approval on its sha; plan gate approved=true and no manifest ->
    spawn executor; manifest and no commit gate -> open commit-approval on its digest;
    otherwise idle and wait.
    """
      .trimIndent()

  /** This workflow's lines of the rendered state, shown after the wake reason. */
  fun renderLines(lead: LeadState): List<String> =
    listOf(
      "ticket: ${lead.currentTicket ?: "none"}  phase: ${lead.phase}",
      "planArtifactSha: ${lead.planArtifactSha ?: "none"}",
      "commitManifestDigest: ${lead.commitManifestDigest ?: "none"}",
    )

  /**
   * Whether [gate] reads approved: it is one a stage of the current ticket waits on, and it is
   * released on the digest it is open on, which is the substrate's evidence for its kind
   * ([LeadState.approvedOnEvidence]). The daemon asks the same of each gate before it acts; the
   * commit effect also asks it of the plan gate.
   */
  fun gateReadsApproved(lead: LeadState, gate: OpenGate): Boolean {
    val ticket = lead.currentTicket ?: return false
    return GateKinds.ALL.any { kind -> gateIdFor(kind, ticket) == gate.gateId && lead.approvedOnEvidence(kind, ticket) }
  }

  /**
   * Parses [p], a proposal of [type], when [type] is one of this workflow's; null when it is not.
   * A required field missing or blank throws from [required], as it does for the host's types.
   */
  fun parseProposal(type: String, p: JSONObject): ProposalParse? =
    when (type) {
      "pod-spawn" -> {
        val taskRef = p.required("taskRef")
        if (!TASK_REF_SHAPE.matches(taskRef)) ProposalParse.Malformed(MalformedReasons.BAD_TASK_REF)
        else ProposalParse.Ok(Proposal.ProposePodSpawn(taskRef))
      }
      "gate-open" -> {
        val kind = p.required("gateKind")
        if (kind !in GateKinds.ALL) ProposalParse.Malformed(MalformedReasons.UNKNOWN_GATE_KIND)
        else ProposalParse.Ok(Proposal.ProposeGateOpen(kind, p.required("payloadDigest")))
      }
      else -> null
    }

  /** plan:/execute: over a ticket ref in the same conservative charset the substrate's own
   * task refs use. The only two task namespaces cognition may name.
   *
   * This is a SHAPE check and nothing more. Excluding '/' removes the obvious traversal
   * spelling, but `plan:..` matches this regex and is well-formed here — what actually
   * stops traversal is execute-time: the ref must equal the current ticket, and the
   * artifact path must canonically resolve inside the workspace. Which TICKET is legal is
   * folded state's call, never the parser's. */
  private val TASK_REF_SHAPE = Regex("""^(plan|execute):[A-Za-z0-9._-]+$""")
}
