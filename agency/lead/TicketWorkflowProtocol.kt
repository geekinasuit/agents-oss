package com.geekinasuit.agency.lead

import org.json.JSONObject

/**
 * The ticket workflow's part of the cognition protocol: its proposal types and how they parse, its
 * lines of the system prompt, and its lines of the rendered state. This object holds no state.
 */
internal object TicketWorkflowProtocol : WorkflowProtocol<LeadState> {
  override val proposalShapes =
    listOf(
      """{"type": "pod-spawn", "taskRef": "plan:<ticket>" | "execute:<ticket>"}""",
      """{"type": "gate-open", "gateKind": "plan-approval" | "commit-approval", "payloadDigest": "<sha256 from the state>"}""",
    )

  /**
   * The first line holds a host rule (an empty array means idle) beside this workflow's gate rule.
   * It sits here whole, so the prompt is a concatenation of parts rather than a line split between
   * them.
   */
  override val rules =
    """
    An empty proposals array means idle. Open a gate only on a digest shown in the state.
    Follow the pipeline: no plan artifact -> spawn planner; plan artifact and no plan
    gate -> open plan-approval on its sha; plan gate approved=true and no manifest ->
    spawn executor; manifest and no commit gate -> open commit-approval on its digest;
    otherwise idle and wait.
    """
      .trimIndent()

  override val proposalTypes = setOf("pod-spawn", "gate-open")

  override fun renderLines(lead: LeadState): List<String> =
    listOf(
      "ticket: ${lead.currentTicket ?: "none"}  phase: ${lead.phase}",
      "planArtifactSha: ${lead.planArtifactSha ?: "none"}",
      "commitManifestDigest: ${lead.commitManifestDigest ?: "none"}",
    )

  /**
   * A gate reads approved when it is one a stage of the current ticket waits on, and it is
   * released on the digest it is open on, which is the substrate's evidence for its kind
   * ([LeadState.approvedOnEvidence], over [records]). The daemon asks the same of each gate before
   * it acts; the commit effect also asks it of the plan gate.
   */
  override fun gateReadsApproved(lead: LeadState, records: HostView, gate: OpenGate): Boolean {
    val ticket = lead.currentTicket ?: return false
    return GateKinds.ALL.any { kind ->
      gateIdFor(kind, ticket) == gate.gateId && lead.approvedOnEvidence(records, kind, ticket)
    }
  }

  override fun parseProposal(type: String, p: JSONObject): ProposalParse =
    try {
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
        else -> throw IllegalArgumentException("not a ticket workflow proposal type: ${type.take(40)}")
      }
    } catch (e: MalformedProposal) {
      ProposalParse.Malformed(e.message!!)
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

/**
 * The cognition protocol of a ticket lead: the host's part composed with [TicketWorkflowProtocol].
 * [CognitionSelection] hands [composed] to every model-backed strategy it builds.
 */
object CognitionProtocol {
  val composed = ComposedCognitionProtocol(TicketWorkflowProtocol)

  val SYSTEM_PROMPT: String
    get() = composed.systemPrompt

  fun renderContext(context: AgentWakeContext<LeadState>): String = composed.renderContext(context)

  fun parseOutput(text: String, meta: Map<String, String>, presentation: ContextPresentation): CognitionOutput =
    composed.parseOutput(text, meta, presentation)
}
