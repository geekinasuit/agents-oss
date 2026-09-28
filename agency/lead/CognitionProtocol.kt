package com.geekinasuit.agency.lead

import org.json.JSONException
import org.json.JSONObject

/**
 * The contract every model-backed [CognitionStrategy] speaks: what the model is told
 * ([SYSTEM_PROMPT]), how a wake's folded state is shown to it ([renderContext]), and how
 * its reply is turned into typed proposals ([parseOutput]).
 *
 * It lives apart from any one strategy because the contract is a property of the
 * SUBSTRATE, not of the provider underneath. Two strategies reaching the same model
 * through different transports must agree on it exactly — a second prompt or a second
 * parser would let "what the lead accepts as a decision" drift by provider, and the fold
 * would then be recording two different things under one origin.
 *
 * Nothing here trusts its input. Parsing is lenient about packaging and strict about
 * structure, and a strategy's transport concerns (auth, timeouts, cost) stay out.
 */
object CognitionProtocol {
  val SYSTEM_PROMPT =
    """
    You are the cognition loop of an Agency lead daemon. You are shown the lead's folded
    state once per wake. You PROPOSE; you never release gates — releases come only from
    the human authorization layer, and the journal fold rejects anything else.

    Respond with EXACTLY one JSON object, no prose around it:
    {"proposals": [
       {"type": "pod-spawn", "taskRef": "plan:<ticket>" | "execute:<ticket>"}
     | {"type": "gate-open", "gateKind": "plan-approval" | "commit-approval", "payloadDigest": "<sha256 from the state>"}
     | {"type": "status", "status": "<short line>"}
     | {"type": "escalate", "reason": "<why a human should look>"}
     ], "reasoning": "<one or two sentences>"}
    An empty proposals array means idle. Open a gate only on a digest shown in the state.
    Follow the pipeline: no plan artifact -> spawn planner; plan artifact and no plan
    gate -> open plan-approval on its sha; plan gate approved=true and no manifest ->
    spawn executor; manifest and no commit gate -> open commit-approval on its digest;
    otherwise idle and wait.
    """
      .trimIndent()

  /** Prompt bounds on untrusted mailbox content. */
  private const val MAX_MAIL_SHOWN = 20
  private const val MAX_MAIL_CHARS = 500

  /**
   * The wake's state as the model sees it. Every field rendered here is derived from the
   * fold, so two calls against one fold render identical text — which is what makes a
   * within-wake retry a repeat of the same question rather than a new one.
   */
  fun renderContext(context: WakeContext): String {
    val lead = context.lead
    val sb = StringBuilder()
    sb.appendLine("WAKE: ${context.reason}")
    sb.appendLine("ticket: ${lead.currentTicket ?: "none"}  phase: ${lead.phase}")
    sb.appendLine("planArtifactSha: ${lead.planArtifactSha ?: "none"}")
    sb.appendLine("commitManifestDigest: ${lead.commitManifestDigest ?: "none"}")
    // A gate reads approved only when it is one a stage of the current ticket waits on, and it is
    // released on the digest it is open on, which is the substrate's evidence for its kind
    // ([LeadState.approvedOnEvidence]). The daemon asks the same of each gate before it acts; the
    // commit effect also asks it of the plan gate.
    fun approved(gate: OpenGate): Boolean {
      val ticket = lead.currentTicket ?: return false
      return GateKinds.ALL.any { kind ->
        gateIdFor(kind, ticket) == gate.gateId && lead.approvedOnEvidence(kind, ticket)
      }
    }
    sb.appendLine(
      "openGates: " +
        lead.openGates.values
          .joinToString(", ") {
            "${it.gateId}(digest=${it.payloadDigest}, approved=${approved(it)})"
          }
          .ifEmpty { "none" }
    )
    sb.appendLine(
      "activePods: " +
        lead.activePods.joinToString(", ") { "${it.podId}:${it.taskRef}" }.ifEmpty { "none" }
    )
    sb.appendLine("staleReleases: ${lead.staleReleases.size}  escalations: ${lead.escalations.size}")
    sb.appendLine("undeliveredMail:")
    // Mail is untrusted content rendered into the model prompt: bound
    // both the count and per-message length so a huge or prompt-injected mailbox cannot
    // amplify cost or dominate the context. Content is data, never executed — the
    // execute-time proposal guards are what stop a hostile message causing an effect.
    for ((seq, msg) in context.undeliveredMail.take(MAX_MAIL_SHOWN))
      sb.appendLine("  [$seq] ${msg.take(MAX_MAIL_CHARS)}")
    if (context.undeliveredMail.size > MAX_MAIL_SHOWN)
      sb.appendLine("  … ${context.undeliveredMail.size - MAX_MAIL_SHOWN} more not shown")
    if (context.undeliveredMail.isEmpty()) sb.appendLine("  none")
    return sb.toString()
  }

  /**
   * Lenient extraction (first '{' to last '}'), strict interpretation.
   *
   * Strict means STRUCTURAL: a known proposal type, its required fields present and
   * non-blank, a known gate kind, a taskRef of the plan:/execute: shape. Anything else is
   * the whole turn's [CognitionOutput.malformed] — one near-miss proposal invalidates the
   * output rather than being dropped from an otherwise-executed batch, because a model
   * that got one proposal structurally wrong has not demonstrated it meant the others.
   *
   * SEMANTIC validity is a separate boundary and stays where it is: whether a well-formed
   * taskRef names the CURRENT ticket, and whether a digest matches substrate evidence, are
   * checked against folded state at execute time (LeadDaemon.executeProposals), which is
   * the only place that state is authoritative.
   */
  fun parseOutput(text: String, meta: Map<String, String>): CognitionOutput {
    val start = text.indexOf('{')
    val end = text.lastIndexOf('}')
    if (start < 0 || end <= start) {
      return CognitionOutput.malformed(MalformedReasons.NOT_JSON, meta)
    }
    return try {
      val obj = JSONObject(text.substring(start, end + 1))
      val proposals = mutableListOf<Proposal>()
      val arr = obj.optJSONArray("proposals")
      // A wrong-TYPE "proposals" reads identically to an absent one here (optJSONArray
      // returns null for both), so the two cases must be told apart explicitly: omitting
      // the key is a turn that proposed nothing, while `"proposals": {...}` / `"str"` /
      // `null` is a turn whose decision shape was wrong. Without this, a container-level
      // near-miss is silently a clean idle — the exact confusion this outcome exists to
      // end, one level up from a malformed element inside the array.
      if (arr == null && obj.has("proposals")) {
        return CognitionOutput.malformed(MalformedReasons.PROPOSALS_NOT_ARRAY, meta)
      }
      if (arr != null) {
        for (i in 0 until arr.length()) {
          val p =
            arr.opt(i) as? JSONObject
              ?: return CognitionOutput.malformed(MalformedReasons.PROPOSAL_NOT_OBJECT, meta)
          when (p.optString("type")) {
            "" -> return CognitionOutput.malformed(MalformedReasons.PROPOSAL_NO_TYPE, meta)
            "pod-spawn" -> {
              val taskRef = p.required("taskRef")
              if (!TASK_REF_SHAPE.matches(taskRef))
                return CognitionOutput.malformed(MalformedReasons.BAD_TASK_REF, meta)
              proposals += Proposal.ProposePodSpawn(taskRef)
            }
            "gate-open" -> {
              val kind = p.required("gateKind")
              if (kind !in GateKinds.ALL)
                return CognitionOutput.malformed(MalformedReasons.UNKNOWN_GATE_KIND, meta)
              proposals += Proposal.ProposeGateOpen(kind, p.required("payloadDigest"))
            }
            "status" -> proposals += Proposal.ProposeStatus(p.required("status"))
            "escalate" -> proposals += Proposal.ProposeEscalate(p.required("reason"))
            else -> return CognitionOutput.malformed(MalformedReasons.UNKNOWN_TYPE, meta)
          }
        }
      }
      CognitionOutput(proposals, obj.optString("reasoning"), meta)
    } catch (e: MalformedProposal) {
      CognitionOutput.malformed(e.message!!, meta)
    } catch (e: Exception) {
      // Not the message: the parser's message can quote the output it was reading.
      CognitionOutput.malformed(MalformedReasons.parseFailure(e), meta)
    }
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

  private class MalformedProposal(field: String) : RuntimeException(MalformedReasons.missingField(field))

  /** Demands an actual non-blank JSON string. `optString` would stringify whatever it
   * found — a number, or a whole nested object — turning a wrong-shaped field into a
   * plausible-looking value instead of the near-miss it is. */
  private fun JSONObject.required(field: String): String {
    val v = opt(field)
    if (v !is String || v.isBlank()) throw MalformedProposal(field)
    return v
  }
}

/**
 * Every reason the lead writes on a [LeadKinds.COGNITION_MALFORMED] row: [CognitionProtocol.parseOutput]'s
 * classifications and the daemon's fallback. The fold holds a reason only when [isLeads] accepts
 * it, so a row the lead did not write cannot put its own text in [LeadState.malformedCognition].
 */
object MalformedReasons {
  const val NOT_JSON = "cognition output was not JSON"
  const val PROPOSALS_NOT_ARRAY = "'proposals' is present but is not an array"
  const val PROPOSAL_NOT_OBJECT = "a proposal is not an object"
  const val PROPOSAL_NO_TYPE = "a proposal has no type"
  const val BAD_TASK_REF = "pod-spawn taskRef is not plan:/execute:<ticket>"
  const val UNKNOWN_GATE_KIND = "gate-open names an unknown gate kind"
  const val UNKNOWN_TYPE = "unknown proposal type"
  const val UNCLASSIFIED = "unclassified"
  const val PARSE_FAILURE_PREFIX = "cognition output failed to parse: "
  const val PARSE_FAILURE_JSON = PARSE_FAILURE_PREFIX + "JSONException"
  const val PARSE_FAILURE_OTHER = PARSE_FAILURE_PREFIX + "an unexpected exception"

  /** The fields [CognitionProtocol.parseOutput] requires; a missing one is named. */
  val REQUIRED_FIELDS = setOf("taskRef", "gateKind", "payloadDigest", "status", "reason")

  fun missingField(field: String): String = "proposal field '$field' is missing or blank"

  /** A parse failure is named by a fixed reason, never by text taken from the exception. */
  fun parseFailure(e: Throwable): String = if (e is JSONException) PARSE_FAILURE_JSON else PARSE_FAILURE_OTHER

  private val FIXED =
    setOf(NOT_JSON, PROPOSALS_NOT_ARRAY, PROPOSAL_NOT_OBJECT, PROPOSAL_NO_TYPE, BAD_TASK_REF, UNKNOWN_GATE_KIND,
      UNKNOWN_TYPE, UNCLASSIFIED, PARSE_FAILURE_JSON, PARSE_FAILURE_OTHER) + REQUIRED_FIELDS.map(::missingField)

  fun isLeads(reason: String): Boolean = reason in FIXED
}
