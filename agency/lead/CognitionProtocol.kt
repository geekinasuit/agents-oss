package com.geekinasuit.agency.lead

import org.json.JSONException
import org.json.JSONObject

/**
 * Which undelivered mail a render shows, and how. It depends on no workflow: the protocol's
 * render ([ComposedCognitionProtocol.renderContext]) and the daemon's retirement of what a turn
 * was shown both read it, so the two cannot disagree.
 */
object MailRender {
  /** Prompt bounds on untrusted mailbox content. */
  internal const val MAX_MAIL_SHOWN = 20
  private const val MAX_MAIL_CHARS = 500

  /**
   * One undelivered mail as [ComposedCognitionProtocol.renderContext] shows it: [text] is the first [MAX_MAIL_CHARS] chars
   * of a message [totalChars] long, which [line] quotes into the prompt.
   *
   * The bound is measured on the source text, before quoting. Cutting the quoted form instead
   * could split an escape sequence. Quoting can grow a char to six (`JSONObject.quote` writes a
   * control char, U+0080 to U+009F, and U+2000 to U+20FF as `\uXXXX`), so one rendered mail
   * line can carry up to about 3,000 chars plus its prefix, not 500. The documented 20 × 500
   * prompt bound on mail is therefore up to about 20 × 3,000 = 60,000 rendered chars. Size
   * nothing from the 20 × 500 figure.
   */
  class ShownMail(val seq: Long, val text: String, val totalChars: Int) {
    val whole: Boolean
      get() = text.length == totalChars

    /**
     * The prompt line. The body is quoted as a JSON string, so its own text cannot close the
     * quote, start a new line, or write into the renderer's bracketed prefix. The prefix carries
     * the seq and, for a cut message, the cut with both lengths: `[seq, truncated: 500 of 3812
     * chars]`. Since the body cannot reach the prefix, a mail cannot forge or hide that marker.
     */
    fun line(): String {
      val prefix = if (whole) "[$seq]" else "[$seq, truncated: ${text.length} of $totalChars chars]"
      return "  $prefix ${JSONObject.quote(text)}"
    }
  }

  /**
   * The mail a render shows: the first [MAX_MAIL_SHOWN] undelivered messages, each bounded to
   * [MAX_MAIL_CHARS]. [ComposedCognitionProtocol.renderContext] renders exactly this, and [mailRenderedForRetirement]
   * derives from it, so what the prompt shows and what the daemon retires cannot disagree.
   */
  fun mailShown(undelivered: List<Pair<Long, String>>): List<ShownMail> =
    undelivered.take(MAX_MAIL_SHOWN).map { (seq, msg) ->
      ShownMail(seq, msg.take(MAX_MAIL_CHARS), totalChars = msg.length)
    }

  /**
   * The seqs of the mail a render shows either whole or cut with the cut stated: what a turn
   * that was presented the render has seen, and so all the daemon may mark delivered after it. Mail
   * past [MAX_MAIL_SHOWN] is not shown at all and waits for a later turn, which sees it once the
   * mail ahead of it is retired.
   *
   * A message longer than [MAX_MAIL_CHARS] can never be shown whole. It is shown cut, with a
   * marker giving the shown and total lengths ([ShownMail.line]), so the turn knows it saw a
   * prefix of a longer message, and it is retired once such a turn was presented it. Keeping it
   * undelivered until shown whole would hold one of the [MAX_MAIL_SHOWN] slots forever, and
   * enough of them at the head of the queue would starve every mail behind them.
   */
  fun mailRenderedForRetirement(undelivered: List<Pair<Long, String>>): Set<Long> =
    mailShown(undelivered).map { it.seq }.toSet()
}

/**
 * A workflow's part of the cognition protocol: its proposal types and how they parse, its lines
 * of the system prompt, and its lines of the rendered state. [ComposedCognitionProtocol] composes
 * it with the host's part.
 */
interface WorkflowProtocol {
  /** The shapes of this workflow's proposals, which the system prompt lists ahead of the host's. */
  val proposalShapes: List<String>

  /** The rules that end the system prompt. */
  val rules: String

  /** The proposal types [parseProposal] parses. None may be a host type. */
  val proposalTypes: Set<String>

  /** This workflow's lines of the rendered state, shown after the wake reason. */
  fun renderLines(lead: LeadState): List<String>

  /** Whether [gate] reads approved in the rendered state. */
  fun gateReadsApproved(lead: LeadState, gate: OpenGate): Boolean

  /**
   * Parses [p], a proposal of [type], one of [proposalTypes]. A near-miss is returned as
   * [ProposalParse.Malformed], never thrown.
   */
  fun parseProposal(type: String, p: JSONObject): ProposalParse
}

/**
 * The contract every model-backed [CognitionStrategy] speaks: what the model is told
 * ([systemPrompt]), how a wake's folded state is shown to it ([renderContext]), and how
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
 *
 * This class holds the host's part and composes it with [workflow]'s. It refuses a workflow that
 * claims a type the host parses, which the host's arms would otherwise shadow.
 */
class ComposedCognitionProtocol(private val workflow: WorkflowProtocol) {
  init {
    val shared = workflow.proposalTypes intersect HOST_TYPES
    require(shared.isEmpty()) { "the workflow claims proposal types the host parses: ${shared.sorted()}" }
  }

  private val PROMPT_HEADER =
    """
    You are the cognition loop of an Agency lead daemon. You are shown the lead's folded
    state once per wake. You PROPOSE; you never release gates — releases come only from
    the human authorization layer, and the journal fold rejects anything else.

    Respond with EXACTLY one JSON object, no prose around it:
    {"proposals": [
    """
      .trimIndent()

  /** The shapes of the host's own proposals, listed after the workflow's. */
  private val HOST_PROPOSAL_SHAPES =
    listOf(
      """{"type": "status", "status": "<short line>"}""",
      """{"type": "escalate", "reason": "<why a human should look>"}""",
    )

  /**
   * The header, then every proposal shape as one union (the first indented, each later one after
   * a `|`), then the closing line and the workflow's rules.
   */
  val systemPrompt =
    (listOf(PROMPT_HEADER) +
        (workflow.proposalShapes + HOST_PROPOSAL_SHAPES).mapIndexed { i, shape ->
          (if (i == 0) "   " else " | ") + shape
        } +
        """ ], "reasoning": "<one or two sentences>"}""" +
        workflow.rules)
      .joinToString("\n")

  /**
   * The wake's state as the model sees it. Every field rendered here is derived from the
   * fold, so two calls against one fold render identical text — which is what makes a
   * within-wake retry a repeat of the same question rather than a new one.
   */
  fun renderContext(context: WakeContext): String {
    val lead = context.lead
    val sb = StringBuilder()
    sb.appendLine("WAKE: ${renderReason(context.reason)}")
    for (line in workflow.renderLines(lead)) sb.appendLine(line)
    sb.appendLine(
      "openGates: " +
        lead.openGates.values
          .joinToString(", ") {
            "${it.gateId}(digest=${it.payloadDigest}, approved=${workflow.gateReadsApproved(lead, it)})"
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
    // amplify cost or dominate the context. The per-message bound is on the source text, and
    // quoting can expand it about sixfold (see [MailRender.ShownMail]). Content is data, never
    // executed — the execute-time proposal guards are what stop a hostile message causing an effect.
    for (mail in MailRender.mailShown(context.undeliveredMail)) sb.appendLine(mail.line())
    if (context.undeliveredMail.size > MailRender.MAX_MAIL_SHOWN)
      sb.appendLine("  … ${context.undeliveredMail.size - MailRender.MAX_MAIL_SHOWN} more not shown")
    if (context.undeliveredMail.isEmpty()) sb.appendLine("  none")
    return sb.toString()
  }

  /**
   * The wake reason's header line. A [WakeReason.MailArrived] is rendered WITHOUT its message:
   * the mail is untrusted, and the `undeliveredMail:` section is the one place it is shown,
   * under that section's bounds. Printing the data class through `toString` would put the
   * whole message (up to the accept bound) into the prompt, unfenced.
   */
  private fun renderReason(reason: WakeReason): String =
    when (reason) {
      is WakeReason.MailArrived ->
        "MailArrived(${reason.message.length} chars; mail still undelivered is listed under undeliveredMail)"
      else -> reason.toString()
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
   *
   * [presentation] is the caller's account of the turn [text] came from, carried onto a usable
   * output. A strategy parses only the reply of a turn that sent [renderContext] and
   * succeeded, so it passes [ContextPresentation.PRESENTED].
   */
  fun parseOutput(text: String, meta: Map<String, String>, presentation: ContextPresentation): CognitionOutput {
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
          when (val type = p.optString("type")) {
            "" -> return CognitionOutput.malformed(MalformedReasons.PROPOSAL_NO_TYPE, meta)
            // Each proposal is parsed as it is reached and appended to the one list, so the batch
            // keeps its order and the first near-miss decides the reason, whichever side owns its
            // type.
            in HOST_PARSERS -> proposals += HOST_PARSERS.getValue(type)(p)
            in workflow.proposalTypes ->
              when (val parsed = workflow.parseProposal(type, p)) {
                is ProposalParse.Ok -> proposals += parsed.proposal
                is ProposalParse.Malformed -> return CognitionOutput.malformed(parsed.reason, meta)
              }
            else -> return CognitionOutput.malformed(MalformedReasons.UNKNOWN_TYPE, meta)
          }
        }
      }
      CognitionOutput(proposals, obj.optString("reasoning"), meta, presentation = presentation)
    } catch (e: MalformedProposal) {
      CognitionOutput.malformed(e.message!!, meta)
    } catch (e: Exception) {
      // Not the message: the parser's message can quote the output it was reading.
      CognitionOutput.malformed(MalformedReasons.parseFailure(e), meta)
    }
  }

  private companion object {
    /** The host's own proposals, by type. A missing or blank field throws from [required]. */
    val HOST_PARSERS: Map<String, (JSONObject) -> Proposal> =
      mapOf(
        "status" to { p -> Proposal.ProposeStatus(p.required("status")) },
        "escalate" to { p -> Proposal.ProposeEscalate(p.required("reason")) },
      )

    /** The types the host parses or reads as "no type"; a workflow may claim none of them. */
    val HOST_TYPES = HOST_PARSERS.keys + ""
  }
}

/** What a workflow made of one proposal of a type it owns. */
sealed interface ProposalParse {
  data class Ok(val proposal: Proposal) : ProposalParse

  /** The proposal is a near-miss; [reason] is one of [MalformedReasons]. */
  data class Malformed(val reason: String) : ProposalParse
}

internal class MalformedProposal(field: String) : RuntimeException(MalformedReasons.missingField(field))

/** Demands an actual non-blank JSON string. `optString` would stringify whatever it
 * found — a number, or a whole nested object — turning a wrong-shaped field into a
 * plausible-looking value instead of the near-miss it is. */
internal fun JSONObject.required(field: String): String {
  val v = opt(field)
  if (v !is String || v.isBlank()) throw MalformedProposal(field)
  return v
}

/**
 * Every reason the lead writes on a [HostKinds.COGNITION_MALFORMED] row: [ComposedCognitionProtocol.parseOutput]'s
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

  /** The fields [ComposedCognitionProtocol.parseOutput] requires; a missing one is named. */
  val REQUIRED_FIELDS = setOf("taskRef", "gateKind", "payloadDigest", "status", "reason")

  fun missingField(field: String): String = "proposal field '$field' is missing or blank"

  /** A parse failure is named by a fixed reason, never by text taken from the exception. */
  fun parseFailure(e: Throwable): String = if (e is JSONException) PARSE_FAILURE_JSON else PARSE_FAILURE_OTHER

  private val FIXED =
    setOf(NOT_JSON, PROPOSALS_NOT_ARRAY, PROPOSAL_NOT_OBJECT, PROPOSAL_NO_TYPE, BAD_TASK_REF, UNKNOWN_GATE_KIND,
      UNKNOWN_TYPE, UNCLASSIFIED, PARSE_FAILURE_JSON, PARSE_FAILURE_OTHER) + REQUIRED_FIELDS.map(::missingField)

  fun isLeads(reason: String): Boolean = reason in FIXED
}
