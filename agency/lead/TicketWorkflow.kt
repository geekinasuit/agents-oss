package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.payloadObject
import com.geekinasuit.agency.shared.journal.requireContract
import java.io.File
import kotlinx.serialization.json.JsonPrimitive

// The ticket workflow's own declarations: the gate kinds and phases of the ticket pipeline, its
// half of the lead fold, the ticket source, and the scripted playbook that drives it.

/** Gate kinds the ticket pipeline opens. */
object GateKinds {
  const val PLAN_APPROVAL = "plan-approval"
  const val COMMIT_APPROVAL = "commit-approval"

  /** Every kind above: a gate of any other kind is never opened. */
  val ALL: Set<String> = setOf(PLAN_APPROVAL, COMMIT_APPROVAL)
}

/** Where the current ticket stands — derived progressively by the fold, one hop per entry. */
enum class TicketPhase {
  IDLE,
  CLAIMED,
  PLAN_REQUESTED,
  PLANNING, // planner pod spawned
  PLAN_RECORDED,
  PLAN_GATED,
  PLAN_APPROVED,
  EXECUTING, // execute pod spawned
  EXECUTED,
  COMMIT_PROPOSED,
  COMMIT_GATED,
  COMMIT_APPROVED,
}

/**
 * The ticket workflow's half of the lead fold: the current ticket, its phase, the evidence the
 * pipeline recorded, and the tickets done. Each field means what the [LeadState] field of the same
 * name means; [leadFold] assembles a [LeadState] from this and a [HostState].
 */
internal data class TicketWorkflowState(
  val currentTicket: String? = null,
  val phase: TicketPhase = TicketPhase.IDLE,
  val planArtifactPath: String? = null,
  val planArtifactSha: String? = null,
  val commitManifestPath: String? = null,
  val commitManifestDigest: String? = null,
  val doneTickets: List<String> = emptyList(),
) {
  /** The pod task refs the workflow intends while this ticket is current: its plan and execute
   * pods. The host reads it to describe an orphaned spawn intent. */
  fun expectedTaskRefs(): Set<String> =
    currentTicket?.let { setOf("plan:$it", "execute:$it") } ?: emptySet()
}

/** The ticket workflow's substrate-only kinds, policed by the host's provenance gate. */
internal val TICKET_WORKFLOW_SUBSTRATE_KINDS =
  setOf(
    LeadKinds.TICKET_CLAIMED,
    LeadKinds.PLAN_REQUESTED,
    LeadKinds.PLAN_ARTIFACT_RECORDED,
    LeadKinds.COMMIT_PROPOSED,
    LeadKinds.TICKET_DONE,
  )

/** Whether [e] ends the ticket workflow's scope: a ticket is done. The host clears its scoped
 * records on it. */
internal fun isTicketScopeEnd(e: JournalEntry): Boolean = e.kind == LeadKinds.TICKET_DONE

/** Well-formed ticket refs: a ticket ref is untrusted input (a fixture line today, a real
 * ticket-index row later) that flows into task refs, gate ids, and effect keys. A conservative
 * charset — ':' and '/' excluded, so it can forge neither a task namespace nor a path — plus a
 * length bound keeps a malformed ref from wedging the pipeline or polluting a namespace. */
private val TICKET_REF_RE = Regex("[A-Za-z0-9._-]+")
private const val MAX_TICKET_REF_LEN = 128

/** Whether the claim accepts [ref]: in [TICKET_REF_RE]'s charset and at most [MAX_TICKET_REF_LEN]
 * chars. The claim journals only a ref that passes, as a JSON string. The fold refuses a
 * substrate-origin claim of any other ref, and records a claim of any other origin in
 * [LeadState.misOriginedEntries] before it reads the ref. The claim and the fold check this one
 * predicate, since a fold stricter than the claim would refuse a journal the lead wrote itself.
 * Widening the predicate keeps every journal already written foldable. Tightening it makes the
 * fold refuse claims already journaled, so it needs a migration of those journals. */
internal fun isClaimableTicketRef(ref: String): Boolean =
  TICKET_REF_RE.matches(ref) && ref.length <= MAX_TICKET_REF_LEN

/**
 * Folds one entry into the ticket workflow's state, after the host step has folded it. [outcome]
 * is what the host did with the entry: a rejected entry changes nothing here, and host events
 * (a gate opened or released, a pod spawned or its result recorded) move the phase.
 */
internal fun ticketWorkflowStep(w: TicketWorkflowState, e: JournalEntry, outcome: HostOutcome): TicketWorkflowState =
  when (outcome) {
    HostOutcome.Rejected -> w
    is HostOutcome.GateOpened ->
      w.copy(
        phase =
          when (outcome.gate.gateKind) {
            GateKinds.PLAN_APPROVAL -> TicketPhase.PLAN_GATED
            GateKinds.COMMIT_APPROVAL -> TicketPhase.COMMIT_GATED
            else -> w.phase
          }
      )
    is HostOutcome.GateReleased ->
      w.copy(
        phase =
          when (outcome.gate.gateKind) {
            GateKinds.PLAN_APPROVAL -> TicketPhase.PLAN_APPROVED
            GateKinds.COMMIT_APPROVAL -> TicketPhase.COMMIT_APPROVED
            else -> w.phase
          }
      )
    is HostOutcome.PodSpawned ->
      w.copy(
        phase =
          when {
            outcome.pod.taskRef.startsWith("plan:") && w.phase == TicketPhase.PLAN_REQUESTED ->
              TicketPhase.PLANNING
            outcome.pod.taskRef.startsWith("execute:") && w.phase == TicketPhase.PLAN_APPROVED ->
              TicketPhase.EXECUTING
            else -> w.phase
          }
      )
    is HostOutcome.PodResultRecorded ->
      w.copy(
        phase =
          if (outcome.pod.taskRef.startsWith("execute:") && w.phase == TicketPhase.EXECUTING)
            TicketPhase.EXECUTED
          else w.phase
      )
    HostOutcome.Folded -> ticketKindStep(w, e)
  }

private fun ticketKindStep(w: TicketWorkflowState, e: JournalEntry): TicketWorkflowState {
  if (e.kind !in TICKET_WORKFLOW_SUBSTRATE_KINDS) return w
  val p = payloadObject(e.payloadJson)
  return when (e.kind) {
    LeadKinds.TICKET_CLAIMED -> {
      // The claim journals only a ref it accepts, as a JSON string, so a claim of any other came
      // from a writer other than the lead. Gate ids, task refs and effect keys are derived from
      // the claimed ref, so such a claim is refused, not held. One check covers the field's type,
      // charset and length, and like every refusal here its message leaves the ref out.
      val ref = p["ticketRef"]
      requireContract(ref is JsonPrimitive && ref.isString && isClaimableTicketRef(ref.content)) {
        "claimed ticket ref is not a JSON string in the claim's charset of at most " +
          "$MAX_TICKET_REF_LEN chars"
      }
      w.copy(currentTicket = ref.content, phase = TicketPhase.CLAIMED)
    }
    LeadKinds.PLAN_REQUESTED -> w.copy(phase = TicketPhase.PLAN_REQUESTED)
    LeadKinds.PLAN_ARTIFACT_RECORDED ->
      w.copy(
        planArtifactPath = p.str("path"),
        planArtifactSha = p.str("sha256"),
        phase = TicketPhase.PLAN_RECORDED,
      )
    LeadKinds.COMMIT_PROPOSED ->
      w.copy(
        commitManifestPath = p.str("manifestPath"),
        commitManifestDigest = p.str("manifestDigest"),
        phase = TicketPhase.COMMIT_PROPOSED,
      )
    // The host has cleared its scoped records; the workflow's own are the ticket's evidence.
    // doneTickets (small refs) persists as the running record.
    LeadKinds.TICKET_DONE ->
      w.copy(
        doneTickets = w.doneTickets + p.str("ticketRef"),
        currentTicket = null,
        phase = TicketPhase.IDLE,
        planArtifactPath = null,
        planArtifactSha = null,
        commitManifestPath = null,
        commitManifestDigest = null,
      )
    else -> w
  }
}

/** The reason [ScriptedCognition] escalates a stale release with. */
private const val STALE_RELEASE_REASON = "stale gate release observed (digest mismatch)"

/**
 * Deterministic playbook on [WakeContext] predicates: drives the full ticket
 * walk — claim (substrate) → plan pod → plan gate → execute pod → commit gate → done
 * (substrate) — with zero model involvement, so every CI path is deterministic. This is
 * the deterministic half of the coverage; [ClaudeCognition] is the model-backed half.
 *
 * Predicates key on EVIDENCE (artifact present, gate open, an active pod exists), not on
 * strict phase progression — so the playbook is idempotent across wakes and self-heals
 * after kill-recovery abandons a pod mid-flight: the missing evidence simply gets
 * re-proposed. [LeadState.phase] stays the observability surface tests assert on.
 */
class ScriptedCognition : CognitionStrategy {
  override val name = "scripted"

  override fun decide(context: WakeContext): CognitionOutput {
    val lead = context.lead
    val ticket = lead.currentTicket ?: return IDLE

    // A stale release is escalated once. The check looks for that escalation only, so an escalation
    // of another kind, such as a gate-open no sink announced, does not silence it. The escalations
    // are a capped tail: once enough later ones push this one out, it is raised again.
    if (lead.staleReleases.isNotEmpty() && STALE_RELEASE_REASON !in lead.escalations) {
      return decided(
        listOf(Proposal.ProposeEscalate(STALE_RELEASE_REASON)),
        "a release did not match the gate as opened; a human should look",
      )
    }

    val planGate = lead.openGates[gateIdFor(GateKinds.PLAN_APPROVAL, ticket)]
    val commitGate = lead.openGates[gateIdFor(GateKinds.COMMIT_APPROVAL, ticket)]
    val planApproved = lead.approvedOnEvidence(GateKinds.PLAN_APPROVAL, ticket)
    fun activePodFor(taskRef: String) = lead.activePods.any { it.taskRef == taskRef }

    return when {
      lead.planArtifactSha == null && !activePodFor("plan:$ticket") ->
        decided(
          listOf(
            Proposal.ProposePodSpawn("plan:$ticket"),
            Proposal.ProposeStatus("planning $ticket"),
          ),
          "no plan artifact and no planner in flight; spawning a planner pod",
        )
      lead.planArtifactSha != null && planGate == null ->
        decided(
          listOf(
            Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, lead.planArtifactSha),
            Proposal.ProposeStatus("plan ready for approval: $ticket"),
          ),
          "plan artifact recorded; opening the plan-approval gate on its digest",
        )
      planApproved && lead.commitManifestDigest == null && !activePodFor("execute:$ticket") ->
        decided(
          listOf(
            Proposal.ProposePodSpawn("execute:$ticket"),
            Proposal.ProposeStatus("executing $ticket"),
          ),
          "plan approved and no manifest yet; spawning the execute pod",
        )
      lead.commitManifestDigest != null && commitGate == null ->
        decided(
          listOf(
            Proposal.ProposeGateOpen(GateKinds.COMMIT_APPROVAL, lead.commitManifestDigest),
            Proposal.ProposeStatus("commit ready for approval: $ticket"),
          ),
          "commit manifest proposed; opening the commit-approval gate on its digest",
        )
      else -> IDLE // waiting on a gate to be authorized or a pod to finish
    }
  }

  private companion object {
    /** The playbook decides from the structured context itself, with no render in between, so
     * every decision it makes, idling included, was made with that context in front of it. */
    val IDLE = CognitionOutput.idle(ContextPresentation.PRESENTED)

    fun decided(proposals: List<Proposal>, reasoning: String) =
      CognitionOutput(proposals, reasoning, presentation = ContextPresentation.PRESENTED)
  }
}

/** Deterministic gate identity: one gate per (kind, ticket) — idempotent across re-proposals. */
fun gateIdFor(gateKind: String, ticketRef: String): String = "$gateKind:$ticketRef"

/** Ticket offer seam: a fixture file today; real ticket-index ops come later. */
fun interface TicketSource {
  /** The next ticket ref on offer that is not in [done], or null when the source is
   * exhausted. [done] is the fold's completed-ticket set — passing it in keeps the source
   * stateless and the offer replay-deterministic (same journal, same offer), and is what
   * lets a multi-ticket source progress: without it, a source has no way to stop
   * re-offering a completed ref. Progression covers refs that complete, deliberately: a
   * ref the claim boundary rejects is escalated and never claimed, so it never enters
   * [done] and stays the head offer — a malformed line parks the source visibly (one
   * escalation per idle wake) until the operator fixes it, rather than being silently
   * skipped. Offering is idempotent, and the source stays untrusted:
   * the daemon still filters done refs and claims at most one at a time. */
  fun next(done: Set<String>): String?
}

class FileTicketSource(private val file: File) : TicketSource {
  override fun next(done: Set<String>): String? =
    if (file.exists()) {
      file.readLines().map { it.trim() }.firstOrNull { it.isNotEmpty() && it !in done }
    } else null
}
