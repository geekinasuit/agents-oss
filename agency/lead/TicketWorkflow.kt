package com.geekinasuit.agency.lead

import java.io.File

// The ticket workflow's own declarations: the gate kinds and phases of the ticket pipeline, the
// ticket source, and the scripted playbook that drives it.

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
