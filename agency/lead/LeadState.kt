package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED

/**
 * Lead-chain entry kinds and the lead fold.
 *
 * The lead's state machine IS this fold — state is derived, never stored. No state
 * file, no state column: recovery after any death is `leadFold(store.readAll())`.
 *
 * SCHEMA-VERSION REASONING (the reviewer-bait question answered up front): these
 * kinds carry state but do NOT bump the envelope schemaVersion. The consumption contract
 * (Fold.kt) protects PRE-EXISTING readers of a chain from silently no-op-folding a new
 * state-carrying kind. The lead chain (`agency/lead/main/v3`) is v3-BORN carrying these
 * kinds from its genesis — no earlier reader of this chain exists to protect. The shared
 * [com.geekinasuit.agency.shared.journal.fold] deliberately does not consume lead kinds:
 * it is a DIFFERENT state machine folding the same list, not a stale
 * reader. A first cross-component reader would trigger its own contract review.
 *
 * GATE RELEASES are not a lead kind: the lead REUSES the shared [KIND_GATE_RELEASED] and
 * honors a release only when provenance, binding, AND nonce discipline all hold — origin
 * must be the authorization layer (the shared fold's rule, re-asserted here), the
 * release's digest must match the opened gate's payload digest, and the single-use nonce
 * rules in [foldRelease] must pass. An authorization-origin release that fails binding or
 * nonce discipline is retained VISIBLY in [HostState.staleReleases] and the gate stays
 * pending — never silently dropped, never honored (a release binds to the exact artifact
 * the approver saw, once).
 *
 * The nonce/approval kinds ([LeadKinds.NONCE_ISSUED], [LeadKinds.NONCE_CONSUMED],
 * [LeadKinds.APPROVAL_RECORDED]) extend this chain's vocabulary under the same
 * schema-version reasoning as the original kinds: the lead chain's one reader is the lead
 * fold, which consumes them; the shared fold remains a different state machine that
 * deliberately does not. A lead binary predating these kinds folds them away and derives
 * a state without nonce views — and that binary UNDER-ENFORCES: fold a journal in which a
 * nonce was minted, consumed by a release, and the release replayed, and the old binary
 * honors the replay this fold refuses (gate and digest still match; nothing else is
 * checked). Its own semantics are unchanged, but it reaches a different verdict on the
 * same journal, so a rollback across this commit reopens the replay window once nonces
 * are being minted (step 2+) — it does not merely lose a view. The tightened release rule
 * exists only in binaries that also know the kinds.
 */
object LeadKinds {
  // Every kind of a ticket lead's chain, by its old name: the host's ([HostKinds]) and the ticket
  // workflow's ([TicketKinds]). Host code names the host's kinds through [HostKinds].
  const val RUN_STARTED = HostKinds.RUN_STARTED
  const val TICKET_CLAIMED = TicketKinds.TICKET_CLAIMED
  const val PLAN_REQUESTED = TicketKinds.PLAN_REQUESTED
  const val PLAN_ARTIFACT_RECORDED = TicketKinds.PLAN_ARTIFACT_RECORDED
  const val COMMIT_PROPOSED = TicketKinds.COMMIT_PROPOSED
  const val STATUS_WRITTEN = HostKinds.STATUS_WRITTEN
  const val TICKET_DONE = TicketKinds.TICKET_DONE
  const val ESCALATED = HostKinds.ESCALATED
  const val GATE_OPENED = HostKinds.GATE_OPENED
  const val GATE_OPEN_NOTIFIED = HostKinds.GATE_OPEN_NOTIFIED
  const val POD_SPAWNED = HostKinds.POD_SPAWNED
  const val POD_RESULT_RECORDED = HostKinds.POD_RESULT_RECORDED
  const val POD_ABANDONED = HostKinds.POD_ABANDONED
  const val POD_SPAWN_INTENDED = HostKinds.POD_SPAWN_INTENDED
  const val POD_SPAWN_ABANDONED = HostKinds.POD_SPAWN_ABANDONED
  const val POD_EVENT = HostKinds.POD_EVENT
  const val COGNITION_PROPOSED = HostKinds.COGNITION_PROPOSED
  const val COGNITION_MALFORMED = HostKinds.COGNITION_MALFORMED
  const val NONCE_ISSUED = HostKinds.NONCE_ISSUED
  const val NONCE_CONSUMED = HostKinds.NONCE_CONSUMED
  const val APPROVAL_RECORDED = HostKinds.APPROVAL_RECORDED
}

/** A ticket lead's own state: the current ticket, its phase, its recorded plan and manifest, and the
 * tickets done. The host's records (gates, releases, nonces, approvals, pods, escalations, spend)
 * are not here: the host keeps them ([HostState]), and decisions that need one read it there
 * ([approvedOnEvidence], [approvedToCommit]). */
data class LeadState(
  val currentTicket: String? = null,
  val phase: TicketPhase = TicketPhase.IDLE,
  val planArtifactPath: String? = null,
  val planArtifactSha: String? = null,
  val commitManifestPath: String? = null,
  val commitManifestDigest: String? = null,
  val doneTickets: List<String> = emptyList(),
) {
  /** The digest recorded as the evidence a gate of [gateKind] binds to, in whatever form the
   * journal holds it: the plan artifact's for the plan gate, the commit manifest's for the commit
   * gate, none for any other kind or while none is recorded. */
  fun recordedEvidence(gateKind: String): String? =
    when (gateKind) {
      GateKinds.PLAN_APPROVAL -> planArtifactSha
      GateKinds.COMMIT_APPROVAL -> commitManifestDigest
      else -> null
    }

  /** The digest the substrate recorded as the evidence a gate of [gateKind] binds to
   * ([recordedEvidence]). A gate opens only on this digest, and a gate-open's nonce is minted only
   * while the gate's digest still equals it. A recorded digest counts only in the form the
   * substrate records one, and any other counts as none: a digest in another form was not recorded
   * by the substrate, and a nonce bound to a blank one would make every later fold of the journal
   * fail. */
  fun evidenceDigest(gateKind: String): String? =
    recordedEvidence(gateKind)?.takeIf { SHA256_HEX_RE.matches(it) }

  /** Why a gate of [gateKind] open on [digest] is not open on the substrate's evidence for that kind,
   * or null when it is. Evidence must be recorded for the kind in the form the substrate records it
   * ([evidenceDigest]), and [digest] must be that evidence. A digest that fails the check came from
   * a journal the lead did not write, so the reason gives its length, never its text. */
  internal fun evidenceMismatch(gateKind: String, digest: String): String? {
    val evidence = evidenceDigest(gateKind)
    return when {
      recordedEvidence(gateKind) == null -> "no evidence is recorded for its kind"
      evidence == null -> "the evidence recorded for its kind is not in the form the substrate records"
      digest != evidence ->
        "its digest of ${digest.length} chars is not the recorded evidence ${evidence.take(16)}"
      else -> null
    }
  }

  /** Whether the [gateKind] gate of [ticket] is approved on the digest it is open on now, and that
   * digest is the substrate's evidence for its kind ([evidenceDigest]). The gate and its releases
   * are read from [records], the host's own. Everything that decides on an approval asks this, not
   * [HostView.approvedOnCurrentDigest] alone: the daemon before it acts, and cognition before it
   * proposes. The lead opens a gate only on its evidence, so a gate open on any other digest came
   * from a journal the lead did not write, and a release on that digest approves nothing the
   * substrate recorded. */
  fun approvedOnEvidence(records: HostView, gateKind: String, ticket: String): Boolean {
    val gateId = gateIdFor(gateKind, ticket)
    val evidence = evidenceDigest(gateKind) ?: return false
    return records.openGates[gateId]?.payloadDigest == evidence && records.approvedOnCurrentDigest(gateId)
  }

  /** Whether the commit effect may fire for [ticket]: its commit gate is approved on the recorded
   * manifest and its plan gate on the recorded plan ([approvedOnEvidence]). The daemon asks this
   * before it journals the effect's intent, and again before adopt re-fires an intent a crash cut
   * short. */
  fun approvedToCommit(records: HostView, ticket: String): Boolean =
    approvedOnEvidence(records, GateKinds.COMMIT_APPROVAL, ticket) &&
      approvedOnEvidence(records, GateKinds.PLAN_APPROVAL, ticket)
}

/** The form the substrate records an evidence digest in: [sha256HexBytes]'s lowercase hex. */
private val SHA256_HEX_RE = Regex("[0-9a-f]{64}")

/**
 * The lead state machine: `leadState = leadFold(entries, auth)`. Folds the SAME entry list
 * the shared fold consumes — two folds, one list; composition, not extension.
 *
 * Each entry folds in two steps: the host's ([hostStep]) and then the ticket workflow's
 * ([ticketWorkflowStep]), which sees what the host step did with the entry. The result is
 * assembled into one [LeadState].
 *
 * RECOVERY CONTRACT (widened by 2b): folded state is now a function of the journal AND
 * [auth]. Approvals re-verify at fold time and a ceremony release gates on a quorum over the
 * VERIFIED approvers (the host's release fold), so the same journal can fold to a DIFFERENT
 * verdict under a different [LeadAuth]: revoke a principal from the allow-list (or install a
 * stricter quorum) and re-fold, and a gate that reached quorum before may no longer — its
 * release folds stale, the gate drops out of [HostState.releasedGates], and the phase never
 * reaches the approved state it did under the old auth. That is deliberate — authorization
 * is not frozen into the journal at write time; it is re-decided on the allow-list and
 * quorum in force at recovery. [auth] is required, with no default: which principals and
 * quorum a fold verifies against is a security-load-bearing choice, and a silent default
 * would be the footgun this parameter exists to refuse. A substrate not yet wired for the
 * ceremony passes [LeadAuth.DENY_ALL] explicitly.
 */
fun leadFold(entries: List<JournalEntry>, auth: LeadAuth): LeadState =
  foldLeadJournal(entries, auth, TicketWorkflowFold)

/** The host's records of a ticket lead's journal, folded beside [leadFold]'s state under [auth]. */
internal fun leadHostFold(entries: List<JournalEntry>, auth: LeadAuth): HostState =
  foldHostAndLead(entries, auth, TicketWorkflowFold).first

/** The ticket workflow's half of the lead fold. */
internal object TicketWorkflowFold : WorkflowFold<LeadState, TicketWorkflowState> {
  override val substrateKinds: Set<String> = TICKET_WORKFLOW_SUBSTRATE_KINDS
  override val scopeEndKinds: Set<String> = TICKET_WORKFLOW_SCOPE_END_KINDS
  override val start = TicketWorkflowState()

  override fun expectedTaskRefs(w: TicketWorkflowState): Set<String> = w.expectedTaskRefs()

  override fun step(w: TicketWorkflowState, e: JournalEntry, outcome: HostOutcome): TicketWorkflowState =
    ticketWorkflowStep(w, e, outcome)

  override fun assemble(host: HostState, w: TicketWorkflowState): LeadState = assembleLeadState(host, w)
}

private fun assembleLeadState(h: HostState, w: TicketWorkflowState): LeadState =
  LeadState(
    currentTicket = w.currentTicket,
    phase = w.phase,
    planArtifactPath = w.planArtifactPath,
    planArtifactSha = w.planArtifactSha,
    commitManifestPath = w.commitManifestPath,
    commitManifestDigest = w.commitManifestDigest,
    doneTickets = w.doneTickets,
  )
