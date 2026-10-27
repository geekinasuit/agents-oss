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
 * nonce discipline is retained VISIBLY in [LeadState.staleReleases] and the gate stays
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

data class LeadState(
  val runsStarted: Int = 0,
  val currentTicket: String? = null,
  val phase: TicketPhase = TicketPhase.IDLE,
  val planArtifactPath: String? = null,
  val planArtifactSha: String? = null,
  val commitManifestPath: String? = null,
  val commitManifestDigest: String? = null,
  override val openGates: Map<String, OpenGate> = emptyMap(),
  val releasedGates: Set<String> = emptySet(),
  /** For each gate, the payload digests it has ALREADY been released on — the epoch-precise
   * single-release guard. [releasedGates] answers "released at all this ticket?" (gate-keyed,
   * epoch-blind); this answers "released on THIS digest?", the question that stops a decided
   * gate being cleared a second time by a fresh, valid, never-consumed nonce minted for the
   * same digest, while still admitting the legitimate re-release of a gate re-opened on a NEW
   * digest (a distinct authorization surface). A Set per gate, not one digest, so a digest
   * revisited across re-opens is still caught. Correctness-bearing (evicting an entry
   * re-enables a re-release), so it sits outside [ANOMALY_TAIL] and is bounded by the ticket:
   * [LeadKinds.TICKET_DONE] clears it, as it does [nonceLessReleases]. */
  val releasedDigests: Map<String, Set<String>> = emptyMap(),
  /** Gates released by the nonce-less pre-ceremony path, keyed to the seq of the RELEASE
   * the mark describes — the disposition marker that keeps "was this release under the
   * ceremony?" answerable from derived state, matching how every other classification
   * this fold makes stays legible after the fact. Keyed by seq so the journal-level
   * re-open shape stays unambiguous: a re-opened gate later released under the ceremony
   * keeps its old mark, and the mark's seq says which release it describes (never the
   * current one). */
  val nonceLessReleases: Map<String, Long> = emptyMap(),
  override val staleReleases: List<Pair<Long, String>> = emptyList(), // (seq, open gate's id, or "an unknown gate id of N chars") — auth origin, but digest mismatch, unknown gate, or nonce indiscipline (consumed/unknown/misbound/absent-where-required)
  /** Every nonce issued this ticket, by value — consumed ones stay listed ([consumedNonces]
   * marks them) so a re-issue of a spent value is detectable as the anomaly it is. */
  override val issuedNonces: Map<String, IssuedNonce> = emptyMap(),
  val consumedNonces: Set<String> = emptySet(),
  /** Nonces whose gate-open announce is final ([LeadKinds.GATE_OPEN_NOTIFIED] without `retry`):
   * announced, not announced because no sink is wired or the artifact could not be inlined, or
   * failed on its last attempt. Keyed by the NONCE, not the gate: a nonce is single-use and bound
   * to one (gate, digest), so a gate re-opened on a new digest mints a NEW nonce and is announced
   * afresh, while a final one is never announced again. The notify arm reads this to stop; a
   * marker that says the announce will be sent again counts in [failedAnnounces] instead.
   * Ticket-scoped: [LeadKinds.TICKET_DONE] clears it, as it does [issuedNonces]. */
  override val notifiedNonces: Set<String> = emptySet(),
  /** Nonce → how many of its announces failed with a failure the sink reported, each marked to be
   * sent again ([LeadKinds.GATE_OPEN_NOTIFIED] with `retry`). The notify arm reads it to find the
   * timer the next attempt waits on, and the daemon to number that attempt, so a failing sink is
   * called once per attempt, never once per pass. [notifiedNonces] takes precedence: a nonce in it
   * is not sent again whatever this holds. Ticket-scoped: [LeadKinds.TICKET_DONE] clears it. */
  override val failedAnnounces: Map<String, Int> = emptyMap(),
  /** Nonce → how many of the attempts in [failedAnnounces] were not attempts at all: the bound copy
   * was not read, for a cause outside it (a marker with `notRead`). The daemon counts only the
   * rest toward the bound on a failing sink's attempts. Ticket-scoped: [LeadKinds.TICKET_DONE]
   * clears it. */
  override val notReadAnnounces: Map<String, Int> = emptyMap(),
  /** gateId → approvals that RE-VERIFIED at fold time (signature over preimage, key in the
   * allow-list, committed binding agreeing with the flat copies). The set a release's quorum
   * is evaluated over — an approval that did not verify never lands here, so the flat
   * `principalId` a record claimed can no longer stuff a quorum. Auth-layer-authored entries
   * only; dedup is by the PREIMAGE-DERIVED (principal, nonce, digest), so re-delivery of the
   * same approval is idempotent while a re-approval under a fresh nonce accumulates. */
  val verifiedApprovals: Map<String, List<VerifiedApproval>> = emptyMap(),
  /** (seq, reason) for approval entries that did NOT verify — no evidence, no signed
   * preimage, a preimage that did not parse, a signature that did not check out, a signer not
   * in the allow-list, or a committed field disagreeing with a flat copy. Kept VISIBLE
   * (never silently dropped), capped like the other anomaly tails, and cleared at
   * [LeadKinds.TICKET_DONE] — the one approval-derived view bounded by a tail rather than
   * correctness, because an unverified approval contributes nothing a release depends on. */
  val unverifiedApprovals: List<Pair<Long, String>> = emptyList(),
  override val pods: Map<String, PodRecord> = emptyMap(),
  override val pendingSpawnIntents: Map<String, Long> = emptyMap(), // taskRef → intent seq: spawn journaled, POD_SPAWNED not yet
  val misOriginedEntries: List<Pair<Long, String>> = emptyList(), // (seq, kind): substrate-authored kind with a non-substrate origin — never honored
  val statusTail: List<String> = emptyList(),
  override val escalations: List<String> = emptyList(),
  /** Gate id → the digests the gate was escalated on this ticket as holding up the stage it guards.
   * A gate is escalated on a digest in four cases: it is open on the digest under a ceremony auth
   * with no usable nonce, one the mint issues none for, and not released on it; it is open on the
   * digest under an auth with no approvers, holds an issued nonce, and is not released on it, so no
   * release can clear it; it is released on the digest, and the digest is not the substrate's
   * evidence for its kind; or it is the plan gate, open on a digest that is not the recorded plan,
   * when an execute pod is proposed. The record keeps the gate and digest, not the case, so a gate
   * escalated on a digest for one case is not escalated on it again for another. Read from the
   * gate and digest an [LeadKinds.ESCALATED] row names beside its reason, so the escalation and its
   * record are one append. The daemon reads it to escalate each gate and digest once, across
   * restarts, which the capped [escalations] tail cannot promise. Ticket-scoped:
   * [LeadKinds.TICKET_DONE] clears it. */
  override val escalatedStalls: Map<String, Set<String>> = emptyMap(),
  /** The pending effect intents adopt declined to re-fire and escalated, each as the SHA-256 of its
   * key's UTF-8 text: a key comes from the journal, of any length, so the record holds a digest of
   * fixed size. Read from the digest an [LeadKinds.ESCALATED] row names beside its reason. The
   * daemon reads it to escalate each declined intent once, across restarts. Not ticket-scoped: a
   * declined intent stays pending, and every adopt meets it again, whichever ticket is current.
   *
   * No field of a row is evidence the lead wrote it. An escalation row with the substrate's origin
   * that the lead did not write can name an intent's digest before adopt declines the intent, and
   * adopt then does not escalate it: the intent stays pending, unfired and unnamed.
   * [escalatedStalls] is silenced the same way. An escalation row with any other origin is never
   * honored. This record does not try to be stronger than the journal: a writer that can use the
   * substrate's origin can already append any substrate row, [LeadKinds.TICKET_DONE] among them,
   * and the shared fold reads `effect-intent` and `effect-done` rows without their origin, so an
   * `effect-done` row of any origin already takes an intent out of adopt's view. Adopt never fires
   * such an intent. The lead's own commit intent is still fired by the commit arm, which records its
   * ticket done only once the effect receiver has seen its key. */
  override val declinedEffects: Set<String> = emptySet(),
  /** (seq, reason) for turns whose output was unusable — the degradation signal, kept apart
   * from [escalations] so a degrading model is countable rather than merely noisy. */
  val malformedCognition: List<Pair<Long, String>> = emptyList(),
  val doneTickets: List<String> = emptyList(),
  /** Journal-derived total model spend: the sum of costUsd across journaled cognition
   * decisions. The budget guard reads THIS, not an in-memory counter — restarts keep it. */
  override val cognitionSpendUsd: Double = 0.0,
) : HostView {
  val pendingGates: List<OpenGate>
    get() = openGates.values.filter { it.gateId !in releasedGates }.sortedBy { it.openedSeq }

  override val activePods: List<PodRecord>
    get() = pods.values.filter { it.active }.sortedBy { it.spawnedSeq }

  fun gate(gateKind: String): OpenGate? = openGates.values.firstOrNull { it.gateKind == gateKind }

  /** Whether [gateId] is approved ON THE DIGEST IT IS CURRENTLY OPEN ON — the epoch-precise
   * approval question every release CONSUMER must ask. [releasedGates] answers only "released
   * at all this ticket?" (gate-keyed, epoch-blind), which a gate re-opened on a NEW digest — a
   * distinct authorization surface — answers stale-true; deciding whether to ACT on an approval
   * (advance the pipeline, launch the executor, drive the commit effect) must instead confirm
   * the digest the gate is open on NOW was the one released. Acting also needs that digest to
   * be the evidence the substrate recorded for the gate's kind, which this does not check: a
   * gate open and released on any other digest approves nothing the substrate recorded, so
   * whatever decides on an approval asks [approvedOnEvidence], which checks both. The read-side
   * mirror of [foldRelease]'s single-release guard — both test `payloadDigest in
   * releasedDigests[gateId]`. Fail-closed: a gate not open is not approved. [pendingGates]
   * deliberately keeps the epoch-blind [releasedGates] read; "do not re-surface a gate released
   * at all this ticket" is a different question. */
  override fun approvedOnCurrentDigest(gateId: String): Boolean {
    val gate = openGates[gateId] ?: return false
    return gate.payloadDigest in releasedDigests[gateId].orEmpty()
  }

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
   * digest is the substrate's evidence for its kind ([evidenceDigest]). Everything that decides on
   * an approval asks this, not [approvedOnCurrentDigest] alone: the daemon before it acts, and
   * cognition before it proposes. The lead opens a gate only on its evidence, so a gate open on any
   * other digest came from a journal the lead did not write, and a release on that digest approves
   * nothing the substrate recorded. */
  fun approvedOnEvidence(gateKind: String, ticket: String): Boolean {
    val gateId = gateIdFor(gateKind, ticket)
    val evidence = evidenceDigest(gateKind) ?: return false
    return openGates[gateId]?.payloadDigest == evidence && approvedOnCurrentDigest(gateId)
  }

  /** Whether the commit effect may fire for [ticket]: its commit gate is approved on the recorded
   * manifest and its plan gate on the recorded plan ([approvedOnEvidence]). The daemon asks this
   * before it journals the effect's intent, and again before adopt re-fires an intent a crash cut
   * short. */
  fun approvedToCommit(ticket: String): Boolean =
    approvedOnEvidence(GateKinds.COMMIT_APPROVAL, ticket) &&
      approvedOnEvidence(GateKinds.PLAN_APPROVAL, ticket)

  /** The gate's currently-usable nonce: issued for THIS gate, bound to the digest the
   * gate is CURRENTLY open on, and not consumed — the same clauses [foldRelease] honors,
   * so a nonce returned here is releasable as it stands (the digest filter matches
   * [boundApprovers]', for the same reason: a nonce bound to a superseded digest can only
   * fold stale, and handing it to a notifier would be a silent liveness failure). Latest
   * by issue order if several are open (the release names its nonce explicitly, so
   * "latest" is a convenience for issuers, not an ambiguity at verification). */
  override fun openNonceFor(gate: OpenGate): IssuedNonce? =
    issuedNonces.values
      .filter {
        it.gateId == gate.gateId &&
          it.payloadDigest == gate.payloadDigest &&
          it.nonce !in consumedNonces
      }
      .maxByOrNull { it.issuedSeq }

  /** Preimage-derived principals whose VERIFIED approval binds the gate AS IT STANDS — same
   * digest the gate is open on, same [nonce] — the set a quorum predicate is evaluated over.
   * Verified approvals bound to a superseded digest or a different nonce are present in
   * [verifiedApprovals] but excluded here; approvals that never verified are absent entirely. */
  fun boundApprovers(gate: OpenGate, nonce: String): Set<String> =
    boundApprovers(verifiedApprovals, gate, nonce)

  /**
   * The latest NON-abandoned pod for a task ref, or null. Abandoned pods are excluded
   * deliberately: an abandoned pod is no longer evidence — its
   * artifact was missing, or it was dropped on restart. Including it caused a boot-loop
   * when a result was recorded but the file was absent (verify → abandon → the mechanical
   * pass re-selected the SAME record → re-verify → re-abandon, until the fixpoint guard
   * threw and a fresh adopt re-folded into the same crash). Filtering here means an
   * abandoned pod stops being selectable, the mechanical pass reaches its fixpoint, and the
   * evidence-based playbook re-proposes a fresh pod. It also closes the late-completion path
   * (a delayed result for an abandoned pod can no longer drive plan/commit recording).
   */
  fun podFor(taskRef: String): PodRecord? =
    pods.values
      .filter { it.taskRef == taskRef && it.abandonedReason == null }
      .maxByOrNull { it.spawnedSeq }
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
 * release folds stale, the gate drops out of [LeadState.releasedGates], and the phase never
 * reaches the approved state it did under the old auth. That is deliberate — authorization
 * is not frozen into the journal at write time; it is re-decided on the allow-list and
 * quorum in force at recovery. [auth] is required, with no default: which principals and
 * quorum a fold verifies against is a security-load-bearing choice, and a silent default
 * would be the footgun this parameter exists to refuse. A substrate not yet wired for the
 * ceremony passes [LeadAuth.DENY_ALL] explicitly.
 */
fun leadFold(entries: List<JournalEntry>, auth: LeadAuth): LeadState =
  foldLeadJournal(
    entries,
    auth,
    workflowKinds = TICKET_WORKFLOW_SUBSTRATE_KINDS,
    isScopeEnd = ::isTicketScopeEnd,
    workflowStart = TicketWorkflowState(),
    expectedTaskRefs = TicketWorkflowState::expectedTaskRefs,
    workflowStep = ::ticketWorkflowStep,
    assemble = ::assemble,
  )

private fun assemble(h: HostState, w: TicketWorkflowState): LeadState =
  LeadState(
    runsStarted = h.runsStarted,
    currentTicket = w.currentTicket,
    phase = w.phase,
    planArtifactPath = w.planArtifactPath,
    planArtifactSha = w.planArtifactSha,
    commitManifestPath = w.commitManifestPath,
    commitManifestDigest = w.commitManifestDigest,
    openGates = h.openGates,
    releasedGates = h.releasedGates,
    releasedDigests = h.releasedDigests,
    nonceLessReleases = h.nonceLessReleases,
    staleReleases = h.staleReleases,
    issuedNonces = h.issuedNonces,
    consumedNonces = h.consumedNonces,
    notifiedNonces = h.notifiedNonces,
    failedAnnounces = h.failedAnnounces,
    notReadAnnounces = h.notReadAnnounces,
    verifiedApprovals = h.verifiedApprovals,
    unverifiedApprovals = h.unverifiedApprovals,
    pods = h.pods,
    pendingSpawnIntents = h.pendingSpawnIntents,
    misOriginedEntries = h.misOriginedEntries,
    statusTail = h.statusTail,
    escalations = h.escalations,
    escalatedStalls = h.escalatedStalls,
    declinedEffects = h.declinedEffects,
    malformedCognition = h.malformedCognition,
    doneTickets = w.doneTickets,
    cognitionSpendUsd = h.cognitionSpendUsd,
  )
