package com.geekinasuit.agency.lead

import com.geekinasuit.agency.lead.PayloadReaders.str
import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.JournalState
import com.geekinasuit.agency.shared.journal.payloadObject
import com.geekinasuit.agency.shared.journal.requireContract
import java.io.File
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

// The ticket workflow's own declarations: the gate kinds and phases of the ticket pipeline, its
// half of the lead fold, its mechanical steps, the ticket source, and the scripted playbook that
// drives it.

/** The lead-chain entry kinds the ticket workflow writes and folds. */
object TicketKinds {
  const val TICKET_CLAIMED = "ticket-claimed"
  const val PLAN_REQUESTED = "plan-requested"
  const val PLAN_ARTIFACT_RECORDED = "plan-artifact-recorded"
  const val COMMIT_PROPOSED = "commit-proposed"
  const val TICKET_DONE = "ticket-done"
}

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

/** The ticket workflow's scope-end kinds: a ticket is done. */
internal val TICKET_WORKFLOW_SCOPE_END_KINDS = setOf(LeadKinds.TICKET_DONE)

/** Whether [e] ends the ticket workflow's scope. The host clears its scoped records on it. */
internal fun isTicketScopeEnd(e: JournalEntry): Boolean = e.kind in TICKET_WORKFLOW_SCOPE_END_KINDS

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

/** The idempotency-key prefix of a ticket's commit effect. */
private const val COMMIT_EFFECT_PREFIX = "apply-commit:"

/**
 * The ticket workflow: claim an offered ticket, record its plan, propose its commit, and apply the
 * commit once both gates are approved on their evidence. Tickets come from [ticketSource].
 */
internal class TicketWorkflow(private val ticketSource: TicketSource) : Workflow<LeadState> {
  override val substrateKinds: Set<String> = TICKET_WORKFLOW_SUBSTRATE_KINDS
  override val scopeEndKinds: Set<String> = TICKET_WORKFLOW_SCOPE_END_KINDS
  override val gateKinds: Set<String> = GateKinds.ALL

  override fun fold(entries: List<JournalEntry>, auth: LeadAuth): LeadState = leadFold(entries, auth)

  /** The current ticket, when it is a ref the claim accepts. */
  override fun scopeKey(lead: LeadState): String? = lead.currentTicket?.takeIf { isClaimableTicketRef(it) }

  override fun currentScopeKey(lead: LeadState): String? = lead.currentTicket

  override fun gateId(gateKind: String, scopeKey: String): String = gateIdFor(gateKind, scopeKey)

  /** A gate opens only on the digest the substrate recorded for its kind: cognition cannot re-bind
   * approval to evidence that does not exist. A refused kind or digest is the proposal's own text,
   * so the reason gives its length, never its content. */
  override fun admitGateOpen(
    gateKind: String,
    payloadDigest: String,
    gateId: String,
    lead: LeadState,
  ): GateOpenDecision {
    val expected = lead.evidenceDigest(gateKind)
    if (expected != null && payloadDigest == expected) return GateOpenDecision.Open(expected)
    return GateOpenDecision.Refuse(
      if (gateKind !in GateKinds.ALL)
        "gate-open rejected: a proposed gate kind of ${gateKind.length} chars is not one the lead opens"
      else
        "gate-open rejected for $gateId: a proposed digest of ${payloadDigest.length} chars " +
          "does not match substrate evidence ${expected?.take(16) ?: "(none recorded)"}"
    )
  }

  /** taskRefs whose redundant-respawn refusal has already been escalated, process-scoped like the
   * host's attempt cap: the refusal itself replays on every proposing wake, deterministically from
   * folded evidence alone; the row announcing that the strategy keeps re-proposing completed work
   * is appended once per taskRef. Loop-thread only. */
  private val redundantSpawnEscalated = mutableSetOf<String>()

  override fun admitPodSpawn(taskRef: String, lead: LeadState, turn: ProposalTurn, host: HostServices): Boolean {
    val ticket = lead.currentTicket ?: return false
    // Bind the spawn to the CURRENT ticket and a known kind:
    // cognition decides WHEN to run a pod, never an arbitrary task namespace. The only
    // legal refs are this ticket's plan/execute; a foreign ticket, an unknown kind, or
    // a traversal attempt is escalated, never spawned — so untrusted judgment cannot
    // amplify into unbounded distinct spawns.
    if (taskRef != "plan:$ticket" && taskRef != "execute:$ticket") {
      host.escalate(
        "pod-spawn rejected: a proposed taskRef of ${taskRef.length} chars is not plan:/execute: " +
          "for the current ticket '$ticket'"
      )
      return false
    }
    // Pipeline ordering has teeth: an execute pod
    // is real work ON the plan, so it may launch only AFTER the plan-approval gate is
    // approved on the digest it is CURRENTLY open on, and that digest is the recorded
    // plan's. The mechanical pass already refuses to PROPOSE a commit before plan
    // approval; without this, cognition — by bug or prompt injection — could still get the
    // substrate to LAUNCH the execute session on an unapproved (or unrecorded) plan, and
    // the human's plan gate would gate nothing. Epoch-precise, not a bare `in
    // releasedGates`: a plan re-opened on a new digest is a fresh, unapproved surface, and a
    // release on a digest that is not the recorded plan approves no plan the executor would
    // run. Escalated, never spawned.
    //
    // A plan gate open on a digest that is not the recorded plan gets its own refusal, which
    // names the gate: the plan may already have been approved on its recorded digest before
    // the gate was re-opened, so asking for its approval would point the operator at the wrong
    // fault. That refusal is escalated once per gate and digest, under the record the
    // mechanical pass keeps ([LeadState.escalatedStalls]), so a strategy that proposes the
    // executor on every wake does not escalate on every wake. The mechanical pass has already
    // escalated such a gate once it is released on that digest. Until a plan is recorded, the
    // gate's digest may yet be the plan's, and the refusal asks for the plan's approval.
    if (taskRef == "execute:$ticket" && !lead.approvedOnEvidence(GateKinds.PLAN_APPROVAL, ticket)) {
      val planGate = lead.openGates[gateIdFor(GateKinds.PLAN_APPROVAL, ticket)]
      val planRecorded = lead.recordedEvidence(GateKinds.PLAN_APPROVAL) != null
      val offEvidence =
        if (planGate == null || !planRecorded) null
        else lead.evidenceMismatch(GateKinds.PLAN_APPROVAL, planGate.payloadDigest)
      if (planGate == null || offEvidence == null) {
        host.escalate(
          "pod-spawn rejected: execute pod for '$ticket' proposed before the plan-approval " +
            "gate is approved on the recorded plan — the plan must be approved before " +
            "execution runs"
        )
      } else if (
        planGate.payloadDigest !in lead.escalatedStalls[planGate.gateId].orEmpty() &&
          turn.escalatedOffEvidence.add(planGate.gateId)
      ) {
        host.escalateGate(
          planGate,
          "pod-spawn rejected: execute pod for '$ticket' proposed while ${planGate.gateId} is " +
            "open off its evidence: $offEvidence — no approval on that digest lets the " +
            "executor run",
        )
      }
      return false
    }
    if (lead.activePods.any { it.taskRef == taskRef }) return false
    if (!turn.seenTaskRefs.add(taskRef)) return false
    // Success-side twin of the host's failure cap: a task whose EVIDENCE is already
    // recorded gets no fresh pod. Successful completions never count toward that cap
    // and clear the active-pod guard, and a completion is itself
    // the next wake — so without this check a strategy re-proposing the same legal
    // ref would buy one real pod (and its real model spend) per wake,
    // self-sustaining through the wait-on-human gate phases, with nothing
    // escalated. Refused on every wake, escalated once per taskRef per process
    // (see [redundantSpawnEscalated]). No legitimate replan is refused here: no
    // fold transition clears plan/manifest evidence within a ticket cycle
    // (TICKET_DONE resets the whole cycle), so a replan mechanism, if one ever
    // exists, must introduce a cleared-evidence transition — which re-legalizes
    // the spawn here by itself.
    // The namespace guard above admits exactly plan:/execute:, so the else branch
    // IS execute:. Deliberately not an exhaustive `when` with `else -> null`: if
    // the legal namespace is ever widened without this selector keeping pace, a
    // new kind inherits the manifest-evidence refusal (escalated, visible) rather
    // than skipping a spend guard silently — over-refusal is the recoverable
    // failure direction here.
    val recorded = if (taskRef == "plan:$ticket") lead.planArtifactSha else lead.commitManifestDigest
    if (recorded != null) {
      if (redundantSpawnEscalated.add(taskRef)) {
        host.escalate(
          "pod-spawn refused for taskRef '${taskRef.take(80)}': the evidence it " +
            "exists to produce is already recorded (${recorded.take(16)}) — completed " +
            "work is not re-run, and further redundant proposals are refused without " +
            "a repeat escalation"
        )
      }
      return false
    }
    return true
  }

  /** The plan's sha for the plan gate, the manifest's digest for the commit gate
   * ([LeadState.recordedEvidence]). */
  override fun recordedEvidence(gateKind: String, lead: LeadState): String? = lead.recordedEvidence(gateKind)

  override fun evidenceMismatch(gateKind: String, digest: String, lead: LeadState): String? =
    lead.evidenceMismatch(gateKind, digest)

  /** The recorded plan for the plan gate, the recorded manifest for the commit gate. */
  override fun gateArtifactPath(gateKind: String, lead: LeadState): String? =
    when (gateKind) {
      GateKinds.PLAN_APPROVAL -> lead.planArtifactPath
      GateKinds.COMMIT_APPROVAL -> lead.commitManifestPath
      else -> null
    }

  /** The current ticket's commit effect, once both its gates are approved on their evidence
   * ([LeadState.approvedToCommit]): the one intent the lead journals, and only then. */
  override fun redriveMessage(key: String, lead: LeadState): String? {
    val ticket = lead.currentTicket ?: return null
    return if (key == commitEffectKey(ticket) && lead.approvedToCommit(ticket)) commitEffectMessage(ticket, lead)
    else null
  }

  override fun redriveDeclineReason(key: String): String? {
    val keyTicket = key.removePrefix(COMMIT_EFFECT_PREFIX)
    return if (key.startsWith(COMMIT_EFFECT_PREFIX) && isClaimableTicketRef(keyTicket))
      "effect re-drive declined for $key: the lead journals a ticket's commit effect only " +
        "while it is the current ticket, with its commit and plan gates approved on their " +
        "recorded evidence, and that does not hold — the effect is not fired"
    else null
  }

  /** The idempotency key of [ticket]'s commit effect: the one intent the lead journals. */
  private fun commitEffectKey(ticket: String) = COMMIT_EFFECT_PREFIX + ticket

  /** The message of [ticket]'s commit effect, built from the lead's own state: the intent row's
   * message is not read back, since a journal the lead did not write can hold any message there. */
  private fun commitEffectMessage(ticket: String, lead: LeadState) =
    "apply-commit ticket=$ticket manifest=${lead.commitManifestDigest}"

  override fun mechanicalStep(lead: LeadState, shared: JournalState, host: HostServices): Boolean {
    // Claim an offered ticket when idle. The done-filter repeats here even though the
    // source receives the same set: the source is a seam an adopter implements, and a
    // completed ticket must stay completed regardless of what any implementation re-offers.
    if (lead.currentTicket == null) {
      val offered = ticketSource.next(lead.doneTickets.toSet())
      if (offered != null && offered !in lead.doneTickets) {
        // The ticket ref is UNTRUSTED input: a fixture
        // line today, a real ticket-index row later. It flows into this ticket's plan:/execute:
        // task refs, gate ids, and effect keys. Validate charset + length at the claim boundary
        // — ':' and '/' excluded so a ref can neither forge a task namespace (`plan:` prefix)
        // nor traverse a path — so a malformed ref is escalated visibly and NOT claimed, rather
        // than silently wedging every later plan/execute spawn against TASK_REF_RE. Returns
        // false (not true): the pass makes no progress on a bad ref instead of re-looping on it.
        if (!isClaimableTicketRef(offered)) {
          host.escalate("ticket claim rejected: an offered ref of ${offered.length} chars is malformed (charset/length)")
          return false
        }
        host.append(LeadKinds.TICKET_CLAIMED, buildJsonObject { put("ticketRef", offered) })
        host.faultAt("after-claim")
        host.append(LeadKinds.PLAN_REQUESTED, buildJsonObject {})
        host.faultAt("after-plan-requested")
        return true
      }
      return false
    }
    val ticket = lead.currentTicket

    // Kill-recovery for the claim window: death between ticket-claimed and plan-requested
    // leaves the phase at CLAIMED; finish the hop so the phase record stays honest.
    if (lead.phase == TicketPhase.CLAIMED) {
      host.append(LeadKinds.PLAN_REQUESTED, buildJsonObject {})
      host.faultAt("after-plan-requested")
      return true
    }

    // Record a finished planner pod's artifact as THE plan. Bind-once: the evidence
    // is the pod's BOUND copy — the lead-owned immutable object written from the engine's
    // single disciplined read — verified against the journaled digest before any gate
    // binds to it. The pod's own artifactPath is provenance only and is never read here.
    // A missing or integrity-failed bound copy abandons the pod, and the evidence-based
    // playbook re-proposes the work.
    if (lead.planArtifactSha == null) {
      val planner = lead.podFor("plan:$ticket")
      if (planner?.resultDigest != null) {
        val verified = host.verifiedBoundArtifact(planner) ?: return true // pod abandoned
        host.append(
          LeadKinds.PLAN_ARTIFACT_RECORDED,
          buildJsonObject {
            put("path", verified.boundPath)
            put("sha256", verified.digest)
          },
        )
        host.faultAt("after-plan-recorded")
        return true
      }
    }

    // Propose the commit from a finished execute pod's manifest — same bound-copy rule.
    val planApproved = lead.approvedOnEvidence(GateKinds.PLAN_APPROVAL, ticket)
    if (planApproved && lead.commitManifestDigest == null) {
      val executor = lead.podFor("execute:$ticket")
      if (executor?.resultDigest != null) {
        val verified = host.verifiedBoundArtifact(executor) ?: return true // pod abandoned
        host.append(
          LeadKinds.COMMIT_PROPOSED,
          buildJsonObject {
            put("manifestPath", verified.boundPath)
            put("manifestDigest", verified.digest)
          },
        )
        host.faultAt("after-commit-proposed")
        return true
      }
    }

    // Commit approved → drive the apply-commit effect exactly-once, then finish the
    // ticket. Gate membership alone is NOT the precondition: each gate must be approved on
    // its evidence — the plan gate on the recorded plan, the commit gate on the recorded
    // manifest ([LeadState.approvedToCommit]) — so a release for a gate that opened out of
    // order, or on a digest the substrate never recorded, can never fire an effect on
    // evidence nobody approved.
    if (lead.approvedToCommit(ticket)) {
      val effectKey = commitEffectKey(ticket)
      val message = commitEffectMessage(ticket, lead)
      if (effectKey !in shared.intents) {
        host.append("effect-intent", buildJsonObject { put("message", message) }, idempotencyKey = effectKey)
        host.faultAt("after-commit-intent")
        host.fireEffect(effectKey, message, attempt = 1)
        return true
      }
      if (effectKey !in shared.doneKeys) {
        // An intent the lead did not journal in this run, e.g. one adopt declined while a gate
        // was not yet approved on its evidence. It is fired now rather than at the next adopt.
        host.fireEffect(effectKey, message, attempt = 2)
        return true
      }
      if (!host.effectSeen(effectKey)) {
        // The journal's done entry is not evidence the effect happened: the shared fold accepts
        // one of any origin. The receiver's own record is, so the ticket is recorded done only
        // once the receiver has seen the key. A receiver that lost its record fires it again.
        // The escalation is at least once: a crash before the fire escalates again on restart.
        host.escalate(
          "effect done entry for $effectKey has no matching effect in the receiver's record — " +
            "the effect is fired before the ticket is recorded done"
        )
        host.faultAt("after-unconfirmed-done-escalated")
        host.fireEffect(effectKey, message, attempt = 2)
        return true
      }
      host.append(LeadKinds.TICKET_DONE, buildJsonObject { put("ticketRef", ticket) })
      host.faultAt("after-ticket-done")
      return true
    }
    return false
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
