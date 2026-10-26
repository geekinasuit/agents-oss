package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalState
import kotlinx.serialization.json.JsonObject

/**
 * A workflow the lead host runs: the procedure that gives the host's machinery (gates, pods,
 * effects, escalation) its work. The ticket workflow ([TicketWorkflow]) is the first.
 *
 * The workflow declares the journal kinds it owns. The host folds every other lead kind, so the two
 * sets must not overlap ([requireKindPartition]): a kind in both would be folded twice, and a
 * scope-end kind the host also folds would skip the host's own arm for it.
 */
internal interface Workflow {
  /** The substrate-only kinds the workflow writes and folds. The host's provenance gate polices
   * them alongside its own. */
  val substrateKinds: Set<String>

  /** The kinds among [substrateKinds] that end the workflow's scope. The host clears its scoped
   * records on an entry of one. */
  val scopeEndKinds: Set<String>

  /** The gate kinds the workflow opens. */
  val gateKinds: Set<String>

  /** The key the current scope's gate ids derive from, or null when no scope is current or its key
   * is not one the workflow would have opened a scope under. The host's gate recovery acts only on
   * gates under ids derived from this key. */
  fun scopeKey(lead: LeadState): String?

  /** The current scope's key as the fold holds it, whether or not it is well-formed, or null when
   * no scope is current. A proposal is executed only within a current scope. Unlike [scopeKey] it
   * does not check the key's form. For a workflow whose fold refuses a malformed key, as the ticket
   * workflow's claim does, the two agree on every state the fold produces; they differ only on a
   * state built some other way. */
  fun currentScopeKey(lead: LeadState): String?

  /** The id of the gate of [gateKind] in the scope keyed [scopeKey]. */
  fun gateId(gateKind: String, scopeKey: String): String

  /** Whether the host may open [gateId], of [gateKind], on [payloadDigest], as cognition proposed:
   * the digest it opens on, or the reason it refuses. The host has already skipped a gate that is
   * open, or that this turn has handled. */
  fun admitGateOpen(gateKind: String, payloadDigest: String, gateId: String, lead: LeadState): GateOpenDecision

  /** Whether the host may launch a pod for [taskRef], as cognition proposed, in [turn]. Refusals
   * the workflow makes are escalated through [host] here, as the workflow's guards require; a
   * proposal it skips without refusing returns false too. The host's own guards (the attempt cap,
   * the ref's form, the artifact path, the launch profile) run after an admission. */
  fun admitPodSpawn(taskRef: String, lead: LeadState, turn: ProposalTurn, host: HostServices): Boolean

  /** The bound copy an operator reads to decide a gate of [gateKind]: the evidence the gate opened
   * on, or null when the workflow recorded none for that kind. */
  fun gateArtifactPath(gateKind: String, lead: LeadState): String?

  /** The digest the workflow recorded as the evidence a gate of [gateKind] binds to, in whatever
   * form the journal holds it, or null while none is recorded. The host waits on a gate's evidence
   * before it escalates the gate as stalled or released off its evidence. */
  fun recordedEvidence(gateKind: String, lead: LeadState): String?

  /** Why a gate of [gateKind] open on [digest] is not open on the workflow's evidence for that kind,
   * or null when it is. The host mints a gate's nonce only when this is null, and escalates a
   * released gate for which it is not.
   *
   * Null is an obligation, not only an answer: the host binds a nonce to [digest] on it, and does
   * not check [digest] itself. So null only for a digest in the form the substrate records evidence
   * in (lowercase sha256 hex), never for a blank one. A nonce bound to a blank digest makes every
   * later fold of the journal fail. */
  fun evidenceMismatch(gateKind: String, digest: String, lead: LeadState): String?

  /** The message to fire a pending effect keyed [key] with again, or null when the workflow would
   * not journal that effect now. The message comes from [lead], never from the intent row. */
  fun redriveMessage(key: String, lead: LeadState): String?

  /** Why the workflow declines to fire a pending effect keyed [key] again, when [key] is one of the
   * workflow's own effect keys, or null when it is not, and the host says so in its own words. */
  fun redriveDeclineReason(key: String): String?

  /** Advance the workflow's own pipeline by one mechanical step, one that needs no judgment, after
   * the host's own recovery found nothing to do. Returns true if the step made progress, so the
   * host refolds and runs the pass again. */
  fun mechanicalStep(lead: LeadState, shared: JournalState, host: HostServices): Boolean
}

/** What the host does for a workflow. Each append is substrate-authored. */
internal interface HostServices {
  /** Append an entry of [kind]. */
  fun append(kind: String, payload: JsonObject, idempotencyKey: String? = null)

  /** A named boundary where a test can kill the daemon ([FaultInjector]). */
  fun faultAt(point: String)

  /** Escalate [reason] to an operator. */
  fun escalate(reason: String)

  /** Escalate [reason] about [gate], recording the gate and the digest it is open on beside it
   * ([LeadState.escalatedStalls]), so the escalation and its record are one append. */
  fun escalateGate(gate: OpenGate, reason: String)

  /** Fire the effect keyed [key] with [message] through the effect receiver, and journal its done
   * entry as attempt [attempt]. */
  fun fireEffect(key: String, message: String, attempt: Int)

  /** Whether the effect receiver's own record holds [key]: the evidence an effect happened, which a
   * journaled done entry is not. */
  fun effectSeen(key: String): Boolean

  /** [pod]'s bound artifact, verified against its journaled digest, or null when the copy is
   * missing or disturbed, in which case the pod has been abandoned. */
  fun verifiedBoundArtifact(pod: PodRecord): VerifiedArtifact?
}

/** What one cognition turn's proposals have done so far, which the state the turn was decided on
 * cannot show: the host makes one per turn, and it is gone with the turn. */
internal class ProposalTurn {
  /** Task refs this turn has already acted on. */
  val seenTaskRefs = mutableSetOf<String>()

  /** Gates this turn escalated as open off their evidence: the record of such an escalation is in
   * the journal, which the turn's state was folded from before the turn ran. */
  val escalatedOffEvidence = mutableSetOf<String>()
}

/** The workflow's answer to a proposed gate-open ([Workflow.admitGateOpen]). */
internal sealed interface GateOpenDecision {
  /** Open the gate on [digest], the substrate's evidence for its kind. */
  data class Open(val digest: String) : GateOpenDecision

  /** Do not open it; escalate [reason]. */
  data class Refuse(val reason: String) : GateOpenDecision
}

/** A bound artifact that passed verification: the lead-owned path consumers use and the
 * digest gates bind to. */
internal data class VerifiedArtifact(val boundPath: String, val digest: String)

/**
 * Refuses a [workflow] whose kinds the host cannot fold alongside [hostKinds]: a scope-end kind that
 * is not one of the workflow's own kinds, or a workflow kind the host also folds.
 */
internal fun requireKindPartition(hostKinds: Set<String>, workflow: Workflow) {
  val strayScopeEnds = workflow.scopeEndKinds - workflow.substrateKinds
  require(strayScopeEnds.isEmpty()) {
    "the workflow's scope-end kinds must be among its own kinds; these are not: ${strayScopeEnds.sorted()}"
  }
  val shared = workflow.substrateKinds intersect hostKinds
  require(shared.isEmpty()) { "the workflow claims kinds the host folds: ${shared.sorted()}" }
}
