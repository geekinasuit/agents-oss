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

  /** The id of the gate of [gateKind] in the scope keyed [scopeKey]. */
  fun gateId(gateKind: String, scopeKey: String): String

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
