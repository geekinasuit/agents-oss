package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.auth.AllowList
import com.geekinasuit.agency.shared.auth.ApprovalEvidence
import com.geekinasuit.agency.shared.auth.ApprovalVerifier
import com.geekinasuit.agency.shared.auth.QuorumNode
import com.geekinasuit.agency.shared.auth.RejectingVerifier
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.oneOfOne
import com.geekinasuit.agency.shared.auth.parseCommitted
import com.geekinasuit.agency.shared.auth.quorumSatisfied
import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.foldFaultMessage
import com.geekinasuit.agency.shared.journal.payloadObject
import com.geekinasuit.agency.shared.journal.requireContract
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

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
  const val RUN_STARTED = "run-started"
  const val TICKET_CLAIMED = "ticket-claimed"
  const val PLAN_REQUESTED = "plan-requested"
  const val PLAN_ARTIFACT_RECORDED = "plan-artifact-recorded"
  const val COMMIT_PROPOSED = "commit-proposed"
  const val STATUS_WRITTEN = "status-written"
  const val TICKET_DONE = "ticket-done"
  const val ESCALATED = "escalated"
  const val GATE_OPENED = "gate-opened"
  const val GATE_OPEN_NOTIFIED = "gate-open-notified"
  const val POD_SPAWNED = "pod-spawned"
  const val POD_RESULT_RECORDED = "pod-result-recorded"
  const val POD_ABANDONED = "pod-abandoned"

  /** Intent journaled BEFORE the spawn side-effect: a pod launch is a
   * side-effect on the world, so it obeys the same intent-before-effect discipline as an
   * [com.geekinasuit.agency.shared.journal.EffectReceiver] fire. A kill between the spawn
   * call and [POD_SPAWNED] would otherwise leave a live pod with NO journal row — re-fold
   * would say "nothing happened," which is false (a record-integrity violation). The intent
   * makes the orphan RECORDED: adopt sees an intent with no matching [POD_SPAWNED] and
   * abandons it visibly. (Reclaiming a real orphaned OS process is the engine's kill-tree
   * job; this keeps the substrate's own record honest regardless of pod realism.) */
  const val POD_SPAWN_INTENDED = "pod-spawn-intended"

  /** Adopt's disposition of an orphaned [POD_SPAWN_INTENDED] (no matching [POD_SPAWNED]):
   * clears the pending intent and surfaces it as an escalation (the pod may or may not have
   * started; the playbook re-proposes from the now-absent evidence). */
  const val POD_SPAWN_ABANDONED = "pod-spawn-abandoned"

  /**
   * A supervisory fact the pod ENGINE observed about a pod it launched: a
   * permission ask and its decision, a preflight or artifact refusal, a restart attempt or
   * exhausted cap, a wall-clock kill, a degraded group kill, a discarded late completion.
   *
   * SUBSTRATE-authored, always: these are OUR observations of an untrusted process, never
   * anything the pod said about itself. The fold does not act on them — a pod event never
   * advances the pipeline (see [com.geekinasuit.agency.lead.LeadDaemon.injectPodEvent]) —
   * it is the AUDIT half of the launcher: what a pod asked for, what we answered, and why
   * it died.
   */
  const val POD_EVENT = "pod-event"

  /** Cognition output (proposals + reasoning), journaled by the substrate with origin
   * [com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION] — the audit record of what
   * the model-bearing layer decided, distinct from the substrate facts that execute it. */
  const val COGNITION_PROPOSED = "cognition-proposed"

  /**
   * A cognition turn whose output the substrate could not use: not JSON, an
   * unknown proposal type, a hallucinated gate kind, a missing required field.
   *
   * SUBSTRATE-authored, unlike [COGNITION_PROPOSED]: the payload is OUR classification of
   * what arrived, not the model's decision — there is no decision to attribute. Held as its
   * own kind rather than an [ESCALATED] row because structured-output reliability is
   * DISTRIBUTIONAL: a model degrades by emitting near-misses at some rate, and that rate is
   * only visible if malformed turns are countable apart from the escalations a working model
   * legitimately asks for. The turn still COST money, so the fold accrues its spend.
   */
  const val COGNITION_MALFORMED = "cognition-malformed"

  /**
   * A gate-scoped, single-use nonce the substrate minted and journaled (payload: nonce,
   * gateId, payloadDigest). SUBSTRATE-issued is load-bearing: if the approval surface
   * minted nonces it would be the sole source of both the pending-gate list AND the nonce
   * authorizing against it, and mechanical re-verification would degrade to checking one
   * client's two assertions against each other. The nonce is what makes an approval mean
   * "once, now, for this gate" — a signature alone proves only "this key said this", and
   * an approval, once carried outside, can be replayed indefinitely.
   */
  const val NONCE_ISSUED = "nonce-issued"

  /**
   * A nonce explicitly retired (payload: nonce, reason) without — or in addition to — a
   * release consuming it: voided when its gate re-opens on a new digest, expired, or
   * recorded as bookkeeping after a release (the fold already derives that consumption, so
   * the bookkeeping form folds as a no-op). Journal-derived spent-ness is the point:
   * rejecting a replay after a restart falls out of re-folding, not out of any in-memory
   * table.
   */
  const val NONCE_CONSUMED = "nonce-consumed"

  /**
   * A signature-carrying approval the authorization layer journaled (payload: gateId,
   * principalId, nonce, payloadDigest, evidence{schemeId, publicKey, signature,
   * carrierArtifactId, gateId, payloadDigest, nonce, signedPreimage}). AUTH-LAYER-authored —
   * the one lead kind besides the release itself that is: approvals accumulate toward a
   * quorum, so an approval-shaped entry from cognition or a pod stuffing the count is the
   * same threat as a forged release, and gets the same treatment (never honored, retained
   * visibly in [LeadState.misOriginedEntries]).
   *
   * The fold CONSUMES the evidence sub-object (2b): [foldApproval] re-derives the signer's
   * identity from the signed preimage, re-verifies the signature over it, resolves the
   * committed key to an allow-listed principal, and cross-checks the committed (gate, digest,
   * nonce) against the flat copies — trusting the PREIMAGE, never the flat `principalId`. An
   * approval that clears all of that lands in [LeadState.verifiedApprovals]; one that does not
   * lands in [LeadState.unverifiedApprovals] with a reason and contributes nothing. Verified
   * accumulation is durable so a k-of-n quorum can fill across restarts, and each verified
   * approval keeps its binding (nonce + digest) so one bound to a superseded digest can never
   * satisfy the re-opened gate. A null/absent preimage is fail-closed: unverifiable, never a
   * pass — the closure the nullable [com.geekinasuit.agency.shared.auth.ApprovalEvidence]
   * field defers to this fold.
   */
  const val APPROVAL_RECORDED = "approval-recorded"
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

data class OpenGate(
  val gateId: String,
  val gateKind: String,
  val payloadDigest: String,
  val openedSeq: Long,
)

/** A substrate-issued nonce as journaled: bound at issue time to one gate AND the digest
 * that gate was open on. The digest binding is what voids an authorization on payload
 * change — a gate re-opened on a new digest leaves old nonces pointing at a digest the
 * gate no longer has. */
data class IssuedNonce(
  val nonce: String,
  val gateId: String,
  val payloadDigest: String,
  val issuedSeq: Long,
) {
  init {
    requireContract(nonce.isNotBlank()) { "an issued nonce requires a non-blank value" }
    requireContract(gateId.isNotBlank()) { "an issued nonce requires a non-blank gateId" }
    requireContract(payloadDigest.isNotBlank()) {
      "an issued nonce requires a non-blank payloadDigest"
    }
  }
}

/**
 * One approval that RE-VERIFIED at fold time: its signature checked out over its committed
 * preimage, the preimage's key resolved to an allow-listed principal, and the preimage's
 * (gate, digest, nonce) agreed with the flat copies beside it. [principalId] is therefore
 * the PREIMAGE-DERIVED identity (the allow-list principal for the committed key) — never the
 * flat `principalId` a record claimed, which the fold no longer trusts. The binding it
 * committed to is retained so consumers filter on (nonce, payloadDigest) against the gate's
 * CURRENT state, leaving a stale-bound approval inert rather than silently counted.
 */
data class VerifiedApproval(
  val principalId: String,
  val nonce: String,
  val payloadDigest: String,
  val seq: Long,
) {
  init {
    requireContract(principalId.isNotBlank()) {
      "a verified approval requires a non-blank principalId"
    }
    requireContract(nonce.isNotBlank()) { "a verified approval requires a non-blank nonce" }
    requireContract(payloadDigest.isNotBlank()) {
      "a verified approval requires a non-blank payloadDigest"
    }
  }
}

/**
 * The authorization context the fold verifies against — supplied to [leadFold], never
 * journaled. It bundles the three things a release verdict is a function of BESIDES the
 * journal: the [allowList] of principals permitted to authorize (it lives with us, never
 * with the approval carrier), the signature [verifier] (a port; the real scheme adapter is
 * later work, the fold's default is [RejectingVerifier]), and the [quorum] a gate's verified
 * approvers must satisfy to release.
 *
 * Because verification happens AT THE FOLD, folded state is a function of (journal, auth):
 * the same journal folded under a different [LeadAuth] can reach a different verdict — see
 * [leadFold]'s recovery-contract note. [DENY_ALL] is the restrictive default: an empty
 * allow-list, the rejecting verifier, and a quorum naming a principal that cannot exist, so
 * nothing on the ceremony path can clear a gate. It is the honest spelling of "this daemon
 * cannot authorize a ceremony release yet": [hasApprovers] is false, and [foldRelease]
 * refuses the nonce-LESS pre-ceremony path under any ceremony auth, so only a DENY_ALL fold
 * still honors a nonce-less release.
 */
class LeadAuth(
  val allowList: AllowList,
  val verifier: ApprovalVerifier,
  val quorum: QuorumNode,
) {
  /** Whether this auth can authorize a ceremony release at all — true iff the [allowList]
   * names at least one principal. It is the semantic complement of [DENY_ALL]'s empty
   * allow-list, derived from the security object rather than an identity check against the
   * sentinel, so a hand-built equivalent of DENY_ALL is classified the same. The substrate
   * mints a nonce at gate-open iff this holds, and [foldRelease] refuses a nonce-less release
   * iff this holds — one predicate, read at both the write and the fold. */
  val hasApprovers: Boolean
    get() = !allowList.isEmpty()

  companion object {
    val DENY_ALL: LeadAuth = LeadAuth(AllowList(emptyList()), RejectingVerifier, oneOfOne("__none__"))
  }
}

data class PodRecord(
  val podId: String,
  val sessionId: String,
  val taskRef: String,
  /** The pod's WRITE TARGET — provenance only after result-record time: consumers
   * read [boundPath], never this, because the pod's path can be swapped under a digest. */
  val artifactPath: String,
  val spawnedSeq: Long,
  val resultDigest: String? = null,
  val costUsd: Double? = null,
  /** The lead-owned immutable copy of the result (bind-once): written from the
   * engine's single disciplined read before the result row was journaled. Null on a pod
   * with no result yet — and on pre-bind-once rows, which downstream verification treats
   * as missing evidence (abandon + re-propose), never as license to read [artifactPath]. */
  val boundPath: String? = null,
  val abandonedReason: String? = null,
) {
  val active: Boolean
    get() = resultDigest == null && abandonedReason == null
}

data class LeadState(
  val runsStarted: Int = 0,
  val currentTicket: String? = null,
  val phase: TicketPhase = TicketPhase.IDLE,
  val planArtifactPath: String? = null,
  val planArtifactSha: String? = null,
  val commitManifestPath: String? = null,
  val commitManifestDigest: String? = null,
  val openGates: Map<String, OpenGate> = emptyMap(),
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
  val staleReleases: List<Pair<Long, String>> = emptyList(), // (seq, gateId) — auth origin, but digest mismatch, unknown gate, or nonce indiscipline (consumed/unknown/misbound/absent-where-required)
  /** Every nonce issued this ticket, by value — consumed ones stay listed ([consumedNonces]
   * marks them) so a re-issue of a spent value is detectable as the anomaly it is. */
  val issuedNonces: Map<String, IssuedNonce> = emptyMap(),
  val consumedNonces: Set<String> = emptySet(),
  /** Nonces whose gate-open announce is final ([LeadKinds.GATE_OPEN_NOTIFIED] without `retry`):
   * announced, not announced because no sink is wired or the artifact could not be inlined, or
   * failed on its last attempt. Keyed by the NONCE, not the gate: a nonce is single-use and bound
   * to one (gate, digest), so a gate re-opened on a new digest mints a NEW nonce and is announced
   * afresh, while a final one is never announced again. The notify arm reads this to stop; a
   * marker that says the announce will be sent again counts in [failedAnnounces] instead.
   * Ticket-scoped: [LeadKinds.TICKET_DONE] clears it, as it does [issuedNonces]. */
  val notifiedNonces: Set<String> = emptySet(),
  /** Nonce → how many of its announces failed with a failure the sink reported, each marked to be
   * sent again ([LeadKinds.GATE_OPEN_NOTIFIED] with `retry`). The notify arm reads it to find the
   * timer the next attempt waits on, and the daemon to number that attempt, so a failing sink is
   * called once per attempt, never once per pass. [notifiedNonces] takes precedence: a nonce in it
   * is not sent again whatever this holds. Ticket-scoped: [LeadKinds.TICKET_DONE] clears it. */
  val failedAnnounces: Map<String, Int> = emptyMap(),
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
  val pods: Map<String, PodRecord> = emptyMap(),
  val pendingSpawnIntents: Map<String, Long> = emptyMap(), // taskRef → intent seq: spawn journaled, POD_SPAWNED not yet
  val misOriginedEntries: List<Pair<Long, String>> = emptyList(), // (seq, kind): substrate-authored kind with a non-substrate origin — never honored
  val statusTail: List<String> = emptyList(),
  val escalations: List<String> = emptyList(),
  /** Gate id → the digests the gate was escalated on this ticket as holding up the stage it guards.
   * A gate is escalated on a digest in three cases: it is open on the digest under a ceremony auth
   * with no usable nonce, one the mint issues none for, and not released on it; it is released on
   * the digest, and the digest is not the substrate's evidence for its kind; or it is the plan gate,
   * open on a digest that is not the recorded plan, when an execute pod is proposed. Read from the
   * gate and digest an [LeadKinds.ESCALATED] row names beside its reason, so the escalation and its
   * record are one append. The daemon reads it to escalate each gate and digest once, across
   * restarts, which the capped [escalations] tail cannot promise. Ticket-scoped:
   * [LeadKinds.TICKET_DONE] clears it. */
  val escalatedStalls: Map<String, Set<String>> = emptyMap(),
  /** The pending effect intents adopt declined to re-fire and escalated, each as the SHA-256 of its
   * key's UTF-8 text: a key comes from the journal, of any length, so the record holds a digest of
   * fixed size. Read from the digest an [LeadKinds.ESCALATED] row names beside its reason. The
   * daemon reads it to escalate each declined intent once, across restarts. Not ticket-scoped: a
   * declined intent stays pending, and every adopt meets it again, whichever ticket is current. */
  val declinedEffects: Set<String> = emptySet(),
  /** (seq, reason) for turns whose output was unusable — the degradation signal, kept apart
   * from [escalations] so a degrading model is countable rather than merely noisy. */
  val malformedCognition: List<Pair<Long, String>> = emptyList(),
  val doneTickets: List<String> = emptyList(),
  /** Journal-derived total model spend: the sum of costUsd across journaled cognition
   * decisions. The budget guard reads THIS, not an in-memory counter — restarts keep it. */
  val cognitionSpendUsd: Double = 0.0,
) {
  val pendingGates: List<OpenGate>
    get() = openGates.values.filter { it.gateId !in releasedGates }.sortedBy { it.openedSeq }

  val activePods: List<PodRecord>
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
  fun approvedOnCurrentDigest(gateId: String): Boolean {
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
  fun openNonceFor(gate: OpenGate): IssuedNonce? =
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
    verifiedApprovals[gate.gateId]
      .orEmpty()
      .filter { it.nonce == nonce && it.payloadDigest == gate.payloadDigest }
      .map { it.principalId }
      .toSet()

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

/** Bounded-view cap for cognition-controllable / anomaly lists: the
 * journal remains the complete record; these FOLD VIEWS keep only a tail so a hostile or
 * buggy strategy cannot grow re-fold memory without bound. Higher than [statusTail]'s 20 —
 * these carry security-relevant tails (escalations, stale releases, mis-origined entries).
 *
 * The nonce/approval records ([LeadState.issuedNonces], [LeadState.consumedNonces],
 * [LeadState.verifiedApprovals], [LeadState.notifiedNonces], [LeadState.failedAnnounces]) sit
 * DELIBERATELY outside this cap: they are correctness-bearing records, not views. Evicting a
 * consumed nonce re-enables the replay it exists to reject; evicting an issued nonce or a verified
 * approval silently voids a live authorization; evicting a notified nonce re-enables the duplicate
 * gate-open announce its marker exists to suppress; evicting a failed-announce count restarts that
 * nonce's attempts, undoing their bound. ([LeadState.unverifiedApprovals] IS capped by this
 * tail — an approval that did not verify contributes nothing a release depends on, so it is a
 * view, not a record.) [LeadState.nonceLessReleases] is uncapped for a DIFFERENT reason — it is
 * an audit marker whose absence is itself a claim ("released under the ceremony"), so an
 * evicted entry would not lose the answer, it would invert it. [LeadState.escalatedStalls] is
 * uncapped too: evicting an entry escalates its gate again, the repeat it exists to suppress. Those
 * seven share the same bound: the ticket, not a tail — TICKET_DONE clears them.
 * [LeadState.declinedEffects] is uncapped for the same reason as the stall record, and is not
 * ticket-scoped: it holds one digest per distinct pending intent key adopt declined, since a
 * declined intent stays pending across tickets. Each entry costs its writer a journal row. All
 * their kinds are origin-gated, so only the substrate and the authorization layer can grow them: a
 * party positioned to flood them could already write worse. */
private const val ANOMALY_TAIL = 100

/** The lead kinds only the substrate ever authors. Any of these
 * arriving with a non-substrate origin is never honored — see the foldOne provenance gate.
 * COGNITION_PROPOSED is excluded (legitimately cognition-origin); GATE_RELEASED is not a
 * lead kind — its auth-origin check lives in foldRelease. State-inert kinds
 * (POD_EVENT — no fold arm consumes them) are still listed: "never honored" is vacuous
 * for them, but a forged row must land in [LeadState.misOriginedEntries] rather than
 * fold invisibly — the audit half of the origin gate applies to every substrate-only kind,
 * not just the state-carrying ones. */
private val SUBSTRATE_AUTHORED_KINDS =
  setOf(
    LeadKinds.RUN_STARTED,
    LeadKinds.TICKET_CLAIMED,
    LeadKinds.PLAN_REQUESTED,
    LeadKinds.PLAN_ARTIFACT_RECORDED,
    LeadKinds.COMMIT_PROPOSED,
    LeadKinds.STATUS_WRITTEN,
    LeadKinds.TICKET_DONE,
    LeadKinds.ESCALATED,
    LeadKinds.GATE_OPENED,
    LeadKinds.GATE_OPEN_NOTIFIED,
    LeadKinds.POD_SPAWNED,
    LeadKinds.POD_RESULT_RECORDED,
    LeadKinds.POD_ABANDONED,
    LeadKinds.POD_SPAWN_INTENDED,
    LeadKinds.POD_SPAWN_ABANDONED,
    LeadKinds.POD_EVENT,
    LeadKinds.COGNITION_MALFORMED,
    LeadKinds.NONCE_ISSUED,
    LeadKinds.NONCE_CONSUMED,
  )

/** Well-formed ticket refs: a ticket ref is untrusted input (a fixture line today, a real
 * ticket-index row later) that flows into task refs, gate ids, and effect keys. A conservative
 * charset — ':' and '/' excluded, so it can forge neither a task namespace nor a path — plus a
 * length bound keeps a malformed ref from wedging the pipeline or polluting a namespace. */
private val TICKET_REF_RE = Regex("[A-Za-z0-9._-]+")
private const val MAX_TICKET_REF_LEN = 128

/** The form the substrate records an evidence digest in: [sha256HexBytes]'s lowercase hex. */
private val SHA256_HEX_RE = Regex("[0-9a-f]{64}")

/** Whether the claim accepts [ref]: in [TICKET_REF_RE]'s charset and at most [MAX_TICKET_REF_LEN]
 * chars. The claim journals only a ref that passes, as a JSON string. The fold refuses a
 * substrate-origin claim of any other ref, and records a claim of any other origin in
 * [LeadState.misOriginedEntries] before it reads the ref. The claim and the fold check this one
 * predicate, since a fold stricter than the claim would refuse a journal the lead wrote itself.
 * Widening the predicate keeps every journal already written foldable. Tightening it makes the
 * fold refuse claims already journaled, so it needs a migration of those journals. */
internal fun isClaimableTicketRef(ref: String): Boolean =
  TICKET_REF_RE.matches(ref) && ref.length <= MAX_TICKET_REF_LEN

/** A fold failure with its position identified — a malformed payload on a known kind
 * (field missing, wrong type) is chain corruption or payload-contract drift, and it must
 * fail CLASSIFIED (seq + kind named) rather than as an anonymous NPE boot-loop. The message
 * takes [foldFaultMessage]'s form, so it quotes nothing from the entry's payload. */
class LeadFoldException(seq: Long, kind: String, cause: Throwable) :
  RuntimeException(foldFaultMessage("lead fold", seq, kind, cause), cause)

/**
 * The lead state machine: `leadState = leadFold(entries, auth)`. Folds the SAME entry list
 * the shared fold consumes — two folds, one list; composition, not extension.
 *
 * RECOVERY CONTRACT (widened by 2b): folded state is now a function of the journal AND
 * [auth]. Approvals re-verify at fold time and a ceremony release gates on a quorum over the
 * VERIFIED approvers ([foldRelease]), so the same journal can fold to a DIFFERENT verdict
 * under a different [LeadAuth]: revoke a principal from the allow-list (or install a
 * stricter quorum) and re-fold, and a gate that reached quorum before may no longer — its
 * release folds stale, the gate drops out of [LeadState.releasedGates], and the phase never
 * reaches the approved state it did under the old auth. That is deliberate — authorization
 * is not frozen into the journal at write time; it is re-decided on the allow-list and
 * quorum in force at recovery. [auth] is required, with no default: which principals and
 * quorum a fold verifies against is a security-load-bearing choice, and a silent default
 * would be the footgun this parameter exists to refuse. A substrate not yet wired for the
 * ceremony passes [LeadAuth.DENY_ALL] explicitly.
 */
fun leadFold(entries: List<JournalEntry>, auth: LeadAuth): LeadState {
  var s = LeadState()
  for (e in entries) {
    s =
      try {
        foldOne(s, e, auth)
      } catch (x: LeadFoldException) {
        throw x
      } catch (x: Exception) {
        throw LeadFoldException(e.seq, e.kind, x)
      }
  }
  return s
}

private fun foldOne(s0: LeadState, e: JournalEntry, auth: LeadAuth): LeadState {
  val s = s0
  // Provenance teeth, symmetric with the release check: the substrate
  // is the sole author of these state-carrying kinds. An entry of such a kind bearing any
  // other origin is a confused deputy or a corrupt/imported entry — it NEVER advances state
  // and lands VISIBLY in misOriginedEntries. (GATE_RELEASED carries auth origin and is
  // handled by foldRelease; COGNITION_PROPOSED is legitimately cognition-origin.) Checked
  // before the payload parse, so a forged entry with a garbage payload is recorded, not thrown.
  if (e.kind in SUBSTRATE_AUTHORED_KINDS && e.origin != ORIGIN_SUBSTRATE) {
    return s.copy(
      misOriginedEntries = (s.misOriginedEntries + (e.seq to e.kind)).takeLast(ANOMALY_TAIL)
    )
  }
  // Same teeth, different sole author: an approval accumulates toward quorum, so its one
  // legitimate origin is the authorization layer — approval-shaped entries from anywhere
  // else (cognition, a pod, an import) are quorum-stuffing and land visibly, never counted.
  if (e.kind == LeadKinds.APPROVAL_RECORDED && e.origin != ORIGIN_AUTH_LAYER) {
    return s.copy(
      misOriginedEntries = (s.misOriginedEntries + (e.seq to e.kind)).takeLast(ANOMALY_TAIL)
    )
  }
  val p = payloadObject(e.payloadJson)
  return when (e.kind) {
      LeadKinds.RUN_STARTED -> s.copy(runsStarted = s.runsStarted + 1)
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
        s.copy(currentTicket = ref.content, phase = TicketPhase.CLAIMED)
      }
      LeadKinds.PLAN_REQUESTED -> s.copy(phase = TicketPhase.PLAN_REQUESTED)
      LeadKinds.PLAN_ARTIFACT_RECORDED ->
        s.copy(
          planArtifactPath = p.str("path"),
          planArtifactSha = p.str("sha256"),
          phase = TicketPhase.PLAN_RECORDED,
        )
      LeadKinds.COMMIT_PROPOSED ->
        s.copy(
          commitManifestPath = p.str("manifestPath"),
          commitManifestDigest = p.str("manifestDigest"),
          phase = TicketPhase.COMMIT_PROPOSED,
        )
      LeadKinds.STATUS_WRITTEN -> s.copy(statusTail = (s.statusTail + p.str("status")).takeLast(20))
      LeadKinds.TICKET_DONE ->
        // Clear ALL ticket-scoped state: the lead claims a new ticket only
        // when currentTicket == null, so every open/released/stale gate and every pod
        // belonged to the ticket just finished. Retaining them grows fold state without
        // bound across tickets AND leaves cross-ticket residue a first-by-kind lookup like
        // gate(gateKind) could later mis-honor. doneTickets (small refs) and the capped
        // tails (statusTail, escalations, misOriginedEntries, malformedCognition) persist as
        // the running record — a model's degradation rate is a property of the model, not of
        // the ticket it happened to be working, so it must not reset at a ticket boundary.
        s.copy(
          doneTickets = s.doneTickets + p.str("ticketRef"),
          currentTicket = null,
          phase = TicketPhase.IDLE,
          planArtifactPath = null,
          planArtifactSha = null,
          commitManifestPath = null,
          commitManifestDigest = null,
          openGates = emptyMap(),
          releasedGates = emptySet(),
          releasedDigests = emptyMap(),
          nonceLessReleases = emptyMap(),
          staleReleases = emptyList(),
          issuedNonces = emptyMap(),
          consumedNonces = emptySet(),
          notifiedNonces = emptySet(),
          failedAnnounces = emptyMap(),
          escalatedStalls = emptyMap(),
          verifiedApprovals = emptyMap(),
          unverifiedApprovals = emptyList(),
          pods = emptyMap(),
          pendingSpawnIntents = emptyMap(),
        )
      LeadKinds.ESCALATED -> {
        val escalated = s.copy(escalations = (s.escalations + p.str("reason")).takeLast(ANOMALY_TAIL))
        // An escalation of a gate that holds up its stage names the gate and its digest beside the
        // reason ([LeadState.escalatedStalls]). Only two JSON strings are recorded: a row with any
        // other value there is still an escalation, and at worst its gate is escalated again, never
        // silenced. Any digest counts, blank or not, since it is the one the gate is open on.
        val gateId = p.jsonStringOrNull("stalledGateId")
        val digest = p.jsonStringOrNull("stalledDigest")
        val stalled =
          if (gateId == null || digest == null) escalated
          else
            escalated.copy(
              escalatedStalls =
                escalated.escalatedStalls + (gateId to escalated.escalatedStalls[gateId].orEmpty() + digest)
            )
        // A declined effect intent is named by its key's digest, on the same terms.
        val declined = p.jsonStringOrNull("declinedEffectDigest")
        if (declined == null) stalled
        else stalled.copy(declinedEffects = stalled.declinedEffects + declined)
      }
      LeadKinds.GATE_OPENED -> {
        val gate = OpenGate(p.str("gateId"), p.str("gateKind"), p.str("payloadDigest"), e.seq)
        s.copy(
          openGates = s.openGates + (gate.gateId to gate),
          phase =
            when (gate.gateKind) {
              GateKinds.PLAN_APPROVAL -> TicketPhase.PLAN_GATED
              GateKinds.COMMIT_APPROVAL -> TicketPhase.COMMIT_GATED
              else -> s.phase
            },
        )
      }
      KIND_GATE_RELEASED -> foldRelease(s, e, p, auth)
      LeadKinds.POD_SPAWNED -> {
        val pod =
          PodRecord(
            podId = p.str("podId"),
            sessionId = p.str("sessionId"),
            taskRef = p.str("taskRef"),
            artifactPath = p.str("artifactPath"),
            spawnedSeq = e.seq,
          )
        s.copy(
          pods = s.pods + (pod.podId to pod),
          pendingSpawnIntents = s.pendingSpawnIntents - pod.taskRef, // intent fulfilled
          phase =
            when {
              pod.taskRef.startsWith("plan:") && s.phase == TicketPhase.PLAN_REQUESTED ->
                TicketPhase.PLANNING
              pod.taskRef.startsWith("execute:") && s.phase == TicketPhase.PLAN_APPROVED ->
                TicketPhase.EXECUTING
              else -> s.phase
            },
        )
      }
      // Unknown-pod results/abandons are DROPPED (a result cannot attach to a pod with no
      // spawn record — result-before-spawn ordering is a contract violation, see
      // PodRunner.spawn) but dropped VISIBLY, consistent with the other anomaly views
      // (AGENCY-021): this fold path is the backstop for the
      // accept-exemption on pod completions, and a backstop that fires silently would be
      // exactly the no-trace loss that fix exists to end.
      LeadKinds.POD_RESULT_RECORDED -> {
        val podId = p.str("podId")
        val pod = s.pods[podId]
        if (pod == null)
          s.copy(
            escalations =
              (s.escalations +
                  "pod-result for unknown pod '$podId' at seq=${e.seq} — dropped (a result must follow its pod's spawn record)")
                .takeLast(ANOMALY_TAIL)
          )
        else {
          // costUsd may be ABSENT (null-not-zero: an unmeasured cost is journaled as no
          // field at all) — absent folds to null, never a fabricated 0.0. A PRESENT value
          // must be a finite, non-negative number — the write side journals only such
          // values — so anything else is payload-contract drift on a substrate-authored
          // entry and fails CLASSIFIED: a value that is not a number by one check, and NaN /
          // Infinity / negatives (which a number conversion accepts) by the next.
          val updated =
            pod.copy(
              resultDigest = p.str("resultDigest"),
              boundPath = p.strOrNull("boundPath"),
              costUsd =
                p.strOrNull("costUsd")?.let { text ->
                  val cost = text.toDoubleOrNull()
                  requireContract(cost != null) { "payload field 'costUsd' is not a number" }
                  requireContract(cost.isFinite() && cost >= 0.0) {
                    "payload field 'costUsd' is non-finite or negative"
                  }
                  cost
                },
            )
          s.copy(
            pods = s.pods + (podId to updated),
            phase =
              if (updated.taskRef.startsWith("execute:") && s.phase == TicketPhase.EXECUTING)
                TicketPhase.EXECUTED
              else s.phase,
          )
        }
      }
      LeadKinds.POD_ABANDONED -> {
        val podId = p.str("podId")
        val pod = s.pods[podId]
        if (pod == null)
          s.copy(
            escalations =
              (s.escalations +
                  "pod-abandoned for unknown pod '$podId' at seq=${e.seq} — dropped (no spawn record)")
                .takeLast(ANOMALY_TAIL)
          )
        else s.copy(pods = s.pods + (podId to pod.copy(abandonedReason = p.str("reason"))))
      }
      // A pod launch's intent, journaled before the side-effect. Tracked by taskRef;
      // POD_SPAWNED clears it (fulfilled), POD_SPAWN_ABANDONED clears it (orphaned on adopt).
      LeadKinds.POD_SPAWN_INTENDED ->
        s.copy(pendingSpawnIntents = s.pendingSpawnIntents + (p.str("taskRef") to e.seq))
      LeadKinds.POD_SPAWN_ABANDONED -> {
        val taskRef = p.str("taskRef")
        s.copy(
          pendingSpawnIntents = s.pendingSpawnIntents - taskRef,
          escalations =
            (s.escalations + "spawn-intent orphaned for $taskRef: ${p.str("reason")}")
              .takeLast(ANOMALY_TAIL),
        )
      }
      LeadKinds.NONCE_ISSUED -> {
        val issued = IssuedNonce(p.str("nonce"), p.str("gateId"), p.str("payloadDigest"), e.seq)
        when {
          // A re-issue of an existing value would REBIND it (or resurrect a spent one) —
          // the first binding stands and the attempt is retained visibly.
          issued.nonce in s.issuedNonces ->
            s.copy(
              escalations =
                (s.escalations +
                    "nonce re-issued at seq=${e.seq} for gate '${issued.gateId}' — first binding kept")
                  .takeLast(ANOMALY_TAIL)
            )
          else -> {
            // Recorded even when the gate is unknown (the substrate's assertion stands in
            // the record; a release still needs an open gate whose digest agrees), but an
            // issue-before-open is contract drift worth seeing.
            val flagged =
              if (issued.gateId !in s.openGates)
                s.copy(
                  escalations =
                    (s.escalations +
                        "nonce issued at seq=${e.seq} for unknown gate '${issued.gateId}'")
                      .takeLast(ANOMALY_TAIL)
                )
              else s
            flagged.copy(issuedNonces = flagged.issuedNonces + (issued.nonce to issued))
          }
        }
      }
      LeadKinds.NONCE_CONSUMED -> {
        val nonce = p.str("nonce")
        when {
          nonce !in s.issuedNonces ->
            s.copy(
              escalations =
                (s.escalations + "consume of unknown nonce at seq=${e.seq} — dropped")
                  .takeLast(ANOMALY_TAIL)
            )
          // Already spent: bookkeeping after a release the fold consumed itself — no-op.
          nonce in s.consumedNonces -> s
          else -> s.copy(consumedNonces = s.consumedNonces + nonce)
        }
      }
      LeadKinds.GATE_OPEN_NOTIFIED -> {
        // One attempt to announce this nonce's gate-open (the outcome rides in the payload for the
        // record). A marker that says the announce will be sent again counts one more failed
        // attempt; any other is final. A marker without the field is final, which is also how a
        // binary that does not retry reads one that has it. The substrate is the sole writer and
        // announces only a nonce it just resolved open, so no gate/issue cross-check is warranted.
        val nonce = p.str("nonce")
        if (p.marksRetry())
          s.copy(
            failedAnnounces = s.failedAnnounces + (nonce to (s.failedAnnounces[nonce] ?: 0) + 1)
          )
        else s.copy(notifiedNonces = s.notifiedNonces + nonce)
      }
      LeadKinds.APPROVAL_RECORDED -> foldApproval(s, e, p, auth)
      LeadKinds.COGNITION_PROPOSED ->
        s.copy(cognitionSpendUsd = s.cognitionSpendUsd + accruedCost(p))
      // A turn that produced garbage was billed exactly like one that produced a decision, so
      // its cost accrues on the same terms: a model that ONLY emits near-misses would
      // otherwise spend against a cap that never moves.
      LeadKinds.COGNITION_MALFORMED ->
        s.copy(
          cognitionSpendUsd = s.cognitionSpendUsd + accruedCost(p),
          malformedCognition =
            (s.malformedCognition + (e.seq to p.str("reason"))).takeLast(ANOMALY_TAIL),
        )
      // Shared + unknown kinds: not this state machine's business (schema-version KDoc
      // above). Also the state-inert lead kinds (POD_EVENT): journaled audit rows the fold
      // deliberately never consumes — their origin was already policed by the gate above.
      else -> s
  }
}

/**
 * The spend a journaled cognition turn contributes. costUsd is a model-supplied, UNTRUSTED
 * number: a non-finite (NaN/±Infinity) or negative
 * value must never enter the total the budget cap reads — NaN makes every `spend >= cap`
 * comparison false, so the cap would never trip and wake-driven spend would be unbounded,
 * and a negative value would understate spend. Only a finite, non-negative cost accrues, so
 * [LeadState.cognitionSpendUsd] stays finite and monotonic non-decreasing.
 */
private fun accruedCost(p: kotlinx.serialization.json.JsonObject): Double =
  p.strOrNull("costUsd")?.toDoubleOrNull()?.takeIf { it.isFinite() && it >= 0.0 } ?: 0.0

/**
 * Release handling — the lead-level teeth. Honored iff origin == auth layer AND the
 * released digest matches the gate as opened AND the nonce discipline holds AND — on the
 * nonce (ceremony) path — a quorum of VERIFIED approvers is satisfied. Wrong origin is the
 * shared fold's visible rejection (re-asserted here by simply not honoring); everything else
 * auth-origin-but-unfaithful (or quorum-unmet) is retained visibly as
 * [LeadState.staleReleases].
 *
 * QUORUM (2b): once a release names a faithful nonce, the gate clears only if
 * [quorumSatisfied] holds over [LeadState.boundApprovers] — the preimage-derived principals
 * whose VERIFIED approval binds this gate at this nonce and digest — against [auth]'s quorum
 * tree. An unverified approval never enters that set (see [foldApproval]), so the flat
 * `principalId` a record claimed cannot fill a quorum. Quorum sits INSIDE the nonce branch,
 * after the faithfulness check: an unfaithful nonce still folds stale on faithfulness and
 * never reaches the quorum gate, so the quorum check bites exactly the releases that would
 * otherwise have cleared. Under [LeadAuth.DENY_ALL] the bound set is always empty and the
 * quorum unsatisfiable, so no ceremony release clears — the honest default for a substrate
 * whose verifier is not yet installed.
 *
 * NONCE DISCIPLINE (single-use, journal-derived): a release naming a nonce is honored
 * only if that nonce was issued FOR THIS GATE, bound at issue to THIS digest, and never
 * consumed — and honoring it consumes it in the derived state, so a second release naming
 * the same nonce folds stale. Replay rejection therefore survives restart by
 * construction: it is a property of re-folding the journal, not of any in-memory table.
 * A release naming NO nonce is the pre-ceremony path, and it is scoped to the AUTHORIZATION
 * in force at fold time. Under a ceremony auth ([LeadAuth.hasApprovers]) it is refused
 * outright: every release must be nonce-bound and quorum-satisfied, so omitting the nonce is
 * never an exemption there. Under [LeadAuth.DENY_ALL] (no approvers to bind) it is honored
 * while its gate has never had a nonce issued — the pre-ceremony stub, kept so journals
 * written before nonces existed keep their meaning.
 *
 * That auth-scoping is what lets the substrate mint nonces safely. The older per-gate clause
 * — `s.issuedNonces.values.any { it.gateId == gateId }` folds a nonce-less release stale the
 * instant its gate has ANY nonce issued — closed a gate's escape hatch only once that gate
 * itself reached the ceremony, which left a gate whose mint step crashed after GATE_OPENED
 * but before NONCE_ISSUED still on the pre-ceremony rule. The [LeadAuth.hasApprovers] refusal
 * closes that window: a ceremony daemon refuses the nonce-less path for ALL its gates,
 * reached-the-ceremony or not. The per-gate clause is kept: it reads the live folded nonce
 * set — the nonces issued as of this release, rebuilt from the journal on every fold, never a
 * marker frozen in at write — so under DENY_ALL it still fires, and it still guards a journal
 * minted under a ceremony auth then re-folded under one since relaxed.
 * `releaseOmittingTheNonceIsNotAnExemption` and `aNonceLessReleaseUnderACeremonyAuthFoldsStale`
 * hold the ceremony-auth refusal; the per-gate clause's own stale-fold is exercised by
 * `nullNonceFieldOnAReleaseReadsAsAbsent` under DENY_ALL.
 *
 * Nonce-less honors (reachable on a DENY_ALL fold only) are marked in [LeadState.nonceLessReleases], keyed by gate to
 * the FIRST honoring release's seq, so the disposition stays legible after the fact — the
 * honor is itself single-use per gate, mirroring the consumed-nonce rule: a second
 * nonce-less release of a marked gate folds stale rather than silently re-honoring and
 * retargeting the mark. That also means a re-opened gate cannot be honored nonce-less a
 * second time within a ticket (the guard reads the mark, which [LeadKinds.TICKET_DONE]
 * clears with the rest of the per-ticket state) — deliberate conservatism on a stub
 * path, and visible in [LeadState.staleReleases] rather than silent. A later ceremony
 * release of a re-opened gate stays distinguishable from the mark.
 *
 * On the re-open shapes several cells exercise: the daemon opens each gateId at most once
 * per ticket (LeadDaemon's seen-gate guard), so a re-opened gate is a journal-level fold
 * surface, not a transition the daemon currently produces. On a real payload change today
 * the gate stays open on the old digest and the voiding path that fires is an explicit
 * [LeadKinds.NONCE_CONSUMED] — which the step-2 ceremony must remember to journal.
 */
private fun foldRelease(
  s: LeadState,
  e: JournalEntry,
  p: kotlinx.serialization.json.JsonObject,
  auth: LeadAuth,
): LeadState {
  if (e.origin != ORIGIN_AUTH_LAYER) return s // forged provenance: never honored here; shared fold records the rejection
  val gateId = p.str("gateId")
  val digest = p.strOrNull("payloadDigest")
  val nonce = p.strOrNull("nonce")
  val gate = s.openGates[gateId]
  fun stale(): LeadState =
    s.copy(staleReleases = (s.staleReleases + (e.seq to gateId)).takeLast(ANOMALY_TAIL))
  if (gate == null || digest != gate.payloadDigest) return stale()
  // Single-release per (gate, digest): a gate already released on THIS digest is decided, so
  // a second release folds stale rather than re-honoring — whether it carries a fresh nonce
  // or none. The nonce-less path has its own per-gate mark ([nonceLessReleases]); this is the
  // nonce path's missing analogue, and keying on the digest (not the gate id) keeps a gate
  // re-opened on a NEW digest releasable, since that is a distinct authorization surface.
  // Placed before the nonce branch so both paths inherit it.
  if (gate.payloadDigest in s.releasedDigests[gateId].orEmpty()) return stale()
  val consumed: Set<String>
  val nonceLess: Map<String, Long>
  if (nonce == null) {
    // Under a ceremony auth (a non-empty allow-list) every release must be nonce-bound and
    // quorum-satisfied; the pre-ceremony nonce-less path is refused outright. Placed first so
    // a gate whose mint step crashed after GATE_OPENED but before NONCE_ISSUED cannot fall
    // back to an un-quorumed release — its daemon's auth refuses the nonce-less path whether
    // or not that particular gate reached the ceremony. Under DENY_ALL this is a no-op and
    // the pre-ceremony rule below still governs.
    if (auth.hasApprovers) return stale()
    if (s.issuedNonces.values.any { it.gateId == gateId }) return stale()
    // A nonce-less honor is itself single-use per gate, mirroring the consumed-nonce
    // rule: a replay folds stale, and the mark keeps the first honoring seq.
    if (gateId in s.nonceLessReleases) return stale()
    consumed = s.consumedNonces
    nonceLess = s.nonceLessReleases + (gateId to e.seq)
  } else {
    val issued = s.issuedNonces[nonce]
    val faithful =
      issued != null &&
        issued.gateId == gateId &&
        issued.payloadDigest == digest &&
        nonce !in s.consumedNonces
    if (!faithful) return stale()
    // Quorum over the VERIFIED approvers bound to this gate at this nonce and digest. Placed
    // after faithfulness so an unfaithful nonce folds stale before it, and the quorum check
    // bites exactly the releases that would otherwise clear. Unmet → stale, visibly.
    if (!quorumSatisfied(auth.quorum, s.boundApprovers(gate, nonce))) return stale()
    consumed = s.consumedNonces + nonce
    nonceLess = s.nonceLessReleases
  }
  return s.copy(
    releasedGates = s.releasedGates + gateId,
    releasedDigests =
      s.releasedDigests + (gateId to (s.releasedDigests[gateId].orEmpty() + gate.payloadDigest)),
    nonceLessReleases = nonceLess,
    consumedNonces = consumed,
    phase =
      when (gate.gateKind) {
        GateKinds.PLAN_APPROVAL -> TicketPhase.PLAN_APPROVED
        GateKinds.COMMIT_APPROVAL -> TicketPhase.COMMIT_APPROVED
        else -> s.phase
      },
  )
}

/**
 * APPROVAL_RECORDED handling — the mechanical re-verification (2b). An approval counts
 * toward a quorum only if it RE-VERIFIES here: the fold reads the evidence sub-object,
 * re-derives the signer's committed identity from the signed preimage, checks the signature
 * over that preimage, resolves the committed key to an allow-listed principal, and confirms
 * every committed field agrees with its flat copy. The PREIMAGE is the sole authority; the
 * flat columns (top-level and evidence) are lookup indices held to agreement, never trusted —
 * so the flat `principalId` a record claims can never by itself put an approver in a quorum.
 *
 * A verified approval lands in [LeadState.verifiedApprovals] under its COMMITTED gate, keyed
 * by the preimage-derived principal, deduped on (principal, nonce, digest). Anything that
 * fails a step lands in [LeadState.unverifiedApprovals] with a reason and contributes
 * nothing — a null/absent preimage included (fail-closed: unverifiable, never a pass). The
 * refusal names WHICH layer disagreed, so a split-source attempt is legible after the fact.
 *
 * The top-level payload framing (gateId/principalId/nonce/payloadDigest) is the auth layer's
 * own contract, read strictly ([str] throws classified on a malformed required field); the
 * evidence sub-object is carrier-provided PROOF, so a malformed or absent one is "unverified",
 * never a fold crash — an approval that cannot be verified must not be able to brick recovery.
 */
private fun foldApproval(
  s: LeadState,
  e: JournalEntry,
  p: kotlinx.serialization.json.JsonObject,
  auth: LeadAuth,
): LeadState {
  val claimedGate = p.str("gateId")
  val claimedPrincipal = p.str("principalId")
  val claimedNonce = p.str("nonce")
  val claimedDigest = p.str("payloadDigest")

  fun unverified(reason: String): LeadState =
    s.copy(
      unverifiedApprovals =
        (s.unverifiedApprovals + (e.seq to "approval at seq=${e.seq} $reason")).takeLast(ANOMALY_TAIL)
    )

  val evidenceObj = p["evidence"] as? JsonObject ?: return unverified("carries no evidence sub-object")
  val evidence =
    try {
      ApprovalEvidence.fromJson(evidenceObj)
    } catch (x: Exception) {
      return unverified("has malformed evidence: ${x.message}")
    }
  val preimage =
    evidence.signedPreimage
      ?: return unverified("carries no signed preimage — cannot re-verify (fail-closed)")
  val committed =
    parseCommitted(preimage)
      ?: return unverified("has a preimage that is not a canonical committed approval")
  if (!auth.verifier.verifies(evidence.schemeId, committed.publicKey, evidence.signature, preimage))
    return unverified("has a signature that does not verify over its preimage")
  val principal =
    auth.allowList.principalFor(SchemeKey(evidence.schemeId, committed.publicKey))
      ?: return unverified("is signed by a key not in the allow-list")
  // Three-layer agreement: the preimage is authority; the evidence's flat copies AND the
  // top-level payload fields must match it, or the record names one thing and signs another.
  if (evidence.publicKey != committed.publicKey) return unverified("evidence publicKey disagrees with the preimage")
  if (evidence.gateId != committed.gateId) return unverified("evidence gateId disagrees with the preimage")
  if (evidence.payloadDigest != committed.payloadDigest)
    return unverified("evidence payloadDigest disagrees with the preimage")
  if (evidence.nonce != committed.nonce) return unverified("evidence nonce disagrees with the preimage")
  if (claimedGate != committed.gateId) return unverified("payload gateId disagrees with the preimage")
  if (claimedNonce != committed.nonce) return unverified("payload nonce disagrees with the preimage")
  if (claimedDigest != committed.payloadDigest)
    return unverified("payload payloadDigest disagrees with the preimage")
  if (claimedPrincipal != principal.principalId)
    return unverified("payload principalId disagrees with the allow-list identity resolved from the preimage")

  val verified = VerifiedApproval(principal.principalId, committed.nonce, committed.payloadDigest, e.seq)
  val current = s.verifiedApprovals[committed.gateId].orEmpty()
  val duplicate =
    current.any {
      it.principalId == verified.principalId &&
        it.nonce == verified.nonce &&
        it.payloadDigest == verified.payloadDigest
    }
  if (duplicate) return s
  // Verified, but drift is still worth flagging: a verified approval can commit to a gate not
  // yet opened or a nonce not yet minted (issue-before-open). Kept — a release re-checks
  // against live state — with the same flagged-but-kept pattern as NONCE_ISSUED.
  val drift = buildList {
    if (committed.gateId !in s.openGates)
      add("verified approval at seq=${e.seq} for unknown gate '${committed.gateId}'")
    if (committed.nonce !in s.issuedNonces)
      add("verified approval at seq=${e.seq} for unminted nonce on gate '${committed.gateId}'")
  }
  val flagged =
    if (drift.isEmpty()) s else s.copy(escalations = (s.escalations + drift).takeLast(ANOMALY_TAIL))
  return flagged.copy(
    verifiedApprovals = flagged.verifiedApprovals + (committed.gateId to (current + verified))
  )
}

/** Required payload field. JsonNull IS a JsonPrimitive whose content is the string
 * "null", so without the explicit check a null-valued field on a known kind would fold
 * onward as a working four-character string (a mint of the guessable nonce "null")
 * instead of failing CLASSIFIED as the payload-contract drift it is. Non-string scalars
 * are refused for the same reason — a numeric 123 must not fold onward as the string
 * "123" — matching the strict readers the shared auth codec sets the doctrine with. */
private fun kotlinx.serialization.json.JsonObject.str(k: String): String {
  val el = this[k]
  requireContract(el != null) { "payload field '$k' is missing" }
  requireContract(el !is kotlinx.serialization.json.JsonNull) { "payload field '$k' is null" }
  requireContract(el is JsonPrimitive && el.isString) { "payload field '$k' must be a JSON string" }
  return el.content
}

/** Optional payload field: absent and JsonNull both read as "no value" — an optional
 * field explicitly set to null must not become the string "null". Deliberately tolerant
 * of non-string scalars, unlike [str]: on the release path a coerced number can only
 * miss (an unminted nonce, a mismatched digest — both fold stale, visibly), and
 * [accruedCost]'s malformed-means-zero contract sits on this reader. */
private fun kotlinx.serialization.json.JsonObject.strOrNull(k: String): String? {
  val el = this[k] ?: return null
  if (el is kotlinx.serialization.json.JsonNull) return null
  requireContract(el is JsonPrimitive) { "payload field '$k' must be a JSON scalar" }
  return el.content
}

/** The field's value if it is a JSON string, else null: absent, null, a number, a boolean, an object
 * or an array all read as no value, so a malformed field never fails the fold. */
private fun kotlinx.serialization.json.JsonObject.jsonStringOrNull(k: String): String? =
  (this[k] as? JsonPrimitive)?.takeIf { it.isString }?.content

/** Whether a notify marker says its announce will be sent again: only a JSON `true` in `retry`
 * does. Absent, null, a string, or any other value reads as final, the outcome that sends nothing
 * again, so a malformed field can cost a retry but never cause one. */
private fun kotlinx.serialization.json.JsonObject.marksRetry(): Boolean {
  val el = this["retry"] as? kotlinx.serialization.json.JsonPrimitive ?: return false
  return !el.isString && el.content == "true"
}
