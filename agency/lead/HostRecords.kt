package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.auth.AllowList
import com.geekinasuit.agency.shared.auth.ApprovalVerifier
import com.geekinasuit.agency.shared.auth.QuorumNode
import com.geekinasuit.agency.shared.auth.RejectingVerifier
import com.geekinasuit.agency.shared.auth.oneOfOne
import com.geekinasuit.agency.shared.journal.foldFaultMessage
import com.geekinasuit.agency.shared.journal.requireContract

// The host's records and bounds: what its fold keeps about gates, nonces, approvals and pods, the
// authorization it verifies against, and how it fails.

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
 * The authorization context the fold verifies against — supplied to [foldLeadJournal], never
 * journaled. It bundles the three things a release verdict is a function of BESIDES the
 * journal: the [allowList] of principals permitted to authorize (it lives with us, never
 * with the approval carrier), the signature [verifier] (a port; the real scheme adapter is
 * later work, the fold's default is [RejectingVerifier]), and the [quorum] a gate's verified
 * approvers must satisfy to release.
 *
 * Because verification happens AT THE FOLD, folded state is a function of (journal, auth):
 * the same journal folded under a different [LeadAuth] can reach a different verdict, and recovery
 * re-decides authorization under the auth in force then. [DENY_ALL] is the restrictive default: an empty
 * allow-list, the rejecting verifier, and a quorum naming a principal that cannot exist, so
 * nothing on the ceremony path can clear a gate. It is the honest spelling of "this daemon
 * cannot authorize a ceremony release yet": [hasApprovers] is false, and [foldRelease]
 * refuses the nonce-LESS pre-ceremony path under any ceremony auth, so only a DENY_ALL fold
 * still honors a nonce-less release.
 *
 * An [allowList] naming a principal [UNLISTED_PRINCIPAL_ID] is refused: that id is the one an
 * approval row names when its key resolves to no principal, so no principal may hold it.
 */
class LeadAuth(
  val allowList: AllowList,
  val verifier: ApprovalVerifier,
  val quorum: QuorumNode,
) {
  init {
    require(allowList.byId(UNLISTED_PRINCIPAL_ID) == null) {
      "principalId '$UNLISTED_PRINCIPAL_ID' is reserved for approvals whose key is in no allow-list"
    }
  }

  /** Whether this auth can authorize a ceremony release at all — true iff the [allowList]
   * names at least one principal. It is the semantic complement of [DENY_ALL]'s empty
   * allow-list, derived from the security object rather than an identity check against the
   * sentinel, so a hand-built equivalent of DENY_ALL is classified the same. The substrate
   * mints a nonce at gate-open iff this holds, and [foldRelease] refuses a nonce-less release
   * iff this holds — one predicate, read at both the write and the fold. */
  val hasApprovers: Boolean
    get() = !allowList.isEmpty()

  companion object {
    /** The principal an approval row names when its key resolves to none, and on every row whose
     * approval did not re-verify. */
    const val UNLISTED_PRINCIPAL_ID = "unlisted-key"

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

/** Bounded-view cap for cognition-controllable / anomaly lists: the
 * journal remains the complete record; these FOLD VIEWS keep only a tail so a hostile or
 * buggy strategy cannot grow re-fold memory without bound. Higher than [statusTail]'s 20 —
 * these carry security-relevant tails (escalations, stale releases, mis-origined entries).
 *
 * The nonce/approval records ([HostState.issuedNonces], [HostState.consumedNonces],
 * [HostState.verifiedApprovals], [HostState.notifiedNonces], [HostState.failedAnnounces]) sit
 * DELIBERATELY outside this cap: they are correctness-bearing records, not views. Evicting a
 * consumed nonce re-enables the replay it exists to reject; evicting an issued nonce or a verified
 * approval silently voids a live authorization; evicting a notified nonce re-enables the duplicate
 * gate-open announce its marker exists to suppress; evicting a failed-announce count restarts that
 * nonce's attempts, undoing their bound. ([HostState.unverifiedApprovals] IS capped by this
 * tail — an approval that did not verify contributes nothing a release depends on, so it is a
 * view, not a record.) [HostState.nonceLessReleases] is uncapped for a DIFFERENT reason — it is
 * an audit marker whose absence is itself a claim ("released under the ceremony"), so an
 * evicted entry would not lose the answer, it would invert it. [HostState.escalatedStalls] is
 * uncapped too: evicting an entry escalates its gate again, the repeat it exists to suppress. Those
 * seven share the same bound: the workflow's scope, not a tail — the workflow's scope-end kind
 * clears them. [HostState.declinedEffects] is uncapped for the same reason as the stall record, and
 * is not scope-bound: it holds one digest per distinct pending intent key adopt declined, since a
 * declined intent stays pending across scopes. Each entry costs its writer a journal row. All
 * their kinds are origin-gated, so only the substrate and the authorization layer can grow them: a
 * party positioned to flood them could already write worse. */
internal const val ANOMALY_TAIL = 100

/** The one reason the lead writes on a [HostKinds.POD_SPAWN_ABANDONED] entry; the fold quotes
 * a reason only when it is this one. */
const val ORPHANED_SPAWN_REASON =
  "spawn intent orphaned at restart (pod may or may not have started; re-proposing)"

/** A fold failure with its position identified — a malformed payload on a known kind
 * (field missing, wrong type) is chain corruption or payload-contract drift, and it must
 * fail CLASSIFIED (seq + kind named) rather than as an anonymous NPE boot-loop. The message
 * takes [foldFaultMessage]'s form, so it quotes nothing from the entry's payload. */
class LeadFoldException(seq: Long, kind: String, cause: Throwable) :
  RuntimeException(foldFaultMessage("lead fold", seq, kind, cause), cause)
