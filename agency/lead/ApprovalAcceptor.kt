package com.geekinasuit.agency.lead

import com.geekinasuit.agency.lead.LeadAuth.Companion.UNLISTED_PRINCIPAL_ID
import com.geekinasuit.agency.lead.PayloadReaders.str
import com.geekinasuit.agency.shared.auth.ApprovalEvidence
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.JournalStore
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import com.geekinasuit.agency.shared.journal.payloadObject
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * One approval as a carrier delivers it: the gate, nonce and digest it claims to approve, and the
 * evidence that proves it. Nothing here is trusted. The principal is not part of it: the host
 * resolves it from the key the evidence names ([AgentHost.injectApproval]).
 */
data class ApprovalCandidate(val gateId: String, val nonce: String, val payloadDigest: String, val evidence: JsonObject)

/** What [AgentHost.injectApproval] did with one [ApprovalCandidate]. Only [RECORDED] and [REJECTED] append. */
enum class ApprovalAccept {
  /** The approval re-verified and was new; its row is in the journal. */
  RECORDED,

  /** The candidate names a gate that is not open, or a nonce that is not the gate's open nonce. */
  NOT_OPEN,

  /** The candidate names the gate's open nonce with a digest other than the one it is bound to. */
  WRONG_DIGEST,

  /** The approval re-verified, and the journal already holds it. */
  DUPLICATE,

  /** The approval did not re-verify, and its row is in the journal: the first rejected attempt the
   * journal holds for its claimed key on this nonce. It counts toward nothing. */
  REJECTED,

  /** The approval did not re-verify, and the journal already holds a rejected attempt for its
   * claimed key on this nonce, so nothing is appended. */
  REJECTED_OVER_ALLOWANCE,

  /** The row would exceed [ApprovalAcceptor.MAX_APPROVAL_ROW_CHARS]; it is refused whole, never cut. */
  OVERSIZED,
}

/**
 * The host's approval accept boundary: it decides on each candidate against the host's records as the
 * journal stands at that moment, and journals what it keeps on the calling thread.
 *
 * Each [accept] runs under one lock, so checks and appends are serialized whoever calls. Under it:
 * 1. A stopped acceptor ([stop]) refuses by throwing, and appends nothing.
 * 2. The view of the journal ([IncrementalLeadView]) is advanced from the store's tail, so a nonce
 *    the loop thread issued an instant ago is seen. The first call reads from genesis.
 * 3. The bounding: a candidate whose gate is not open, whose nonce is not the gate's open nonce
 *    ([HostView.openNonceFor]), or whose digest is not the one that nonce is bound to, is dropped.
 * 4. A row over [MAX_APPROVAL_ROW_CHARS] is dropped. The bound is on the row as it would be
 *    journaled, so it bounds the journal and the memory of every later fold.
 * 5. The candidate is classified by the fold's own code ([classifyApproval]). A verified approval
 *    the journal does not hold yet is appended with the authorization layer's origin. A duplicate is
 *    dropped, since the journal holds it already. A rejected one is appended only as its claimed
 *    key's allowance on the nonce, below.
 *
 * The allowance: on each open nonce, the journal holds at most one rejected row per claimed key
 * ([ApprovalVerdict.Rejected.claimedKey], an allow-listed key the evidence names consistently), and
 * one more for every other rejection, the unlisted bucket. So a flood of rejected attempts on a nonce
 * adds at most one row per allow-listed key, plus one; and attempts whose evidence disagrees with
 * itself fall in the unlisted bucket, so they cannot use up a listed key's allowance. A verified
 * approval is never held back by an allowance. A rejected row names [UNLISTED_PRINCIPAL_ID], whatever
 * key it claims, so the journal never names a principal on an approval that principal may not have
 * made; the key it claims stays in its evidence.
 *
 * The tally of allowances used is read from the journal: every authorization-layer approval row the
 * view folds is classified again, and its bucket is marked used on its nonce. So it is rebuilt when a
 * new view reads from genesis, and a restart neither resets nor loses it. It is classified under the
 * auth in force, so a key added to or taken out of the allow-list across a restart moves the rows it
 * claims between its bucket and the unlisted one, as the fold re-decides those rows under that auth.
 * The tally keeps only the nonces issued and not consumed, which bounds it by the scope's nonces and
 * the allow-list: a scope end clears the issued nonces.
 *
 * The lock is taken before the store's own, never while holding it, so the lock order is always this
 * lock, then the store's.
 *
 * When the view fails to advance (a chain fault in the tail, an entry the fold refuses, a store
 * error), the acceptor stops: the failure is escalated and thrown, and every later [accept] throws
 * until the host restarts. The view cannot be trusted after such a failure. Nothing here restarts the
 * host: a chain fault also stops the loop at its next wake, but that wake may be far off, and a
 * transient store error may never reach the loop at all. Until a restart, the escalation is the only
 * signal that approvals are refused.
 */
internal class ApprovalAcceptor<S>(
  private val store: JournalStore,
  private val auth: LeadAuth,
  private val fold: WorkflowFold<S, *>,
  private val faults: FaultInjector,
  private val escalate: (String) -> Unit,
) {
  private val lock = Any()
  private var view: IncrementalLeadView<S, *>? = null
  private var stoppedBecause: String? = null

  /** Nonce issued and not consumed → the claimed keys whose rejected row the journal holds on it;
   * null is the unlisted bucket. */
  private val rejectedBuckets = mutableMapOf<String, MutableSet<SchemeKey?>>()

  /** Stops the acceptor: every later [accept] throws. The first reason is kept. */
  fun stop(reason: String) {
    synchronized(lock) { if (stoppedBecause == null) stoppedBecause = reason }
  }

  /** Decides on [candidate], appending its row only when it is [ApprovalAccept.RECORDED] or
   * [ApprovalAccept.REJECTED]. */
  fun accept(candidate: ApprovalCandidate): ApprovalAccept =
    synchronized(lock) {
      stoppedBecause?.let { throw IllegalStateException("approval refused: the approval boundary has stopped ($it)") }
      val host = advance()
      val gate = host.openGates[candidate.gateId] ?: return ApprovalAccept.NOT_OPEN
      val open = host.openNonceFor(gate)
      if (open == null || open.nonce != candidate.nonce) return ApprovalAccept.NOT_OPEN
      if (candidate.payloadDigest != open.payloadDigest) return ApprovalAccept.WRONG_DIGEST
      val payload = payloadOf(candidate)
      if (!fits(payload)) return ApprovalAccept.OVERSIZED
      when (val verdict = classifyApproval(host.verifiedApprovals, payload, UNJOURNALED_SEQ, auth)) {
        is ApprovalVerdict.VerifiedNew -> {
          append(payload)
          ApprovalAccept.RECORDED
        }
        is ApprovalVerdict.VerifiedDuplicate -> ApprovalAccept.DUPLICATE
        is ApprovalVerdict.Rejected -> {
          if (verdict.claimedKey in rejectedBuckets[candidate.nonce].orEmpty()) {
            return ApprovalAccept.REJECTED_OVER_ALLOWANCE
          }
          val row = JsonObject(payload + ("principalId" to JsonPrimitive(UNLISTED_PRINCIPAL_ID)))
          if (!fits(row)) return ApprovalAccept.OVERSIZED
          append(row)
          ApprovalAccept.REJECTED
        }
      }
    }

  private fun append(row: JsonObject) {
    faults.at(FAULT_BEFORE_APPEND)
    store.append(HostKinds.APPROVAL_RECORDED, row, origin = ORIGIN_AUTH_LAYER)
    faults.at(FAULT_AFTER_APPEND)
  }

  private fun fits(row: JsonObject): Boolean = row.toString().length <= MAX_APPROVAL_ROW_CHARS

  private fun advance(): HostState =
    try {
      val v = view ?: IncrementalLeadView(store, auth, fold).also { view = it }
      val folded = v.advance()
      val host = v.host
      tallyRejected(folded, host)
      host
    } catch (x: Exception) {
      val reason = "approval boundary stopped: " + (x.message ?: x::class.qualifiedName ?: "unknown")
      stoppedBecause = reason
      try {
        escalate(reason)
      } catch (journalFailure: Exception) {
        x.addSuppressed(journalFailure)
      }
      throw x
    }

  /**
   * Marks the bucket of every rejected approval row in [folded] used on its nonce, then keeps only
   * the nonces issued and not consumed in [host]. That is wider than the open set on purpose: an
   * issued nonce that is not open can open again (its gate re-opened on the digest it is bound to,
   * or a newer nonce for that digest consumed), and its tally must still be there when it does, as
   * it would be after a restart. A consumed nonce never opens again.
   *
   * A row is read as the fold reads it: only the authorization layer's origin, parsed by
   * [payloadObject], classified by [classifyApproval]. [folded] has just been folded without a
   * failure, so neither throws here.
   */
  private fun tallyRejected(folded: List<JournalEntry>, host: HostState) {
    for (e in folded) {
      if (e.kind != HostKinds.APPROVAL_RECORDED || e.origin != ORIGIN_AUTH_LAYER) continue
      val p = payloadObject(e.payloadJson)
      val verdict = classifyApproval(emptyMap(), p, e.seq, auth)
      if (verdict is ApprovalVerdict.Rejected) {
        rejectedBuckets.getOrPut(p.str("nonce")) { mutableSetOf() } += verdict.claimedKey
      }
    }
    rejectedBuckets.keys.retainAll(host.issuedNonces.keys - host.consumedNonces)
  }

  /**
   * The row for [c]: its fields, and the principal the key its evidence names resolves to in the
   * allow-list. A key not in the allow-list, or evidence that does not parse, resolves to no
   * principal, so the row carries [UNLISTED_PRINCIPAL_ID]; the fold rejects such a row on its key
   * before it compares the principal.
   *
   * Evidence that parses is written as it re-serializes, with only the fields [ApprovalEvidence]
   * knows: a carrier's other keys are signed by nothing, and would otherwise reach the journal.
   * Evidence that does not parse is written as an empty object, for the same reason; the row is
   * rejected either way.
   */
  private fun payloadOf(c: ApprovalCandidate): JsonObject {
    val evidence =
      try {
        ApprovalEvidence.fromJson(c.evidence)
      } catch (_: Exception) {
        null
      }
    val principalId =
      evidence?.let { auth.allowList.principalFor(SchemeKey(it.schemeId, it.publicKey))?.principalId }
        ?: UNLISTED_PRINCIPAL_ID
    return buildJsonObject {
      put("gateId", c.gateId)
      put("principalId", principalId)
      put("nonce", c.nonce)
      put("payloadDigest", c.payloadDigest)
      put("evidence", evidence?.toJson() ?: JsonObject(emptyMap()))
    }
  }

  companion object {
    /** The fault point after a candidate is classified and its row is decided on, before the row is
     * appended. */
    const val FAULT_BEFORE_APPEND = "approval-before-append"

    /** The fault point after an approval's row is appended, before [accept] returns. */
    const val FAULT_AFTER_APPEND = "approval-after-append"

    /**
     * The largest approval row the boundary journals, as JSON chars, measured before the store
     * escapes any surrogate pair (which adds a few chars per pair). A genuine row is a few hundred:
     * a key, a signature, a preimage over the gate, digest and nonce, and the carrier's id. The
     * carrier's id is signed by nothing, so without a bound a carrier could pad it, land the padded
     * copy first, and have the genuine one dropped as its duplicate, at whatever size it chose.
     */
    const val MAX_APPROVAL_ROW_CHARS = 4096

    /** The seq [classifyApproval] is given for a candidate not journaled yet. The acceptor reads
     * only the verdict's kind, never this seq. */
    private const val UNJOURNALED_SEQ = -1L
  }
}
