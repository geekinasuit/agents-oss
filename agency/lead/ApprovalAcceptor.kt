package com.geekinasuit.agency.lead

import com.geekinasuit.agency.lead.LeadAuth.Companion.UNLISTED_PRINCIPAL_ID
import com.geekinasuit.agency.lead.PayloadReaders.str
import com.geekinasuit.agency.pod.sha256HexBytes
import com.geekinasuit.agency.shared.auth.ApprovalEvidence
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.journal.ArmedTimer
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.JournalStore
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import com.geekinasuit.agency.shared.journal.payloadObject
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

/**
 * One approval as a carrier delivers it: the gate, nonce and digest it claims to approve, and the
 * evidence that proves it. Nothing here is trusted. The principal is not part of it: the host
 * resolves it from the key the evidence names ([AgentHost.injectApproval]).
 */
data class ApprovalCandidate(val gateId: String, val nonce: String, val payloadDigest: String, val evidence: JsonObject)

/** What [AgentHost.injectApproval] did with one [ApprovalCandidate]. Only [RECORDED], [RELEASED] and
 * [REJECTED] append. */
enum class ApprovalAccept {
  /** The approval re-verified and was new; its row is in the journal. It released nothing: it did not
   * complete the gate's quorum, or the fold would not honor a release with it (the gate is already
   * released on its digest). */
  RECORDED,

  /**
   * The approval re-verified, was new, and completed the gate's quorum: its row, marked as completing
   * it, and the gate's release are in the journal, and the loop has been woken. The fold decides the
   * release when it folds it, as it decides every release, so a row the loop appended between the
   * two (a scope end, a consumed nonce) leaves the release stale.
   */
  RELEASED,

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

  /** The row would exceed [ApprovalAcceptor.MAX_APPROVAL_ROW_CHARS]; it is refused whole, never cut.
   * The row is measured as it would be journaled, with any field the acceptor adds, so an approval
   * that completes the quorum can be refused where the same approval below it would be recorded. */
  OVERSIZED,
}

/** Ends a host's loop ([AgentHost.runLoop]) when its approval accept boundary has stopped: the host
 * would run on with every approval refused. The boundary has escalated why, unless the journal
 * refused that too. */
class ApprovalBoundaryStoppedException(reason: String) : IllegalStateException(reason)

/**
 * The host's approval accept boundary: it decides on each candidate against the host's records as the
 * journal stands at that moment, and journals what it keeps on the calling thread.
 *
 * Each [accept] runs under one lock, so checks and appends are serialized whoever calls. Under it:
 * 1. A stopped acceptor ([stop]) refuses by throwing, and appends nothing.
 * 2. The view of the journal ([IncrementalLeadView]) is advanced from the store's tail, so a nonce
 *    the loop thread issued an instant ago is seen. The first call reads from genesis. Then the
 *    repair runs (below), so a release it writes is in the view the candidate is decided against.
 * 3. The bounding: a candidate whose gate is not open, whose nonce is not the gate's open nonce
 *    ([HostView.openNonceFor]), or whose digest is not the one that nonce is bound to, is dropped.
 * 4. A row over [MAX_APPROVAL_ROW_CHARS] is dropped. The bound is on the row as it would be
 *    journaled, so it bounds the journal and the memory of every later fold.
 * 5. The candidate is classified by the fold's own code ([classifyApproval]). A verified approval
 *    the journal does not hold yet is appended with the authorization layer's origin. A duplicate is
 *    dropped, since the journal holds it already. A rejected one is appended only as its claimed
 *    key's allowance on the nonce, below.
 * 6. When a release naming the nonce would be honored with the verified approvers bound to the gate
 *    at it plus the new approval ([honorsNonceRelease], the fold's own decision, so the quorum and
 *    the single release per digest are judged as the fold judges them), the approval's row is marked
 *    `completesQuorum: true`, the gate's release naming the nonce is appended after it, and only
 *    then is the loop woken ([ring]), so the loop wakes to a journal that holds the release.
 *
 * The mark records the acceptor's own decision, under the auth in force when the row was appended.
 * The fold reads only the fields it names, so it ignores the mark. Only a verified-new approval
 * decides a release: an approval already journaled that a loosened auth would now count releases
 * nothing here.
 *
 * The repair ([repair]) writes the release a marked row lacks, when a crash or a failed append came
 * between the two. It runs before each [accept] decides, when the host adopts the journal ([prime]),
 * and when the ingress timer fires, which a failed release arms. It releases only on a marked row whose
 * own approval still verifies under the auth in force, and only where the fold would honor the
 * release now ([honorsNonceRelease]); it wakes the loop once per release it writes.
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
 * Drops: a candidate that names a gate's open nonce and is dropped (a duplicate, a wrong digest, a
 * rejection over its key's allowance, or a row too large) is counted on that nonce in memory. Once
 * the nonce has closed, the next pass journals one `approval-drops-summarized` row for it with the
 * counts and the first dropped attempt's evidence, then forgets them ([flush]). The counts start
 * over at a restart; each row's `countsSince` shows when they started. An attempt that names no open
 * nonce is counted by the hour instead, from `countsSince`, and each hour with a count gets one
 * `approval-drops-aggregated` row once it has ended ([flushAggregates]).
 *
 * The lock is taken before the store's own, never while holding it, so the lock order is always this
 * lock, then the store's.
 *
 * When the view fails to advance (a chain fault in the tail, an entry the fold refuses, a store
 * error), the acceptor stops: the failure is escalated and thrown, and every later [accept] throws
 * until the host restarts. The view cannot be trusted after such a failure. So the acceptor tells the
 * host ([stopped]), which ends its loop for a supervisor to restart it, whatever the loop's own read
 * of the journal would say: a transient store error can leave that read healthy while approvals are
 * refused.
 *
 * A failure between an approval's marked row and its doorbell does not stop the acceptor: the repair
 * retries the release. It is escalated once per nonce, however many retries fail, since an untrusted
 * caller drives the accepts that retry it.
 */
internal class ApprovalAcceptor<S>(
  private val store: JournalStore,
  private val auth: LeadAuth,
  private val fold: WorkflowFold<S, *>,
  private val faults: FaultInjector,
  private val escalate: (String) -> Unit,
  /** Arms the ingress timer ([armTimer]). Its firing calls back into the acceptor, not the loop. */
  private val timers: TimerService,
  /** How long after it is armed the ingress timer fires. */
  private val tickMs: Long,
  /** The wall clock, in epoch milliseconds: the timer's due time, `countsSince`, and the hour an
   * attempt naming no open nonce is counted in. */
  private val clock: () -> Long,
  /** Wakes the loop for the release of a gate on a digest, after the release is journaled. */
  private val ring: (gateId: String, payloadDigest: String) -> Unit,
  /** Told why, once, when the view's failure to advance stops the acceptor, after the escalation. Not
   * told for a [stop] the host makes itself. */
  private val stopped: (reason: String) -> Unit,
) {
  private val lock = Any()
  private var view: IncrementalLeadView<S, *>? = null
  private var stoppedBecause: String? = null

  /** Why the view's failure to advance stopped the acceptor, or null while it has not. A [stop] the
   * host makes itself does not set it. Read without the lock, so the loop can check it before each
   * wake without waiting on an accept. */
  @Volatile var failure: String? = null
    private set

  /** Nonce issued and not consumed → the claimed keys whose rejected row the journal holds on it;
   * null is the unlisted bucket. */
  private val rejectedBuckets = mutableMapOf<String, MutableSet<SchemeKey?>>()

  /** Nonce issued and not consumed → the marked rows on it that verify ([tally]); the repair's
   * candidates. */
  private val marked = mutableMapOf<String, MarkedNonce>()

  /** Nonces whose failed release has been escalated ([releaseFailed]). */
  private val repairEscalated = mutableSetOf<String>()

  /** Whether the ingress timer is armed and has not fired yet. */
  private var timerArmed = false

  /** Nonce → the attempts dropped on it while it was open, until its summary is journaled ([flush]).
   * An entry is made only for a nonce some candidate named as the open nonce of an open gate. */
  private val drops = linkedMapOf<String, NonceDrops>()

  /** When this acceptor started counting drops; every summary and aggregate carries it, so counts a
   * restart reset show as such. The aggregate's intervals are laid out from it. */
  private val countsSince = clock()

  /** Interval index ([intervalOf]) → the attempts in it that named no open nonce, until its aggregate
   * is journaled ([flushAggregates]). Only intervals with a count are present. */
  private val notOpen = linkedMapOf<Long, Int>()

  /** Stops the acceptor: every later [accept] throws. The first reason is kept. */
  fun stop(reason: String) {
    synchronized(lock) { if (stoppedBecause == null) stoppedBecause = reason }
  }

  /** Whether an approval could count now: some open gate holds an open nonce, and the acceptor has
   * not stopped. Appends nothing. A failure to advance the view stops the acceptor and throws, as it
   * does in [accept]. */
  fun awaited(): Boolean =
    synchronized(lock) {
      if (stoppedBecause != null) return false
      val host = advance()
      host.openGates.values.any { host.openNonceFor(it) != null }
    }

  /** Decides on [candidate], appending only when it is [ApprovalAccept.RECORDED],
   * [ApprovalAccept.RELEASED] or [ApprovalAccept.REJECTED]. */
  fun accept(candidate: ApprovalCandidate): ApprovalAccept =
    synchronized(lock) {
      stoppedBecause?.let { throw IllegalStateException("approval refused: the approval boundary has stopped ($it)") }
      val host = flush(repair(advance()))
      val gate = host.openGates[candidate.gateId] ?: return notOpenDropped()
      val open = host.openNonceFor(gate)
      if (open == null || open.nonce != candidate.nonce) return notOpenDropped()
      val (evidence, evidenceRefusal) = parseEvidence(candidate)
      if (candidate.payloadDigest != open.payloadDigest) {
        return dropped(open, evidence, ApprovalAccept.WRONG_DIGEST) { wrongDigest++ }
      }
      val payload = payloadOf(candidate, evidence)
      if (!fits(payload)) return dropped(open, evidence, ApprovalAccept.OVERSIZED) { oversized++ }
      when (val verdict = classifyApproval(host.verifiedApprovals, payload, UNJOURNALED_SEQ, auth)) {
        is ApprovalVerdict.VerifiedNew -> {
          val approvers = host.boundApprovers(gate, open.nonce) + verdict.approval.principalId
          if (!honorsNonceRelease(host, gate.gateId, open.payloadDigest, open.nonce, approvers, auth)) {
            append(payload)
            return ApprovalAccept.RECORDED
          }
          val markedRow = JsonObject(payload + ("completesQuorum" to JsonPrimitive(true)))
          if (!fits(markedRow)) return dropped(open, evidence, ApprovalAccept.OVERSIZED) { oversized++ }
          // Once the marked row may be durable, a failure may leave a met quorum with no release. The
          // repair writes it: at the next accept, a redelivery of this one included, or when the
          // ingress timer fires. So the failure is escalated and thrown, and the acceptor goes on.
          try {
            append(markedRow)
            journalRelease(gate.gateId, open.payloadDigest, open.nonce)
          } catch (x: Exception) {
            releaseFailed(gate.gateId, open.nonce, x)
            throw x
          }
          wake(gate.gateId, open.payloadDigest)
          ApprovalAccept.RELEASED
        }
        is ApprovalVerdict.VerifiedDuplicate ->
          dropped(open, evidence, ApprovalAccept.DUPLICATE) {
            duplicates++
            originalSeqs += verdict.originalSeq
          }
        is ApprovalVerdict.Rejected -> {
          if (verdict.claimedKey in rejectedBuckets[candidate.nonce].orEmpty()) {
            return dropped(open, evidence, ApprovalAccept.REJECTED_OVER_ALLOWANCE) {
              val key = verdict.claimedKey
              if (key == null) overAllowanceUnlisted++ else overAllowance[key] = (overAllowance[key] ?: 0) + 1
            }
          }
          // Evidence that did not parse is classified as the empty object payloadOf writes, so its
          // verdict names the first field that object lacks; the reason names what the candidate's
          // own evidence lacks instead.
          val reason = evidenceRefusal ?: verdict.reason
          val row =
            JsonObject(
              payload +
                ("principalId" to JsonPrimitive(UNLISTED_PRINCIPAL_ID)) +
                ("rejectedReason" to JsonPrimitive(reason))
            )
          if (!fits(row)) return dropped(open, evidence, ApprovalAccept.OVERSIZED) { oversized++ }
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

  /** Appends the gate's release naming [nonce] under the authorization layer's origin. */
  private fun journalRelease(gateId: String, payloadDigest: String, nonce: String) {
    faults.at(FAULT_BEFORE_RELEASE)
    store.append(
      KIND_GATE_RELEASED,
      buildJsonObject {
        put("gateId", gateId)
        put("payloadDigest", payloadDigest)
        put("nonce", nonce)
      },
      origin = ORIGIN_AUTH_LAYER,
    )
  }

  /** Wakes the loop for a release just journaled. A crash before it loses nothing: the restarted
   * host folds the release. */
  private fun wake(gateId: String, payloadDigest: String) {
    faults.at(FAULT_AFTER_RELEASE)
    ring(gateId, payloadDigest)
  }

  private fun fits(row: JsonObject): Boolean = row.toString().length <= MAX_APPROVAL_ROW_CHARS

  private fun advance(): HostState = stoppingOnFailure {
    val v = view ?: IncrementalLeadView(store, auth, fold).also { view = it }
    val folded = v.advance()
    val host = v.host
    tally(folded, host)
    host
  }

  /**
   * Runs the repair from the loop thread as the host adopts the journal, so a release a crash cut
   * short lands before the loop's first wake. It never throws. A view that fails to advance stops the
   * acceptor (escalated, and told to [stopped], as at any accept), which ends the loop before its first
   * wake; a release that fails is escalated and retried on the timer, which does not.
   */
  fun prime() {
    synchronized(lock) { repairQuietly() }
  }

  /**
   * The ingress timer's firing: the repair, as at [prime], then the timer again while work is still
   * due ([workDue]). So a firing whose own re-arm the [TimerService] refused, inside the pass, arms
   * here instead. A refusal here leaves the timer unarmed until the next failed release arms it;
   * nothing is left on this thread to report to.
   */
  private fun onTimerDue() {
    synchronized(lock) {
      timerArmed = false
      val host = repairQuietly() ?: return
      if (workDue(host)) {
        try {
          armTimer()
        } catch (_: Exception) {
          // See the KDoc: the next failed release arms it.
        }
      }
    }
  }

  /** Whether the ingress timer must come back to [host]: some marked row the repair would release
   * ([repairable]) still lacks its release, as after a release that failed, or some nonce's drops are
   * not summarized yet, or some hour's count of attempts naming no open nonce is not aggregated yet.
   * A nonce that stays open, or an hour not yet over, keeps the timer coming back. */
  private fun workDue(host: HostState): Boolean =
    drops.isNotEmpty() || notOpen.isNotEmpty() || marked.any { (nonce, m) -> repairable(host, nonce, m) }

  /** The repair and the summaries, catching what they do not handle themselves; the host as the
   * journal then stands, or null when the acceptor is stopped or a doorbell after a release threw. In
   * the second case a firing does not arm the timer again, as before the ingress timer; only the test
   * fault seam can make a doorbell throw. */
  private fun repairQuietly(): HostState? {
    if (stoppedBecause != null) return null
    return try {
      flush(repair(advance()))
    } catch (_: Exception) {
      // advance() has stopped the acceptor and escalated why. repair() handles a failed release
      // itself; only the doorbell after a release it wrote is outside that, and a lost doorbell loses
      // nothing the next wake does not fold.
      null
    }
  }

  /** Whether the repair would release [nonce]'s marked row [m] over [host] now. */
  private fun repairable(host: HostState, nonce: String, m: MarkedNonce): Boolean {
    val gate = host.openGates[m.gateId] ?: return false
    return honorsNonceRelease(host, m.gateId, m.payloadDigest, nonce, host.boundApprovers(gate, nonce), auth)
  }

  /**
   * Appends the release each repairable marked row lacks, and returns the host as the journal then
   * stands. The candidates are the marked rows whose own approval still verifies under the auth in
   * force ([tally] notes no other), and one is repaired when a release naming its nonce would be
   * honored now ([honorsNonceRelease]). So a marked row whose approver was revoked, or whose quorum
   * the auth in force no longer meets, is not repaired, and no row that was never marked is: a
   * loosened auth alone releases nothing.
   *
   * A release that fails is escalated and left to the ingress timer, and the repair goes on to the next
   * marked nonce, so a release that keeps failing for one nonce does not hold back another; the next
   * advance shows whether it landed. The view is not advanced after a failure, so if the failed
   * release landed after all, a later marked nonce on the same gate and digest (a journal the lead
   * did not write) can get a release in the same pass. That one folds stale: the gate is released
   * once, at the cost of an anomaly row and a doorbell.
   */
  private fun repair(host: HostState): HostState {
    var h = host
    for ((nonce, m) in marked.toList()) {
      if (!repairable(h, nonce, m)) continue
      try {
        journalRelease(m.gateId, m.payloadDigest, nonce)
      } catch (x: Exception) {
        releaseFailed(m.gateId, nonce, x)
        continue
      }
      wake(m.gateId, m.payloadDigest)
      h = advance()
    }
    return h
  }

  /**
   * A marked row on [nonce] may be journaled without its release, for [x]: escalates that once per
   * nonce for the life of this acceptor, since an untrusted caller drives every retry, and arms the
   * ingress timer.
   */
  private fun releaseFailed(gateId: String, nonce: String, x: Exception) {
    // The nonce is noted only once its escalation is journaled, so a store that refuses the
    // escalation too is asked again at the next failure; a refused append adds no row.
    if (nonce !in repairEscalated) {
      try {
        escalate(
          "an approval completing the quorum of gate $gateId may be journaled without its release: " +
            (x.message ?: x::class.qualifiedName ?: "unknown") + " — the release is retried"
        )
        repairEscalated += nonce
      } catch (journalFailure: Exception) {
        x.addSuppressed(journalFailure)
      }
    }
    try {
      armTimer()
    } catch (timerFailure: Exception) {
      x.addSuppressed(timerFailure)
    }
  }

  /**
   * Arms the ingress timer unless it is armed already. A [TimerService] that throws leaves it
   * unarmed, so the next failed release, or the end of a firing with work still due, tries again.
   * The timer must fire after [arm][TimerService.arm]
   * returns, as [ThreadTimerService] does: one that fired inside it would retry a release that keeps
   * failing with no delay at all.
   */
  private fun armTimer() {
    if (timerArmed) return
    timerArmed = true
    try {
      timers.arm(ArmedTimer(TIMER_ID, clock() + tickMs, TIMER_ACTION)) { onTimerDue() }
    } catch (x: Exception) {
      timerArmed = false
      throw x
    }
  }

  /** Runs [block]; when it throws, stops the acceptor, escalates why, tells [stopped], and rethrows. */
  private inline fun <T> stoppingOnFailure(block: () -> T): T =
    try {
      block()
    } catch (x: Exception) {
      val reason = "approval boundary stopped: " + (x.message ?: x::class.qualifiedName ?: "unknown")
      stoppedBecause = reason
      failure = reason
      try {
        escalate(reason)
      } catch (journalFailure: Exception) {
        x.addSuppressed(journalFailure)
      }
      stopped(reason)
      throw x
    }

  /**
   * Reads the approval rows in [folded] into the acceptor's records: marks the bucket of every
   * rejected row used on its nonce, and notes the nonce of every row marked `completesQuorum` whose
   * approval verifies, for the repair. Then it keeps only the nonces issued and not
   * consumed in [host]. That is wider than the open set on purpose: an issued nonce that is not open
   * can open again (its gate re-opened on the digest it is bound to, or a newer nonce for that digest
   * consumed), and its records must still be there when it does, as they would be after a restart. A
   * consumed nonce never opens again.
   *
   * A row is read as the fold reads it: only the authorization layer's origin, parsed by
   * [payloadObject], classified by [classifyApproval] under the auth in force. So a marked row of any
   * other origin, or one whose approval no longer verifies, is never noted. [folded] has just been
   * folded without a failure, so neither throws here.
   */
  private fun tally(folded: List<JournalEntry>, host: HostState) {
    for (e in folded) {
      if (e.kind != HostKinds.APPROVAL_RECORDED || e.origin != ORIGIN_AUTH_LAYER) continue
      val p = payloadObject(e.payloadJson)
      when (val verdict = classifyApproval(emptyMap(), p, e.seq, auth)) {
        is ApprovalVerdict.Rejected -> rejectedBuckets.getOrPut(p.str("nonce")) { mutableSetOf() } += verdict.claimedKey
        is ApprovalVerdict.VerifiedNew ->
          if (p["completesQuorum"] == JsonPrimitive(true)) {
            marked[verdict.approval.nonce] = MarkedNonce(verdict.gateId, verdict.approval.payloadDigest)
          }
        is ApprovalVerdict.VerifiedDuplicate -> Unit // not reached: nothing is held to duplicate
      }
    }
    val live = host.issuedNonces.keys - host.consumedNonces
    rejectedBuckets.keys.retainAll(live)
    marked.keys.retainAll(live)
    repairEscalated.retainAll(live)
  }

  /** The gate and digest a nonce some verifying marked row names was bound to. */
  private data class MarkedNonce(val gateId: String, val payloadDigest: String)

  /**
   * The attempts dropped on one nonce, bound to [gateId] and [payloadDigest]. A rejected attempt
   * journaled within its key's allowance is not a drop. [overAllowance] is keyed by the allow-listed
   * key the attempt claimed, [overAllowanceUnlisted] counts the rest, so its size is bounded by the
   * allow-list; the claims are unauthenticated.
   */
  private class NonceDrops(val gateId: String, val payloadDigest: String) {
    var duplicates = 0
    val originalSeqs = sortedSetOf<Long>()
    val overAllowance = linkedMapOf<SchemeKey, Int>()
    var overAllowanceUnlisted = 0
    var wrongDigest = 0
    var oversized = 0

    /** Whether the first drop has been seen; its evidence, if it parsed, is [firstDropped]. */
    var firstSeen = false
    var firstDropped: JsonObject? = null
  }

  /** [c]'s evidence and null, or null and why it does not parse, as the classifier words it. */
  private fun parseEvidence(c: ApprovalCandidate): Pair<ApprovalEvidence?, String?> =
    try {
      ApprovalEvidence.fromJson(c.evidence) to null
    } catch (x: Exception) {
      null to malformedEvidenceReason(x)
    }

  /**
   * Counts a candidate dropped on [open] with [count], keeps the evidence of the first one dropped
   * there ([firstDroppedOf]), arms the ingress timer so the nonce's summary is written even if
   * nothing else arrives, and returns [result]. A [TimerService] that refuses leaves that to the next
   * drop or failed release.
   */
  private inline fun dropped(
    open: IssuedNonce,
    evidence: ApprovalEvidence?,
    result: ApprovalAccept,
    count: NonceDrops.() -> Unit,
  ): ApprovalAccept {
    val d = drops.getOrPut(open.nonce) { NonceDrops(open.gateId, open.payloadDigest) }
    d.count()
    if (!d.firstSeen) {
      d.firstSeen = true
      d.firstDropped = evidence?.let(::firstDroppedOf)
    }
    try {
      armTimer()
    } catch (_: Exception) {
      // See the KDoc.
    }
    return result
  }

  /**
   * The `firstDropped` field for [evidence]: the evidence as it re-serializes, with only the fields
   * [ApprovalEvidence] knows (a carrier's other keys are signed by nothing), when that JSON's UTF-8
   * bytes number at most [MAX_FIRST_DROPPED_BYTES]; otherwise their count and SHA-256 (an unpaired
   * surrogate encodes as `?`), since cut evidence could not be verified again.
   */
  private fun firstDroppedOf(evidence: ApprovalEvidence): JsonObject {
    val json = evidence.toJson()
    val bytes = json.toString().toByteArray(Charsets.UTF_8)
    if (bytes.size <= MAX_FIRST_DROPPED_BYTES) return json
    return buildJsonObject {
      put("length", bytes.size)
      put("sha256", sha256HexBytes(bytes))
    }
  }

  /**
   * Writes the summary of every nonce with drops that has left the open set ([HostView.openNonceFor]
   * of an open gate), and forgets its counts once the row is journaled. Each summary names its own
   * nonce, so the order they are written in carries nothing. A nonce leaves the set when a release consumes it, a `nonce-consumed` row voids it, a
   * scope end clears it, its gate re-opens on another digest, or a newer nonce shadows it; the
   * summary lands at the first advance after the row that closed it. A summary the store refuses is
   * kept for the next pass, and the others are still tried, so one that keeps failing holds back
   * none. It is not escalated, unlike a failed release: a lost summary loses a count, never a gate's
   * release, and the store failure that refused it shows wherever else it bites. A nonce that opens
   * again after its summary gets a second summary for its later drops.
   *
   * A summary row is bounded however many attempts arrive: its keys are allow-listed, its
   * `originalSeqs` hold at most one seq per allow-listed principal (a duplicate is matched on
   * principal, nonce and digest), and `firstDropped` is at most [MAX_FIRST_DROPPED_BYTES] of
   * evidence or a length and a hash.
   *
   * Returns [host] unchanged: the rows are audit-only.
   */
  private fun flush(host: HostState): HostState {
    flushAggregates()
    if (drops.isEmpty()) return host
    val open = host.openGates.values.mapNotNullTo(mutableSetOf()) { host.openNonceFor(it)?.nonce }
    for ((nonce, d) in drops.toList()) {
      if (nonce in open) continue
      try {
        store.append(HostKinds.APPROVAL_DROPS_SUMMARIZED, summaryOf(nonce, d), origin = ORIGIN_AUTH_LAYER)
      } catch (_: Exception) {
        continue
      }
      drops.remove(nonce)
    }
    return host
  }

  /** Counts an attempt that named no open nonce in the current interval, arms the ingress timer so
   * the interval's aggregate is written after it ends, and returns [ApprovalAccept.NOT_OPEN]. */
  private fun notOpenDropped(): ApprovalAccept {
    val interval = intervalOf(clock())
    notOpen[interval] = (notOpen[interval] ?: 0) + 1
    try {
      armTimer()
    } catch (_: Exception) {
      // The next drop or failed release arms it.
    }
    return ApprovalAccept.NOT_OPEN
  }

  /**
   * The index of the interval [epochMs] falls in: intervals of [AGGREGATE_INTERVAL_MS] laid out from
   * [countsSince], by the wall clock, as decision 3 counts by the hour. A clock step moves counts
   * between intervals but loses none: after a backward step an interval already counted waits until
   * the clock passes its end again, and a step below [countsSince] gives a negative index, whose row's
   * `intervalStart` is before its `countsSince`. The map stays one entry per counted index.
   */
  private fun intervalOf(epochMs: Long): Long = Math.floorDiv(epochMs - countsSince, AGGREGATE_INTERVAL_MS)

  /**
   * Writes one `approval-drops-aggregated` row for every interval that has ended with a count, and
   * forgets it once the row is journaled. An interval with no count writes nothing, so a quiet hour
   * leaves no row. A row the store refuses is kept for the next pass, and the others are still tried;
   * it is not escalated, for the reason [flush] gives. One row an hour at most, so a sustained flood
   * costs rows by the hour, not by the attempt.
   */
  private fun flushAggregates() {
    if (notOpen.isEmpty()) return
    val current = intervalOf(clock())
    for ((interval, count) in notOpen.toList()) {
      if (interval >= current) continue
      try {
        store.append(
          HostKinds.APPROVAL_DROPS_AGGREGATED,
          buildJsonObject {
            put("notOpen", count)
            put("intervalStart", countsSince + interval * AGGREGATE_INTERVAL_MS)
            put("countsSince", countsSince)
          },
          origin = ORIGIN_AUTH_LAYER,
        )
      } catch (_: Exception) {
        continue
      }
      notOpen.remove(interval)
    }
  }

  private fun summaryOf(nonce: String, d: NonceDrops): JsonObject = buildJsonObject {
    put("gateId", d.gateId)
    put("nonce", nonce)
    put("payloadDigest", d.payloadDigest)
    put("countsSince", countsSince)
    put("duplicates", d.duplicates)
    putJsonArray("originalSeqs") { d.originalSeqs.forEach { add(it) } }
    putJsonArray("rejectedOverAllowance") {
      for ((key, n) in d.overAllowance) {
        addJsonObject {
          put("schemeId", key.schemeId)
          put("publicKey", key.publicKey)
          put("count", n)
        }
      }
    }
    put("rejectedOverAllowanceUnlisted", d.overAllowanceUnlisted)
    put("wrongDigest", d.wrongDigest)
    put("oversized", d.oversized)
    d.firstDropped?.let { put("firstDropped", it) }
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
  private fun payloadOf(c: ApprovalCandidate, evidence: ApprovalEvidence?): JsonObject {
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

    /** The fault point after an approval's row is appended, before anything after it. */
    const val FAULT_AFTER_APPEND = "approval-after-append"

    /** The fault point before a release is appended: after an approval's row marked as completing the
     * quorum, or in a repair. */
    const val FAULT_BEFORE_RELEASE = "approval-before-release"

    /** The fault point after the release is appended, before the loop is woken. */
    const val FAULT_AFTER_RELEASE = "approval-after-release"

    /**
     * The largest approval row the boundary journals, as JSON chars, measured before the store
     * escapes any surrogate pair (which adds a few chars per pair). A genuine row is a few hundred:
     * a key, a signature, a preimage over the gate, digest and nonce, and the carrier's id. The
     * carrier's id is signed by nothing, so without a bound a carrier could pad it, land the padded
     * copy first, and have the genuine one dropped as its duplicate, at whatever size it chose.
     */
    const val MAX_APPROVAL_ROW_CHARS = 4096

    /** The ingress timer's id. It is never journaled: a restart repairs at adopt, so a lost timer
     * loses nothing. */
    const val TIMER_ID = "approval-ingress"

    /** The ingress timer's action, carried for the [TimerService] seam; nothing reads it. */
    const val TIMER_ACTION = "approval-ingress"

    /** The ingress timer's period in a real run: a release that failed on a store error is tried
     * again, and pending drop counts are checked for a closed nonce, a minute after it is armed, if no
     * accept has done so first. */
    const val DEFAULT_TICK_MS = 60_000L

    /** The interval an `approval-drops-aggregated` row counts over: an hour (operator, 2026-10-29). */
    const val AGGREGATE_INTERVAL_MS = 3_600_000L

    /** The largest evidence a summary's `firstDropped` holds, as UTF-8 bytes of its JSON (4 KiB);
     * larger evidence is replaced by its length and hash. */
    const val MAX_FIRST_DROPPED_BYTES = 4096

    /** The seq [classifyApproval] is given for a candidate not journaled yet. The acceptor reads
     * only the verdict's kind, never this seq. */
    private const val UNJOURNALED_SEQ = -1L
  }
}
