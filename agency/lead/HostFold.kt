package com.geekinasuit.agency.lead

import com.geekinasuit.agency.lead.PayloadReaders.jsonStringOrNull
import com.geekinasuit.agency.lead.PayloadReaders.marksRetry
import com.geekinasuit.agency.lead.PayloadReaders.marksTrue
import com.geekinasuit.agency.lead.PayloadReaders.str
import com.geekinasuit.agency.lead.PayloadReaders.strOrNull
import com.geekinasuit.agency.shared.auth.ApprovalEvidence
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.parseCommitted
import com.geekinasuit.agency.shared.auth.quorumSatisfied
import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.payloadObject
import com.geekinasuit.agency.shared.journal.requireContract
import kotlinx.serialization.json.JsonObject

/**
 * The host's half of the lead fold: the records every agent keeps, whatever workflow it runs —
 * gates, nonces, approvals, releases, announces, pods, escalations, spend. A workflow assembles
 * its lead's state from this and its own half ([foldLeadJournal]), and the host reads that state
 * through [HostView], whose fields mean what the fields of the same name here mean.
 */
internal data class HostState(
  val runsStarted: Int = 0,
  val openGates: Map<String, OpenGate> = emptyMap(),
  val releasedGates: Set<String> = emptySet(),
  val releasedDigests: Map<String, Set<String>> = emptyMap(),
  val nonceLessReleases: Map<String, Long> = emptyMap(),
  val staleReleases: List<Pair<Long, String>> = emptyList(),
  val issuedNonces: Map<String, IssuedNonce> = emptyMap(),
  val consumedNonces: Set<String> = emptySet(),
  val notifiedNonces: Set<String> = emptySet(),
  val failedAnnounces: Map<String, Int> = emptyMap(),
  val notReadAnnounces: Map<String, Int> = emptyMap(),
  val verifiedApprovals: Map<String, List<VerifiedApproval>> = emptyMap(),
  val unverifiedApprovals: List<Pair<Long, String>> = emptyList(),
  val pods: Map<String, PodRecord> = emptyMap(),
  val pendingSpawnIntents: Map<String, Long> = emptyMap(),
  val misOriginedEntries: List<Pair<Long, String>> = emptyList(),
  val statusTail: List<String> = emptyList(),
  val escalations: List<String> = emptyList(),
  val escalatedStalls: Map<String, Set<String>> = emptyMap(),
  val declinedEffects: Set<String> = emptySet(),
  val malformedCognition: List<Pair<Long, String>> = emptyList(),
  val cognitionSpendUsd: Double = 0.0,
)

/**
 * What the host step did with an entry, for the workflow step that follows it. The workflow reads
 * this, not a comparison of the host state before and after: a capped tail such as
 * [HostState.misOriginedEntries] stops growing at its cap, so a diff cannot tell a rejected entry
 * from an accepted one.
 */
internal sealed interface HostOutcome {
  /** The provenance gate refused the entry; nothing about it may advance any state. */
  data object Rejected : HostOutcome

  /** The entry passed the provenance gate; any host change it made carries no workflow signal. */
  data object Folded : HostOutcome

  /** A gate was opened (or re-opened) by this entry. */
  data class GateOpened(val gate: OpenGate) : HostOutcome

  /** A release of [gate] was honored by this entry. A stale release is [Folded]. */
  data class GateReleased(val gate: OpenGate) : HostOutcome

  /** A pod's spawn was recorded by this entry. */
  data class PodSpawned(val pod: PodRecord) : HostOutcome

  /** A result was recorded by this entry for a pod the host knows. */
  data class PodResultRecorded(val pod: PodRecord) : HostOutcome
}

internal data class HostStep(val state: HostState, val outcome: HostOutcome)

/** The lead kinds the host authors as substrate. The workflow passes its own to [hostStep]; any
 * kind in either set arriving with a non-substrate origin is never honored — see the provenance
 * gate in [hostStep]. COGNITION_PROPOSED is excluded (legitimately cognition-origin); GATE_RELEASED
 * is not a lead kind — its auth-origin check lives in foldRelease. State-inert kinds (POD_EVENT —
 * no fold arm consumes them) are still listed: "never honored" is vacuous for them, but a forged
 * row must land in [HostState.misOriginedEntries] rather than fold invisibly — the audit half of
 * the origin gate applies to every substrate-only kind, not just the state-carrying ones. */
internal val HOST_SUBSTRATE_KINDS =
  setOf(
    HostKinds.RUN_STARTED,
    HostKinds.STATUS_WRITTEN,
    HostKinds.ESCALATED,
    HostKinds.GATE_OPENED,
    HostKinds.GATE_OPEN_NOTIFIED,
    HostKinds.POD_SPAWNED,
    HostKinds.POD_RESULT_RECORDED,
    HostKinds.POD_ABANDONED,
    HostKinds.POD_SPAWN_INTENDED,
    HostKinds.POD_SPAWN_ABANDONED,
    HostKinds.POD_EVENT,
    HostKinds.COGNITION_MALFORMED,
    HostKinds.NONCE_ISSUED,
    HostKinds.NONCE_CONSUMED,
  )

/** Every kind the host folds: its substrate-only kinds, plus approvals (authored by the
 * authorization layer), cognition turns (authored by cognition), and the shared journal's gate
 * releases, which the host's release fold reads. A workflow's kinds must be disjoint from these
 * ([requireKindPartition]). */
internal val HOST_KINDS: Set<String> =
  HOST_SUBSTRATE_KINDS + setOf(HostKinds.APPROVAL_RECORDED, HostKinds.COGNITION_PROPOSED, KIND_GATE_RELEASED)

/**
 * Folds a lead's journal: each entry through the host's step ([hostStep]) and then the workflow's
 * ([workflowStep]), which sees what the host step did with the entry, and the two results assembled
 * into the lead's state ([assemble]). A failure is classified by the entry it failed on
 * ([LeadFoldException]).
 *
 * The loop, the order of the two steps and the failure's classification are the host's; the
 * workflow supplies its own state's start, step and assembly, and what [hostStep] asks of it.
 */
internal fun <W, S> foldLeadJournal(
  entries: List<JournalEntry>,
  auth: LeadAuth,
  workflowKinds: Set<String>,
  isScopeEnd: (JournalEntry) -> Boolean,
  workflowStart: W,
  expectedTaskRefs: (W) -> Set<String>,
  workflowStep: (W, JournalEntry, HostOutcome) -> W,
  assemble: (HostState, W) -> S,
): S {
  var host = HostState()
  var workflow = workflowStart
  for (e in entries) {
    try {
      val step =
        hostStep(
          host,
          e,
          auth,
          workflowKinds = workflowKinds,
          isScopeEnd = isScopeEnd(e),
          expectedTaskRefs = expectedTaskRefs(workflow),
        )
      workflow = workflowStep(workflow, e, step.outcome)
      host = step.state
    } catch (x: LeadFoldException) {
      throw x
    } catch (x: Exception) {
      throw LeadFoldException(e.seq, e.kind, x)
    }
  }
  return assemble(host, workflow)
}

/**
 * Folds one entry into the host's records.
 *
 * The workflow supplies what the host must not know about it: [workflowKinds], its substrate-only
 * kinds, which the provenance gate polices alongside [HOST_SUBSTRATE_KINDS]; [isScopeEnd], whether
 * this entry ends the workflow's scope, which clears the host's scoped records; and
 * [expectedTaskRefs], the pod task refs the workflow intends as of the entry before this one, which
 * decides how an orphaned spawn intent's task ref is described.
 */
internal fun hostStep(
  s: HostState,
  e: JournalEntry,
  auth: LeadAuth,
  workflowKinds: Set<String>,
  isScopeEnd: Boolean,
  expectedTaskRefs: Set<String>,
): HostStep {
  // Provenance teeth, symmetric with the release check: the substrate
  // is the sole author of these state-carrying kinds. An entry of such a kind bearing any
  // other origin is a confused deputy or a corrupt/imported entry — it NEVER advances state
  // and lands VISIBLY in misOriginedEntries. (GATE_RELEASED carries auth origin and is
  // handled by foldRelease; COGNITION_PROPOSED is legitimately cognition-origin.) Checked
  // before the payload parse, so a forged entry with a garbage payload is recorded, not thrown.
  if ((e.kind in HOST_SUBSTRATE_KINDS || e.kind in workflowKinds) && e.origin != ORIGIN_SUBSTRATE) {
    return rejected(s, e)
  }
  // Same teeth, different sole author: an approval accumulates toward quorum, so its one
  // legitimate origin is the authorization layer — approval-shaped entries from anywhere
  // else (cognition, a pod, an import) are quorum-stuffing and land visibly, never counted.
  if (e.kind == HostKinds.APPROVAL_RECORDED && e.origin != ORIGIN_AUTH_LAYER) {
    return rejected(s, e)
  }
  val p = payloadObject(e.payloadJson)
  if (isScopeEnd) {
    // Clear ALL scope-held records: the workflow starts a new scope only once the last one ended,
    // so every open/released/stale gate and every pod belonged to the scope just finished.
    // Retaining them grows fold state without bound across scopes AND leaves cross-scope residue
    // a first-by-kind lookup like gate(gateKind) could later mis-honor. The capped tails
    // (statusTail, escalations, misOriginedEntries, malformedCognition) persist as the running
    // record — a model's degradation rate is a property of the model, not of the scope it
    // happened to be working, so it must not reset at a scope boundary. declinedEffects persists
    // too (see [HostState.declinedEffects]).
    return HostStep(
      s.copy(
        openGates = emptyMap(),
        releasedGates = emptySet(),
        releasedDigests = emptyMap(),
        nonceLessReleases = emptyMap(),
        staleReleases = emptyList(),
        issuedNonces = emptyMap(),
        consumedNonces = emptySet(),
        notifiedNonces = emptySet(),
        failedAnnounces = emptyMap(),
        notReadAnnounces = emptyMap(),
        escalatedStalls = emptyMap(),
        verifiedApprovals = emptyMap(),
        unverifiedApprovals = emptyList(),
        pods = emptyMap(),
        pendingSpawnIntents = emptyMap(),
      ),
      HostOutcome.Folded,
    )
  }
  return when (e.kind) {
    HostKinds.RUN_STARTED -> folded(s.copy(runsStarted = s.runsStarted + 1))
    HostKinds.STATUS_WRITTEN -> folded(s.copy(statusTail = (s.statusTail + p.str("status")).takeLast(20)))
    HostKinds.ESCALATED -> {
      val escalated = s.copy(escalations = (s.escalations + p.str("reason")).takeLast(ANOMALY_TAIL))
      // An escalation of a gate that holds up its stage names the gate and its digest beside the
      // reason ([HostState.escalatedStalls]). Only two JSON strings are recorded: a row with any
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
      folded(if (declined == null) stalled else stalled.copy(declinedEffects = stalled.declinedEffects + declined))
    }
    HostKinds.GATE_OPENED -> {
      val gate = OpenGate(p.str("gateId"), p.str("gateKind"), p.str("payloadDigest"), e.seq)
      HostStep(s.copy(openGates = s.openGates + (gate.gateId to gate)), HostOutcome.GateOpened(gate))
    }
    KIND_GATE_RELEASED -> foldRelease(s, e, p, auth)
    HostKinds.POD_SPAWNED -> {
      val pod =
        PodRecord(
          podId = p.str("podId"),
          sessionId = p.str("sessionId"),
          taskRef = p.str("taskRef"),
          artifactPath = p.str("artifactPath"),
          spawnedSeq = e.seq,
        )
      HostStep(
        s.copy(
          pods = s.pods + (pod.podId to pod),
          pendingSpawnIntents = s.pendingSpawnIntents - pod.taskRef, // intent fulfilled
        ),
        HostOutcome.PodSpawned(pod),
      )
    }
    // Unknown-pod results/abandons are DROPPED (a result cannot attach to a pod with no
    // spawn record — result-before-spawn ordering is a contract violation, see
    // PodRunner.spawn) but dropped VISIBLY, consistent with the other anomaly views
    // (AGENCY-021): this fold path is the backstop for the
    // accept-exemption on pod completions, and a backstop that fires silently would be
    // exactly the no-trace loss that fix exists to end. The lead's own code never writes
    // such an entry, so nothing vouches for its fields: the anomaly names the entry by its
    // seq and the refused pod id by its length, as the nonce re-issue below does its gate id.
    HostKinds.POD_RESULT_RECORDED -> {
      val podId = p.str("podId")
      val pod = s.pods[podId]
      if (pod == null)
        folded(
          s.copy(
            escalations =
              (s.escalations +
                  ("pod-result at seq=${e.seq} for an unknown pod id of ${podId.length} chars — dropped " +
                    "(a result must follow its pod's spawn record)"))
                .takeLast(ANOMALY_TAIL)
          )
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
        HostStep(s.copy(pods = s.pods + (podId to updated)), HostOutcome.PodResultRecorded(updated))
      }
    }
    HostKinds.POD_ABANDONED -> {
      val podId = p.str("podId")
      val pod = s.pods[podId]
      if (pod == null)
        folded(
          s.copy(
            escalations =
              (s.escalations +
                  ("pod-abandoned at seq=${e.seq} for an unknown pod id of ${podId.length} chars — dropped " +
                    "(no spawn record)"))
                .takeLast(ANOMALY_TAIL)
          )
        )
      else folded(s.copy(pods = s.pods + (podId to pod.copy(abandonedReason = p.str("reason")))))
    }
    // A pod launch's intent, journaled before the side-effect. Tracked by taskRef;
    // POD_SPAWNED clears it (fulfilled), POD_SPAWN_ABANDONED clears it (orphaned on adopt).
    HostKinds.POD_SPAWN_INTENDED ->
      folded(s.copy(pendingSpawnIntents = s.pendingSpawnIntents + (p.str("taskRef") to e.seq)))
    HostKinds.POD_SPAWN_ABANDONED -> {
      val taskRef = p.str("taskRef")
      val reason = p.str("reason")
      // The lead writes this only for a pending intent, with its one fixed reason; a field
      // the lead did not write is described by its length. Pending is not enough for the
      // ref: the fold holds any intent's ref, and the lead intends only the task refs the
      // workflow expects now.
      val ref =
        if (taskRef in s.pendingSpawnIntents && taskRef in expectedTaskRefs) taskRef
        else "an unknown task ref of ${taskRef.length} chars"
      val why = if (reason == ORPHANED_SPAWN_REASON) reason else "a reason of ${reason.length} chars"
      folded(
        s.copy(
          pendingSpawnIntents = s.pendingSpawnIntents - taskRef,
          escalations =
            (s.escalations + "spawn-intent orphaned at seq=${e.seq} for $ref: $why")
              .takeLast(ANOMALY_TAIL),
        )
      )
    }
    HostKinds.NONCE_ISSUED -> {
      val issued = IssuedNonce(p.str("nonce"), p.str("gateId"), p.str("payloadDigest"), e.seq)
      when {
        // A re-issue of an existing value would REBIND it (or resurrect a spent one) —
        // the first binding stands and the attempt is retained visibly.
        issued.nonce in s.issuedNonces ->
          folded(
            s.copy(
              escalations =
                (s.escalations +
                    ("nonce re-issued at seq=${e.seq} for a gate id of ${issued.gateId.length} chars — " +
                      "the binding at seq=${s.issuedNonces.getValue(issued.nonce).issuedSeq} kept"))
                  .takeLast(ANOMALY_TAIL)
            )
          )
        else -> {
          // Recorded even when the gate is unknown (the substrate's assertion stands in
          // the record; a release still needs an open gate whose digest agrees), but an
          // issue-before-open is contract drift worth seeing. The lead mints only for an open
          // gate, so the unknown id is the entry's own: it is described by its length.
          val flagged =
            if (issued.gateId !in s.openGates)
              s.copy(
                escalations =
                  (s.escalations +
                      "nonce issued at seq=${e.seq} for an unknown gate id of ${issued.gateId.length} chars")
                    .takeLast(ANOMALY_TAIL)
              )
            else s
          folded(flagged.copy(issuedNonces = flagged.issuedNonces + (issued.nonce to issued)))
        }
      }
    }
    HostKinds.NONCE_CONSUMED -> {
      val nonce = p.str("nonce")
      when {
        nonce !in s.issuedNonces ->
          folded(
            s.copy(
              escalations =
                (s.escalations + "consume of unknown nonce at seq=${e.seq} — dropped")
                  .takeLast(ANOMALY_TAIL)
            )
          )
        // Already spent: bookkeeping after a release the fold consumed itself — no-op.
        nonce in s.consumedNonces -> folded(s)
        else -> folded(s.copy(consumedNonces = s.consumedNonces + nonce))
      }
    }
    HostKinds.GATE_OPEN_NOTIFIED -> {
      // One attempt to announce this nonce's gate-open (the outcome rides in the payload for the
      // record). A marker that says the announce will be sent again counts one more failed
      // attempt; any other is final. A marker without the field is final, which is also how a
      // binary that does not retry reads one that has it. The substrate is the sole writer and
      // announces only a nonce it just resolved open, so no gate/issue cross-check is warranted.
      // A retry marker that also says the copy was not read counts in [notReadAnnounces] too.
      val nonce = p.str("nonce")
      if (p.marksRetry())
        folded(
          s.copy(
            failedAnnounces = s.failedAnnounces + (nonce to (s.failedAnnounces[nonce] ?: 0) + 1),
            notReadAnnounces =
              if (p.marksTrue("notRead"))
                s.notReadAnnounces + (nonce to (s.notReadAnnounces[nonce] ?: 0) + 1)
              else s.notReadAnnounces,
          )
        )
      else folded(s.copy(notifiedNonces = s.notifiedNonces + nonce))
    }
    HostKinds.APPROVAL_RECORDED -> folded(foldApproval(s, e, p, auth))
    HostKinds.COGNITION_PROPOSED -> folded(s.copy(cognitionSpendUsd = s.cognitionSpendUsd + accruedCost(p)))
    // A turn that produced garbage was billed exactly like one that produced a decision, so
    // its cost accrues on the same terms: a model that ONLY emits near-misses would
    // otherwise spend against a cap that never moves.
    // The reason is held only when it is one the lead writes; any other is described by its length.
    HostKinds.COGNITION_MALFORMED -> {
      val reason = p.str("reason")
      val held = if (MalformedReasons.isLeads(reason)) reason else "a reason of ${reason.length} chars"
      folded(
        s.copy(
          cognitionSpendUsd = s.cognitionSpendUsd + accruedCost(p),
          malformedCognition = (s.malformedCognition + (e.seq to held)).takeLast(ANOMALY_TAIL),
        )
      )
    }
    // Workflow, shared and unknown kinds: not the host's business. Also the state-inert lead kinds
    // (POD_EVENT): journaled audit rows the fold deliberately never consumes — their origin was
    // already policed by the gate above.
    else -> folded(s)
  }
}

private fun rejected(s: HostState, e: JournalEntry): HostStep =
  HostStep(
    s.copy(misOriginedEntries = (s.misOriginedEntries + (e.seq to e.kind)).takeLast(ANOMALY_TAIL)),
    HostOutcome.Rejected,
  )

private fun folded(s: HostState): HostStep = HostStep(s, HostOutcome.Folded)

/**
 * The spend a journaled cognition turn contributes. costUsd is a model-supplied, UNTRUSTED
 * number: a non-finite (NaN/±Infinity) or negative
 * value must never enter the total the budget cap reads — NaN makes every `spend >= cap`
 * comparison false, so the cap would never trip and wake-driven spend would be unbounded,
 * and a negative value would understate spend. Only a finite, non-negative cost accrues, so
 * [HostState.cognitionSpendUsd] stays finite and monotonic non-decreasing.
 */
private fun accruedCost(p: JsonObject): Double =
  p.strOrNull("costUsd")?.toDoubleOrNull()?.takeIf { it.isFinite() && it >= 0.0 } ?: 0.0

/**
 * Release handling — the lead-level teeth. Honored iff origin == auth layer AND the
 * released digest matches the gate as opened AND the nonce discipline holds AND — on the
 * nonce (ceremony) path — a quorum of VERIFIED approvers is satisfied. Wrong origin is the
 * shared fold's visible rejection (re-asserted here by simply not honoring); everything else
 * auth-origin-but-unfaithful (or quorum-unmet) is retained visibly as
 * [HostState.staleReleases]. An honored release is reported as [HostOutcome.GateReleased], which
 * is what lets the workflow advance on it.
 *
 * QUORUM (2b): once a release names a faithful nonce, the gate clears only if
 * [quorumSatisfied] holds over [boundApprovers] — the preimage-derived principals
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
 * Nonce-less honors (reachable on a DENY_ALL fold only) are marked in [HostState.nonceLessReleases], keyed by gate to
 * the FIRST honoring release's seq, so the disposition stays legible after the fact — the
 * honor is itself single-use per gate, mirroring the consumed-nonce rule: a second
 * nonce-less release of a marked gate folds stale rather than silently re-honoring and
 * retargeting the mark. That also means a re-opened gate cannot be honored nonce-less a
 * second time within a scope (the guard reads the mark, which the scope end clears with the
 * rest of the scoped records) — deliberate conservatism on a stub
 * path, and visible in [HostState.staleReleases] rather than silent. A later ceremony
 * release of a re-opened gate stays distinguishable from the mark.
 *
 * On the re-open shapes several cells exercise: the daemon opens each gateId at most once
 * per ticket (the host's seen-gate guard), so a re-opened gate is a journal-level fold
 * surface, not a transition the daemon currently produces. On a real payload change today
 * the gate stays open on the old digest and the voiding path that fires is an explicit
 * [HostKinds.NONCE_CONSUMED] — which the step-2 ceremony must remember to journal.
 */
private fun foldRelease(s: HostState, e: JournalEntry, p: JsonObject, auth: LeadAuth): HostStep {
  if (e.origin != ORIGIN_AUTH_LAYER) return folded(s) // forged provenance: never honored here; shared fold records the rejection
  val gateId = p.str("gateId")
  val digest = p.strOrNull("payloadDigest")
  val nonce = p.strOrNull("nonce")
  val gate = s.openGates[gateId]
  // An open gate's id is one the lead opened; a release naming no open gate carries an id the
  // fold has checked nothing about, so it is recorded by its length.
  val recordedId = if (gate == null) "an unknown gate id of ${gateId.length} chars" else gateId
  fun stale(): HostStep =
    folded(s.copy(staleReleases = (s.staleReleases + (e.seq to recordedId)).takeLast(ANOMALY_TAIL)))
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
    if (!quorumSatisfied(auth.quorum, boundApprovers(s.verifiedApprovals, gate, nonce))) return stale()
    consumed = s.consumedNonces + nonce
    nonceLess = s.nonceLessReleases
  }
  return HostStep(
    s.copy(
      releasedGates = s.releasedGates + gateId,
      releasedDigests =
        s.releasedDigests + (gateId to (s.releasedDigests[gateId].orEmpty() + gate.payloadDigest)),
      nonceLessReleases = nonceLess,
      consumedNonces = consumed,
    ),
    HostOutcome.GateReleased(gate),
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
 * A verified approval lands in [HostState.verifiedApprovals] under its COMMITTED gate, keyed
 * by the preimage-derived principal, deduped on (principal, nonce, digest). Anything that
 * fails a step lands in [HostState.unverifiedApprovals] with a reason and contributes
 * nothing — a null/absent preimage included (fail-closed: unverifiable, never a pass). The
 * refusal names WHICH layer disagreed, so a split-source attempt is legible after the fact.
 *
 * The top-level payload framing (gateId/principalId/nonce/payloadDigest) is the auth layer's
 * own contract, read strictly ([str] throws classified on a malformed required field); the
 * evidence sub-object is carrier-provided PROOF, so a malformed or absent one is "unverified",
 * never a fold crash — an approval that cannot be verified must not be able to brick recovery.
 */
private fun foldApproval(s: HostState, e: JournalEntry, p: JsonObject, auth: LeadAuth): HostState {
  val claimedGate = p.str("gateId")
  val claimedPrincipal = p.str("principalId")
  val claimedNonce = p.str("nonce")
  val claimedDigest = p.str("payloadDigest")

  fun unverified(reason: String): HostState =
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

/** Preimage-derived principals whose VERIFIED approval binds [gate] AS IT STANDS — same digest the
 * gate is open on, same [nonce]. See [foldRelease], which reads it. */
internal fun boundApprovers(
  verifiedApprovals: Map<String, List<VerifiedApproval>>,
  gate: OpenGate,
  nonce: String,
): Set<String> =
  verifiedApprovals[gate.gateId]
    .orEmpty()
    .filter { it.nonce == nonce && it.payloadDigest == gate.payloadDigest }
    .map { it.principalId }
    .toSet()
