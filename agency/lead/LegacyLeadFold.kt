package com.geekinasuit.agency.lead

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
import kotlinx.serialization.json.JsonPrimitive

// TEST ORACLE: the lead fold as it stood before the host/workflow split, frozen verbatim from
// LeadState.kt so FoldSplitDifferentialTest can check that the split fold reaches the same state,
// or the same failure, on every journal. Only the entry point is renamed (leadFold →
// legacyLeadFold). What the oracle still shares with production is code this PR does not change:
// the state and record types (LeadState and its field types, LeadKinds, LeadAuth),
// MalformedReasons, ORPHANED_SPAWN_REASON and LeadFoldException. Two pieces of logic are private
// copies, not shared: the internal isClaimableTicketRef, invisible from this test target, kept
// without its KDoc; and LeadState.boundApprovers, whose body moved into HostFold.kt, called as
// legacyBoundApprovers. Everything else is byte-for-byte the pre-split text. Delete this file
// once the split has shipped and the differential test has no further use.

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

private fun isClaimableTicketRef(ref: String): Boolean =
  TICKET_REF_RE.matches(ref) && ref.length <= MAX_TICKET_REF_LEN

/** The form the substrate records an evidence digest in: [sha256HexBytes]'s lowercase hex. */
private val SHA256_HEX_RE = Regex("[0-9a-f]{64}")

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
fun legacyLeadFold(entries: List<JournalEntry>, auth: LeadAuth): LeadState {
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
          notReadAnnounces = emptyMap(),
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
      // exactly the no-trace loss that fix exists to end. The lead's own code never writes
      // such an entry, so nothing vouches for its fields: the anomaly names the entry by its
      // seq and the refused pod id by its length, as the nonce re-issue below does its gate id.
      LeadKinds.POD_RESULT_RECORDED -> {
        val podId = p.str("podId")
        val pod = s.pods[podId]
        if (pod == null)
          s.copy(
            escalations =
              (s.escalations +
                  ("pod-result at seq=${e.seq} for an unknown pod id of ${podId.length} chars — dropped " +
                    "(a result must follow its pod's spawn record)"))
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
                  ("pod-abandoned at seq=${e.seq} for an unknown pod id of ${podId.length} chars — dropped " +
                    "(no spawn record)"))
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
        val reason = p.str("reason")
        // The lead writes this only for a pending intent, with its one fixed reason; a field
        // the lead did not write is described by its length. Pending is not enough for the
        // ref: the fold holds any intent's ref, and the lead intends only this ticket's
        // plan or execute pod.
        val cur = s.currentTicket
        val ref =
          if (taskRef in s.pendingSpawnIntents && cur != null && taskRef in setOf("plan:$cur", "execute:$cur"))
            taskRef
          else "an unknown task ref of ${taskRef.length} chars"
        val why = if (reason == ORPHANED_SPAWN_REASON) reason else "a reason of ${reason.length} chars"
        s.copy(
          pendingSpawnIntents = s.pendingSpawnIntents - taskRef,
          escalations =
            (s.escalations + "spawn-intent orphaned at seq=${e.seq} for $ref: $why")
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
                    ("nonce re-issued at seq=${e.seq} for a gate id of ${issued.gateId.length} chars — " +
                      "the binding at seq=${s.issuedNonces.getValue(issued.nonce).issuedSeq} kept"))
                  .takeLast(ANOMALY_TAIL)
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
        // A retry marker that also says the copy was not read counts in [notReadAnnounces] too.
        val nonce = p.str("nonce")
        if (p.marksRetry())
          s.copy(
            failedAnnounces = s.failedAnnounces + (nonce to (s.failedAnnounces[nonce] ?: 0) + 1),
            notReadAnnounces =
              if (p.marksTrue("notRead"))
                s.notReadAnnounces + (nonce to (s.notReadAnnounces[nonce] ?: 0) + 1)
              else s.notReadAnnounces,
          )
        else s.copy(notifiedNonces = s.notifiedNonces + nonce)
      }
      LeadKinds.APPROVAL_RECORDED -> foldApproval(s, e, p, auth)
      LeadKinds.COGNITION_PROPOSED ->
        s.copy(cognitionSpendUsd = s.cognitionSpendUsd + accruedCost(p))
      // A turn that produced garbage was billed exactly like one that produced a decision, so
      // its cost accrues on the same terms: a model that ONLY emits near-misses would
      // otherwise spend against a cap that never moves.
      // The reason is held only when it is one the lead writes; any other is described by its length.
      LeadKinds.COGNITION_MALFORMED -> {
        val reason = p.str("reason")
        val held = if (MalformedReasons.isLeads(reason)) reason else "a reason of ${reason.length} chars"
        s.copy(
          cognitionSpendUsd = s.cognitionSpendUsd + accruedCost(p),
          malformedCognition = (s.malformedCognition + (e.seq to held)).takeLast(ANOMALY_TAIL),
        )
      }
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
  // An open gate's id is one the lead opened; a release naming no open gate carries an id the
  // fold has checked nothing about, so it is recorded by its length.
  val recordedId = if (gate == null) "an unknown gate id of ${gateId.length} chars" else gateId
  fun stale(): LeadState =
    s.copy(staleReleases = (s.staleReleases + (e.seq to recordedId)).takeLast(ANOMALY_TAIL))
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
    if (!quorumSatisfied(auth.quorum, legacyBoundApprovers(s, gate, nonce))) return stale()
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
private fun kotlinx.serialization.json.JsonObject.marksRetry(): Boolean = marksTrue("retry")

/** Whether the field [k] holds a JSON `true`; any other value, or none, reads as false. */
private fun kotlinx.serialization.json.JsonObject.marksTrue(k: String): Boolean {
  val el = this[k] as? kotlinx.serialization.json.JsonPrimitive ?: return false
  return !el.isString && el.content == "true"
}

/** Pre-split body of [LeadState.boundApprovers], copied so the oracle does not share the
 * filter with the fold under test. */
private fun legacyBoundApprovers(s: LeadState, gate: OpenGate, nonce: String): Set<String> =
  s.verifiedApprovals[gate.gateId]
    .orEmpty()
    .filter { it.nonce == nonce && it.payloadDigest == gate.payloadDigest }
    .map { it.principalId }
    .toSet()
