package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

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
   * A signature-verified approval the authorization layer accepted and journaled (payload:
   * gateId, principalId, nonce, payloadDigest, evidence{schemeId, publicKey, signature,
   * carrierArtifactId}). AUTH-LAYER-authored — the one lead kind besides the release itself that is:
   * approvals accumulate toward a quorum, so an approval-shaped entry from cognition or a
   * pod stuffing the count is the same threat as a forged release, and gets the same
   * treatment (never honored, retained visibly in [LeadState.misOriginedEntries]).
   * Accumulation is durable so a k-of-n quorum can fill across restarts; the fold retains
   * each approval's binding (nonce + digest) so an approval bound to a superseded digest
   * can never satisfy the re-opened gate. The evidence sub-object is journal-resident
   * audit — the fold does not consume it.
   */
  const val APPROVAL_RECORDED = "approval-recorded"
}

/** Gate kinds the ticket pipeline opens. */
object GateKinds {
  const val PLAN_APPROVAL = "plan-approval"
  const val COMMIT_APPROVAL = "commit-approval"
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
)

/** One accepted approval as journaled, with the binding it committed to retained —
 * consumers filter on (nonce, payloadDigest) against the gate's CURRENT state, so a
 * stale-bound approval is inert rather than silently counted. */
data class RecordedApproval(
  val principalId: String,
  val nonce: String,
  val payloadDigest: String,
  val seq: Long,
)

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
  /** Gates released by the nonce-less pre-ceremony path — the disposition marker that
   * keeps "was this release under the ceremony?" answerable from derived state, matching
   * how every other classification this fold makes stays legible after the fact. */
  val nonceLessReleases: Set<String> = emptySet(),
  val staleReleases: List<Pair<Long, String>> = emptyList(), // (seq, gateId) — auth origin, but digest mismatch, unknown gate, or nonce indiscipline (consumed/unknown/misbound/absent-where-required)
  /** Every nonce issued this ticket, by value — consumed ones stay listed ([consumedNonces]
   * marks them) so a re-issue of a spent value is detectable as the anomaly it is. */
  val issuedNonces: Map<String, IssuedNonce> = emptyMap(),
  val consumedNonces: Set<String> = emptySet(),
  /** gateId → accepted approvals with their bindings. Auth-layer-authored entries only;
   * dedup at fold is by (principal, nonce, digest), so re-delivery of the same approval is
   * idempotent while a re-approval under a fresh nonce accumulates. */
  val approvals: Map<String, List<RecordedApproval>> = emptyMap(),
  val pods: Map<String, PodRecord> = emptyMap(),
  val pendingSpawnIntents: Map<String, Long> = emptyMap(), // taskRef → intent seq: spawn journaled, POD_SPAWNED not yet
  val misOriginedEntries: List<Pair<Long, String>> = emptyList(), // (seq, kind): substrate-authored kind with a non-substrate origin — never honored
  val statusTail: List<String> = emptyList(),
  val escalations: List<String> = emptyList(),
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

  /** Principals whose recorded approval binds the gate AS IT STANDS — same digest the gate
   * is open on, same [nonce] — the set a quorum predicate is evaluated over. Approvals
   * bound to a superseded digest or a different nonce are present in [approvals] but
   * excluded here. */
  fun boundApprovers(gate: OpenGate, nonce: String): Set<String> =
    approvals[gate.gateId]
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
 * [LeadState.approvals], [LeadState.nonceLessReleases]) sit DELIBERATELY outside this
 * cap: they are correctness-bearing records, not views. Evicting a consumed nonce
 * re-enables the replay it exists to reject; evicting an issued nonce or a recorded
 * approval silently voids a live authorization. Their bound is the ticket, not a tail —
 * TICKET_DONE clears them — and their kinds are origin-gated, so only the substrate and
 * the authorization layer can grow them: a party positioned to flood them could already
 * write worse. */
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

/** A fold failure with its position identified — a malformed payload on a known kind
 * (field missing, wrong type) is chain corruption or payload-contract drift, and it must
 * fail CLASSIFIED (seq + kind named) rather than as an anonymous NPE boot-loop. */
class LeadFoldException(seq: Long, kind: String, cause: Throwable) :
  RuntimeException("lead fold failed at seq=$seq kind='$kind': ${cause.message}", cause)

/** The lead state machine: `leadState = leadFold(entries)`. Folds the SAME entry
 * list the shared fold consumes — two folds, one list; composition, not extension. */
fun leadFold(entries: List<JournalEntry>): LeadState {
  var s = LeadState()
  for (e in entries) {
    s =
      try {
        foldOne(s, e)
      } catch (x: LeadFoldException) {
        throw x
      } catch (x: Exception) {
        throw LeadFoldException(e.seq, e.kind, x)
      }
  }
  return s
}

private fun foldOne(s0: LeadState, e: JournalEntry): LeadState {
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
  val p = Json.parseToJsonElement(e.payloadJson).jsonObject
  return when (e.kind) {
      LeadKinds.RUN_STARTED -> s.copy(runsStarted = s.runsStarted + 1)
      LeadKinds.TICKET_CLAIMED ->
        s.copy(currentTicket = p.str("ticketRef"), phase = TicketPhase.CLAIMED)
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
          nonceLessReleases = emptySet(),
          staleReleases = emptyList(),
          issuedNonces = emptyMap(),
          consumedNonces = emptySet(),
          approvals = emptyMap(),
          pods = emptyMap(),
          pendingSpawnIntents = emptyMap(),
        )
      LeadKinds.ESCALATED ->
        s.copy(escalations = (s.escalations + p.str("reason")).takeLast(ANOMALY_TAIL))
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
      KIND_GATE_RELEASED -> foldRelease(s, e, p)
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
          // entry and fails CLASSIFIED: non-numeric via toDouble throwing, and NaN /
          // Infinity / negatives (which toDouble would accept silently) via the explicit
          // check.
          val updated =
            pod.copy(
              resultDigest = p.str("resultDigest"),
              boundPath = p.strOrNull("boundPath"),
              costUsd =
                p.strOrNull("costUsd")?.toDouble()?.also {
                  require(it.isFinite() && it >= 0.0) { "costUsd '$it' is non-finite or negative" }
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
      LeadKinds.APPROVAL_RECORDED -> {
        val gateId = p.str("gateId")
        val approval = RecordedApproval(p.str("principalId"), p.str("nonce"), p.str("payloadDigest"), e.seq)
        val current = s.approvals[gateId].orEmpty()
        val duplicate =
          current.any {
            it.principalId == approval.principalId &&
              it.nonce == approval.nonce &&
              it.payloadDigest == approval.payloadDigest
          }
        if (duplicate) s
        else s.copy(approvals = s.approvals + (gateId to (current + approval)))
      }
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
 * released digest matches the gate as opened AND the nonce discipline holds. Wrong origin
 * is the shared fold's visible rejection (re-asserted here by simply not honoring);
 * everything else auth-origin-but-unfaithful is retained visibly as
 * [LeadState.staleReleases].
 *
 * NONCE DISCIPLINE (single-use, journal-derived): a release naming a nonce is honored
 * only if that nonce was issued FOR THIS GATE, bound at issue to THIS digest, and never
 * consumed — and honoring it consumes it in the derived state, so a second release naming
 * the same nonce folds stale. Replay rejection therefore survives restart by
 * construction: it is a property of re-folding the journal, not of any in-memory table.
 * A release naming NO nonce is honored only while its gate has never had one issued — the
 * pre-ceremony stub path, kept so journals written before nonces existed keep their
 * meaning — and once a nonce exists for a gate, omitting the field is indiscipline, not
 * an exemption. That condition is per-gate LIVE STATE, not a journal epoch: a gate whose
 * mint step fails or is skipped stays on the pre-ceremony rule until a nonce exists for
 * it, and refusing nonce-less releases outright once the ceremony is wired is step 2's
 * call. Nonce-less honors are marked in [LeadState.nonceLessReleases] so the disposition
 * stays legible after the fact.
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
): LeadState {
  if (e.origin != ORIGIN_AUTH_LAYER) return s // forged provenance: never honored here; shared fold records the rejection
  val gateId = p.str("gateId")
  val digest = p.strOrNull("payloadDigest")
  val nonce = p.strOrNull("nonce")
  val gate = s.openGates[gateId]
  fun stale(): LeadState =
    s.copy(staleReleases = (s.staleReleases + (e.seq to gateId)).takeLast(ANOMALY_TAIL))
  if (gate == null || digest != gate.payloadDigest) return stale()
  val consumed: Set<String>
  val nonceLess: Set<String>
  if (nonce == null) {
    if (s.issuedNonces.values.any { it.gateId == gateId }) return stale()
    consumed = s.consumedNonces
    nonceLess = s.nonceLessReleases + gateId
  } else {
    val issued = s.issuedNonces[nonce]
    val faithful =
      issued != null &&
        issued.gateId == gateId &&
        issued.payloadDigest == digest &&
        nonce !in s.consumedNonces
    if (!faithful) return stale()
    consumed = s.consumedNonces + nonce
    nonceLess = s.nonceLessReleases
  }
  return s.copy(
    releasedGates = s.releasedGates + gateId,
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

private fun kotlinx.serialization.json.JsonObject.str(k: String): String =
  this[k]!!.jsonPrimitive.content

private fun kotlinx.serialization.json.JsonObject.strOrNull(k: String): String? =
  this[k]?.jsonPrimitive?.content
