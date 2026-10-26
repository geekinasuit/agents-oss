package com.geekinasuit.agency.lead

/**
 * The lead-chain entry kinds the host writes and folds. A workflow declares its own kinds, which
 * must be disjoint from these ([requireKindPartition]).
 */
object HostKinds {
  const val RUN_STARTED = "run-started"
  const val STATUS_WRITTEN = "status-written"
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
