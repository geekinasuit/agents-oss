package com.geekinasuit.agency.pod

/**
 * Supervisory events the engine reports upward. Same discipline as
 * [PodEngine.spawn]'s onComplete: the consumer callback must only ENQUEUE — the lead's
 * loop journals these as substrate facts (ask/decision durability, refusal
 * visibility, restart/deadline visibility) on its own thread. Everything in
 * here is lead-owned data: engine-observed facts about an UNTRUSTED pod, never anything
 * the pod authored (pod-authored evidence stays in [TurnResult.updates] and is validated
 * separately).
 */
sealed interface PodEvent {
  val podId: String

  /** A session was established on [attempt]. [PodSpawned.sessionId] carries only the
   * FIRST one; every restart mints a new session, and re-attach needs the LATEST — so the
   * spawn-time value alone was never sufficient and the record now carries each. Also the
   * only place a session id appears when the first launch failed and a later attempt
   * succeeded (spawn returns "unestablished" in that case, deliberately: see
   * [AcpPodEngine]'s note on why retries do not run on the caller's thread). */
  data class SessionEstablished(
    override val podId: String,
    val sessionId: String,
    val attempt: Int,
  ) : PodEvent

  /** The agent routed a permission ask: recorded BEFORE the decider is consulted,
   * so an ask that dies with the process is still on the record. */
  data class PermissionAsked(
    override val podId: String,
    val sessionId: String,
    val toolCallId: String,
    val title: String,
    val toolKind: String,
  ) : PodEvent

  /** The bridge's decider answered (or the answer is known discarded). [lateAfterDeadline]
   * — the answer arrived after the client's fail-closed deadline already rejected on the
   * wire; it authorized NOTHING (the deadline is ours, the late answer is
   * discarded, and the record says so). */
  data class PermissionDecided(
    override val podId: String,
    val sessionId: String,
    val toolCallId: String,
    val decision: String,
    val elapsedMs: Long,
    val lateAfterDeadline: Boolean,
  ) : PodEvent

  /** rp-liveness preflight refused the agent: the sentinel turn produced no
   * permission ask — the statically non-asking (copilot-cli#845 class) profile. Terminal
   * for the pod; the lead abandons it visibly. */
  data class PreflightRefused(override val podId: String, val sessionId: String, val reason: String) :
    PodEvent

  /** The disciplined artifact read refused the object at the lead-assigned path:
   * symlink, non-regular file (FIFO/dir/device), resolved path outside the workspace,
   * over the size cap, or missing. Terminal; no completion is reported. */
  data class ArtifactRefused(
    override val podId: String,
    val artifactPath: String,
    val reason: String,
  ) : PodEvent

  /** One crash-restart attempt: the previous process/session died or failed its
   * handshake; the engine backs off and tries again with a FRESH session (asks are
   * re-asked — a decision against the dead session authorizes nothing). */
  data class RestartAttempted(
    override val podId: String,
    val attempt: Int,
    val backoffMs: Long,
    val cause: String,
  ) : PodEvent

  /** The restart cap is exhausted: visible escalation, never a silent loop. The
   * lead abandons the pod. */
  data class RestartsExhausted(override val podId: String, val attempts: Int, val cause: String) :
    PodEvent

  /** The pod's WALL-CLOCK deadline fired: the engine group-killed the process tree
   * on a clock it owns. Terminal; the lead abandons the pod. */
  data class DeadlineKilled(override val podId: String, val afterMs: Long) : PodEvent

  /** A would-be completion lost the single-owner race: a terminal disposition
   * (deadline kill, abandonment, refusal) already owns this pod, so the completion is
   * DISCARDED at the engine — recorded, never delivered as a second advance. */
  data class CompletionDiscarded(override val podId: String, val reason: String) : PodEvent

  /**
   * The engine could not kill the pod's PROCESS GROUP and fell back to killing the direct
   * child tree only. The exact hazard the group contract exists to prevent — a
   * backgrounded grandchild that outlives the kill — so it is REPORTED rather than
   * swallowed: silent degradation is indistinguishable in the log from a clean kill.
   * [reason] is `no-pgid` (the wrapper never reported a group, e.g. crash-on-start) or
   * `kill-uninvokable` (`/bin/kill` could not be run on this host).
   *
   * NOT emitted when the group merely no longer exists — killing an already-exited group
   * is an ordinary race, not a degradation.
   */
  data class GroupKillDegraded(
    override val podId: String,
    val reason: String,
    val detail: String,
  ) : PodEvent
}
