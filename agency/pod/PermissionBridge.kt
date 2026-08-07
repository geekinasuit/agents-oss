package com.geekinasuit.agency.pod

/**
 * rp → gate bridge: wraps the permission decider with the
 * DURABILITY the transport does not supply — every ask and every decision is reported as
 * a [PodEvent] for the lead to journal (an approval absent from the journal is
 * invisible to the fold — it can't be audited or re-driven).
 *
 * WHO DECIDES (stated plainly): the authenticated authorizer ceremony is later work;
 * today [decide] is a PLACEHOLDER — a test script, or CI's stub-approver, which is
 * auto-approval relocated from the agent to us and the preflight cannot see it. The CI
 * assertion is only ever that gate RELEASE requires ORIGIN_AUTH_LAYER provenance — a
 * pod's allow answer permits a TOOL CALL inside the pod's own sandbox of consequences,
 * it releases no lead gate (the DELAYED_BYPASS cell pins that).
 *
 * RE-ASK ACROSS CRASHES: there is deliberately NO decision cache — every ask is
 * freshly dispatched to [decide], so a decision made against a dead session cannot
 * authorize a successor session (the engine's restart path re-asks; the events record
 * both asks under their distinct sessionIds).
 *
 * LATE ANSWERS: the CLIENT owns the ask deadline and rejects on the wire when it expires
 * ([AcpClient] fail-closed); a decider answer arriving after that is DISCARDED there.
 * This bridge stamps [PodEvent.PermissionDecided.lateAfterDeadline] from its own clock so
 * the record distinguishes an honored answer from one that arrived after the reject had
 * already crossed the wire.
 *
 * UNJOURNALABLE ASK = DENIED ASK (AGENCY-028): an ask whose
 * PermissionAsked fact the sink REFUSES never reaches the decider at all — the answer is
 * an immediate wire-level reject, with a best-effort "denied-unjournaled" decision fact
 * recording why. The rule is that an approval absent from the journal is invisible
 * to the fold; letting the decider grant one anyway would create exactly that invisible
 * approval. Denials are the one decision safe to make off the record (they authorize
 * nothing), and the refused report is still COUNTED, so the runner's health drain
 * escalates the hole at the next wake.
 */
class PermissionBridge(
  private val askDeadlineMs: Long,
  private val decide: (PermissionAsk) -> PermissionDecision,
  private val eventSink: (PodEvent) -> Unit,
) {
  /** Failed reports are COUNTED, never allowed to change an already-made decision's answer.
   * A throwing sink used to propagate out of the decider into [AcpClient]'s
   * `runCatching`, which turns it into a fail-closed reject — safe in direction, but the
   * ask then crossed the wire REFUSED and unjournaled: the same journal-hole gap in the
   * other direction. */
  private val reportFailures = java.util.concurrent.atomic.AtomicInteger(0)

  /** Count of ask/decision facts the sink refused. Non-zero means the permission record has
   * holes; the lead drains this every wake and escalates (AGENCY-028). */
  fun reportFailures(): Int = reportFailures.get()

  /** True when the sink ACCEPTED the fact (accept means durable, per the journal's own
   * convention); false counts the hole and lets the caller fail closed on it. */
  private fun events(e: PodEvent): Boolean =
    try {
      eventSink(e)
      true
    } catch (_: Throwable) {
      reportFailures.incrementAndGet()
      false
    }

  /** The [PermissionDecider] the engine hands its [AcpClient] for one pod. */
  fun deciderFor(podId: String): PermissionDecider = PermissionDecider { ask ->
    val askRecorded =
      events(
        PodEvent.PermissionAsked(
          podId = podId,
          sessionId = ask.sessionId,
          toolCallId = ask.toolCallId,
          title = ask.title,
          toolKind = ask.toolKind,
        )
      )
    if (!askRecorded) {
      // Fail closed BEFORE the decider (AGENCY-028): no journalable ask, no decision to
      // make. Best-effort decision fact — if the sink refuses this too it is counted the
      // same way — then the reject crosses the wire.
      events(
        PodEvent.PermissionDecided(
          podId = podId,
          sessionId = ask.sessionId,
          toolCallId = ask.toolCallId,
          decision = "denied-unjournaled",
          elapsedMs = 0,
          lateAfterDeadline = false,
        )
      )
      return@PermissionDecider PermissionDecision.RejectOnce
    }
    val t0 = System.nanoTime()
    try {
      val decision = decide(ask)
      val elapsedMs = (System.nanoTime() - t0) / 1_000_000
      events(
        PodEvent.PermissionDecided(
          podId = podId,
          sessionId = ask.sessionId,
          toolCallId = ask.toolCallId,
          decision =
            when (decision) {
              PermissionDecision.AllowOnce -> "allow-once"
              PermissionDecision.RejectOnce -> "reject-once"
            },
          elapsedMs = elapsedMs,
          lateAfterDeadline = elapsedMs > askDeadlineMs,
        )
      )
      decision
    } catch (t: Throwable) {
      val elapsedMs = (System.nanoTime() - t0) / 1_000_000
      // A crashing decider is a FAIL-CLOSED reject at the client (runCatching → null);
      // record the truth of what happened before letting the client's machinery see it.
      events(
        PodEvent.PermissionDecided(
          podId = podId,
          sessionId = ask.sessionId,
          toolCallId = ask.toolCallId,
          decision = "decider-error-denied",
          elapsedMs = elapsedMs,
          lateAfterDeadline = elapsedMs > askDeadlineMs,
        )
      )
      throw t
    }
  }
}
