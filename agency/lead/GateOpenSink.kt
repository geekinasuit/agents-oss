package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.text.hasReadableText

/**
 * The lead-facing seam for announcing that a ceremony gate opened with a single-use nonce, so an
 * operator can be told what to authorize. TRANSPORT-NEUTRAL by construction: no relay, recipient,
 * or nostr type appears here, because the substrate does not depend on the transport — which
 * custodians and which relay a notice reaches are the deployment's wiring. A deployment that
 * notifies over nostr adapts this seam to the relay notifier, supplying the recipient set and the
 * socket timeout; the artifact the operator reads is carried on the signal, read daemon-side from
 * the gate's lead-owned bound copy.
 *
 * NEVER THROWS: [announce] runs on the single-writer loop thread, so a throw would sink the whole
 * drive. A delivery fault is a value ([AnnounceOutcome.Failed]) the daemon journals, not an
 * exception — and the daemon guards the call, so a sink that breaks this contract by throwing an
 * ordinary exception still cannot take the loop down: the fault is recorded as a failed announce
 * instead. (A fatal Error is not caught; it propagates, as an Error does anywhere in the loop.)
 *
 * RETURNS PROMPTLY: [announce] holds the loop thread for as long as it runs, so a sink does not
 * retry or wait inside the call. It returns [AnnounceOutcome.Failed] when it cannot deliver, and
 * the daemon sends the whole signal again on a later wake, after a backoff, for a bounded number of
 * attempts; when the last fails, the daemon escalates. So a recipient reached on an earlier attempt
 * may receive the same signal again; the nonce is single-use, so a repeat cannot authorize twice. A
 * sink that reached some recipients and not others chooses: [AnnounceOutcome.Announced] if what it
 * delivered lets the operator act, or [AnnounceOutcome.Failed] to have the whole signal sent again.
 * The retry and the escalation need the daemon's timer service to fire. Its default,
 * [TimerService.NOOP], fires nothing, and under it a failed announce is neither sent again nor
 * escalated.
 */
fun interface GateOpenSink {
  fun announce(signal: GateOpenSignal): AnnounceOutcome
}

/**
 * What the daemon hands a [GateOpenSink] the moment a ceremony gate opens: the auth-layer facts an
 * operator authorizes against — the gate, the digest it is open on, the substrate-issued nonce an
 * approval must commit to — and [artifact], the readable thing a human approves instead of a hash.
 * The daemon reads [artifact] from the gate's lead-owned bound copy and verifies its bytes hash to
 * [payloadDigest] before constructing this signal, so the operator reads EXACTLY what the nonce
 * authorizes: the hash match is a correctness property of the notice, not storage hygiene. [artifact]
 * always has something to read ([hasReadableText]): a notice cannot be built from one that does not,
 * so it is refused here and no sink is handed one.
 */
data class GateOpenSignal(
  val gateId: String,
  val payloadDigest: String,
  val nonce: String,
  val artifact: String,
) {
  init {
    require(hasReadableText(artifact)) { "GateOpenSignal.artifact must have something to read" }
  }
}

/**
 * The lead-neutral result of [GateOpenSink.announce], recorded verbatim as the notify marker's
 * outcome. Never thrown — a fault is [Failed], so a sink that could not deliver leaves a legible
 * record. Only a [Failed] the sink reports, or a throw from it, is sent again, when a retry timer
 * fires, never on every pass of the loop. The daemon's own [Failed] for an artifact it could not
 * resolve is final.
 */
sealed interface AnnounceOutcome {
  /** The sink took responsibility for the announcement; [summary] is opaque to the substrate — a
   * wired sink maps its per-recipient delivery report to it — and journaled as-is. */
  data class Announced(val summary: String) : AnnounceOutcome

  /** No sink is wired: nothing was announced. The gate is still marked, so the arm stays inert and
   * fires at most once — the notice reaches an operator only once a real sink is wired. */
  object NoSink : AnnounceOutcome

  /** The sink could not deliver; [detail] is journaled. The daemon sends the signal again later,
   * when its timer service fires (see [GateOpenSink]), for a bounded number of attempts, and
   * escalates when the last fails. A value, not a throw — the loop survives. */
  data class Failed(val detail: String) : AnnounceOutcome
}

/**
 * The default [GateOpenSink]: announces nothing, reports [AnnounceOutcome.NoSink]. Every in-tree
 * daemon runs with this, so a ceremony gate is marked announced and never re-announced, keeping the
 * notify arm inert until the deployment wires a sink that reaches an operator.
 */
val NoOpGateOpenSink = GateOpenSink { AnnounceOutcome.NoSink }
