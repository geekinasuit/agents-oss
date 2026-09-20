package com.geekinasuit.agency.lead

/**
 * The lead-facing seam for announcing that a ceremony gate opened with a single-use nonce, so an
 * operator can be told what to authorize. TRANSPORT-NEUTRAL by construction: no relay, recipient,
 * or nostr type appears here, because the substrate does not depend on the transport — which
 * custodians and which relay a notice reaches are coach-side wiring (§REPO_SEAM). Coach adapts this
 * seam to the relay notifier, supplying the recipient set and the socket timeout; the artifact the
 * operator reads is carried on the signal, read daemon-side from the gate's lead-owned bound copy.
 *
 * NEVER THROWS: [announce] runs on the single-writer loop thread, so a throw would sink the whole
 * drive. A delivery fault is a value ([AnnounceOutcome.Failed]) the daemon journals, not an
 * exception — and the daemon guards the call, so a sink that breaks this contract by throwing an
 * ordinary exception still cannot take the loop down: the fault is recorded as a failed announce
 * instead. (A fatal Error is not caught; it propagates, as an Error does anywhere in the loop.)
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
 * is never blank — a blank one cannot build a notice — enforced here so no sink is handed one.
 */
data class GateOpenSignal(
  val gateId: String,
  val payloadDigest: String,
  val nonce: String,
  val artifact: String,
) {
  init {
    require(artifact.isNotBlank()) { "GateOpenSignal.artifact must not be blank" }
  }
}

/**
 * The lead-neutral result of [GateOpenSink.announce], recorded verbatim as the notify marker's
 * outcome. Never thrown — a fault is [Failed], so a sink that could not deliver leaves a legible
 * record and the gate is still marked announced (a fail-closed liveness gap), rather than the loop
 * re-announcing every pass.
 */
sealed interface AnnounceOutcome {
  /** The sink took responsibility for the announcement; [summary] is opaque to the substrate — a
   * wired sink maps its per-recipient delivery report to it — and journaled as-is. */
  data class Announced(val summary: String) : AnnounceOutcome

  /** No sink is wired: nothing was announced. The gate is still marked, so the arm stays inert and
   * fires at most once — the notice reaches an operator only once a real sink is wired. */
  object NoSink : AnnounceOutcome

  /** The sink faulted; [detail] is journaled. A value, not a throw — the loop survives. */
  data class Failed(val detail: String) : AnnounceOutcome
}

/**
 * The default [GateOpenSink]: announces nothing, reports [AnnounceOutcome.NoSink]. Every in-tree
 * daemon runs with this, so a ceremony gate is marked announced and never re-announced, keeping the
 * notify arm inert until coach wires a sink that reaches an operator.
 */
val NoOpGateOpenSink = GateOpenSink { AnnounceOutcome.NoSink }
