package com.geekinasuit.agency.pod

import java.io.File

/** A launched pod's identity: [sessionId] is journaled at spawn time so re-attach can be
 * designed from the entries alone. */
data class PodSpawned(val podId: String, val sessionId: String)

/**
 * A pod's completion report. [costUsd] is NULL when the transport surfaces no measurement
 * (null-not-zero): an unmeasured cost must never be representable as a measured
 * $0 — the journal omits the field entirely and the fold reads it back as null. A real
 * 0.0 means MEASURED zero (the scripted fake, which runs no model, reports that).
 *
 * [snapshot] is the BIND-ONCE hand-off: the exact bytes the
 * engine's single disciplined read produced — an immutable in-memory snapshot the lead
 * binds, persists to its own bound-artifact store, and hands every downstream consumer.
 * [artifactPath] (the pod's write target) is journaled as PROVENANCE and never read a
 * second time: re-reading it would let anything that can still reach the workspace swap
 * the inode between the digest and its consumers. [resultDigest] is the engine's digest
 * of these same bytes; the lead RECOMPUTES from [snapshot] before journaling (cheap, and
 * it keeps "the digest describes what was consumed" a property the lead verified itself).
 * Size is bounded by the engine's artifact byte cap. NOTE: [ByteArray] compares by
 * reference under data-class equals — completions are consumed field-wise, never compared
 * wholesale.
 */
data class PodCompletion(
  val podId: String,
  val artifactPath: String,
  val resultDigest: String,
  val costUsd: Double?,
  val snapshot: ByteArray,
)

/**
 * Engine seam: the transport-facing layer BELOW the daemon's
 * PodRunner. A runner dispatches by [PodSpec.transport]; each engine owns one transport's
 * process/connection lifecycle ([AcpPodEngine] speaks ACP to a pinned agent
 * binary; an HTTP engine drives plain APIs). Engine obligations mirror the runner
 * contract and add the fence:
 *  - call [PodSpec.requireSpawnable] before ANY side effect (defense in depth under the
 *    daemon's own spawn-site check);
 *  - the pod writes its result at the lead-assigned [spawn] artifactPath and reports a
 *    digest — artifacts + digests are the only hand-off;
 *  - [spawn]'s onComplete must only ENQUEUE, never touch the store (a completion can
 *    arrive before the loop journals POD_SPAWNED; completion facts are the loop's to
 *    journal).
 */
interface PodEngine {
  fun spawn(
    spec: PodSpec,
    taskRef: String,
    workdir: File,
    artifactPath: String,
    onComplete: (PodCompletion) -> Unit,
  ): PodSpawned
}
