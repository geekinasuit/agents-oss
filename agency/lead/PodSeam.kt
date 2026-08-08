package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodCompletion
import com.geekinasuit.agency.pod.PodSpawned
import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.pod.sha256Hex
import java.io.File
import java.util.UUID

/**
 * Pod seam: the interface the lead drives
 * pods through, plus the scripted fake that makes every CI path deterministic. The REAL
 * launcher — engines behind this seam (//agency/pod's PodEngine;
 * AcpPodEngine) under their stated residuals — drops in without touching the daemon. The shared
 * completion/identity types ([PodCompletion], [PodSpawned]) live in //agency/pod.
 *
 * Hand-off discipline: the LEAD assigns the artifact path at spawn; the pod
 * writes its result THERE and reports a digest. The lead never scrapes transcripts —
 * artifacts + digests are the only hand-off.
 *
 * Session identity: [PodSpawned.sessionId] is journaled at spawn time so re-attach
 * can be designed from the entries alone. Fake pods RE-SPAWN on adopt rather than resume;
 * real `--resume` adoption arrives later.
 */
interface PodRunner {
  /**
   * Launch a pod described by [spec] for [taskRef], instructed to write its artifact at
   * [artifactPath]. The [spec] is the LEAD's (substrate-constructed — the daemon
   * passes its own lead-owned profile; nothing cognition outputs can reach it), already
   * fence-checked via [PodSpec.requireSpawnable] before this is called. Completion is
   * reported via [onComplete] — which must only ENQUEUE, never touch the store: a
   * completion can arrive synchronously inside spawn, BEFORE the loop has journaled
   * POD_SPAWNED, so an append here would write the result ahead of its pod's spawn record
   * and the fold would drop it (completion facts are the loop's to journal — see
   * [LeadDaemon.injectPodCompletion]).
   */
  fun spawn(
    spec: PodSpec,
    taskRef: String,
    workdir: File,
    artifactPath: String,
    onComplete: (PodCompletion) -> Unit,
  ): PodSpawned

  /**
   * Return-and-clear accumulated health faults: report failures the runner's async
   * plumbing could not surface as journal facts at the moment they happened (an event
   * sink's synchronous append refused, a permission ask that could not be recorded —
   * AGENCY-028). The daemon drains this at the top of EVERY wake and escalates each
   * fault, so a fault ages at most one wake before a human-visible record exists.
   * Draining must be idempotent-when-empty; the default covers runners with no async
   * plumbing (the scripted fakes).
   */
  fun drainHealthFaults(): List<String> = emptyList()
}

/**
 * Scripted pod runner: writes a deterministic artifact at the lead-assigned path and
 * completes immediately (through the callback, so completion still arrives as a wake
 * event, exercising the same path a real async pod will). [holdCompletions] parks
 * completions instead — the idle/no-spend and kill-while-pod-active cells need a pod
 * that is genuinely outstanding.
 */
class FakePodRunner(private val holdCompletions: Boolean = false) : PodRunner {
  private val held = mutableListOf<Pair<PodCompletion, (PodCompletion) -> Unit>>()

  val spawnedTaskRefs = mutableListOf<String>()

  /** The specs the daemon spawned with — the provenance tripwire's observation
   * point: a test asserts these are exactly the lead-owned spec, never anything a
   * cognition proposal could have supplied. */
  val spawnedSpecs = mutableListOf<PodSpec>()

  override fun spawn(
    spec: PodSpec,
    taskRef: String,
    workdir: File,
    artifactPath: String,
    onComplete: (PodCompletion) -> Unit,
  ): PodSpawned {
    spawnedTaskRefs += taskRef
    spawnedSpecs += spec
    val podId = "pod-" + UUID.randomUUID().toString().take(8)
    val sessionId = "fake-session-" + UUID.randomUUID().toString()
    val content = scriptedArtifact(taskRef)
    val f = File(artifactPath)
    f.parentFile?.mkdirs()
    f.writeText(content)
    // costUsd = 0.0 is a MEASURED zero — the fake runs no model, so its true spend is $0.
    // null is reserved for genuinely unmeasured transports (null-not-zero).
    val completion =
      PodCompletion(
        podId,
        artifactPath,
        sha256Hex(content),
        costUsd = 0.0,
        snapshot = content.toByteArray(),
      )
    if (holdCompletions) held += completion to onComplete else onComplete(completion)
    return PodSpawned(podId, sessionId)
  }

  /** Release parked completions (test control surface). */
  fun releaseHeld() {
    val toRun = held.toList()
    held.clear()
    for ((completion, cb) in toRun) cb(completion)
  }

  private fun scriptedArtifact(taskRef: String): String =
    when {
      taskRef.startsWith("plan:") ->
        "# Plan for ${taskRef.removePrefix("plan:")}\n\n1. change the fixture file\n2. verify\n"
      taskRef.startsWith("execute:") ->
        """{"fileset":["src/example.txt"],"summary":"scripted change for ${taskRef.removePrefix("execute:")}"}""" + "\n"
      else -> "artifact for $taskRef\n"
    }
}
