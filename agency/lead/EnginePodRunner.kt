package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.AcpPodEngine
import com.geekinasuit.agency.pod.EngineProfile
import com.geekinasuit.agency.pod.EngineTimings
import com.geekinasuit.agency.pod.PermissionAsk
import com.geekinasuit.agency.pod.PermissionBridge
import com.geekinasuit.agency.pod.PermissionDecision
import com.geekinasuit.agency.pod.PodCompletion
import com.geekinasuit.agency.pod.PodEvent
import com.geekinasuit.agency.pod.PodSpawned
import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.pod.PodTransport
import java.io.File
import java.util.concurrent.atomic.AtomicReference

/**
 * The REAL pod runner: fills the daemon's [PodRunner] seam with the ACP
 * engine stack — [AcpPodEngine] + [PermissionBridge] over one lead-owned [EngineProfile] —
 * replacing the scripted fakes for live runs. One runner hosts ONE profile, matching the
 * daemon's single lead-owned [PodSpec]; per-provider dispatch widens when a second pod
 * transport gains an engine, and until then a non-ACP spec is refused loudly below.
 *
 * EVENT SINK, LATE-BOUND: engine and bridge report supervisory facts ([PodEvent]) which
 * belong in the journal via [LeadDaemon.injectPodEvent] — but the daemon is constructed
 * WITH its runner, so the sink cannot exist at construction time. [bindEventSink] closes
 * the loop once, after the daemon exists. An event arriving UNBOUND (a mis-wired rig —
 * impossible through the daemon, which only spawns after construction) throws into the
 * engine/bridge defenses: counted as a report failure, surfaced by [drainHealthFaults],
 * and for a permission ask the bridge's fail-closed rule turns it into a wire-level deny.
 *
 * HEALTH DRAIN (AGENCY-028, resolved): the engine and bridge COUNT reports their sink
 * refused — the synchronous accept-boundary append stays (a queue would re-open the
 * accepted-but-not-durable window AGENCY-021 closed), and the counters are READ:
 * [drainHealthFaults] watermarks both counters and returns one fault line per NEW batch
 * of refusals, which [LeadDaemon.handleWake] escalates at the top of every wake — so a
 * journal with holes announces itself within one wake, and an idle daemon (no wakes)
 * is also generating no reportable facts beyond what its last wake swept.
 */
class EnginePodRunner(
  profile: EngineProfile,
  timings: EngineTimings,
  decide: (PermissionAsk) -> PermissionDecision,
) : PodRunner, AutoCloseable {

  private val eventSink = AtomicReference<((PodEvent) -> Unit)?>(null)

  private val bridge = PermissionBridge(timings.askDeadlineMs, decide, ::deliver)
  private val engine = AcpPodEngine(profile, bridge, ::deliver, timings)

  /** Watermarks for [drainHealthFaults] — loop-thread only, like the drain itself. */
  private var reportedEngineFailures = 0
  private var reportedBridgeFailures = 0

  /** Bind the journal-side event sink (normally `daemon::injectPodEvent`) exactly once. */
  fun bindEventSink(sink: (PodEvent) -> Unit) {
    check(eventSink.compareAndSet(null, sink)) { "event sink already bound" }
  }

  private fun deliver(e: PodEvent) {
    val sink =
      eventSink.get()
        ?: throw IllegalStateException("pod event before the event sink was bound (mis-wired rig)")
    sink(e)
  }

  override fun spawn(
    spec: PodSpec,
    taskRef: String,
    workdir: File,
    artifactPath: String,
    onComplete: (PodCompletion) -> Unit,
  ): PodSpawned {
    // Fence first, before dispatch (defense in depth under the daemon's own spawn-site
    // check and the engine's — three locks, same door).
    spec.requireSpawnable()
    return when (spec.transport) {
      PodTransport.ACP -> engine.spawn(spec, taskRef, workdir, artifactPath, onComplete)
      PodTransport.HTTP ->
        // A configuration fault, so a THROW is right (the daemon's wake-fault path journals
        // it and stops for a supervisor): the lead's own spec names a transport this runner
        // has no engine for. The OpenAI-compatible harness does NOT serve this — it backs
        // the lead's own cognition turns, which are chat completions, whereas a pod runs a
        // task in a workspace. An HTTP-transport pod needs an engine of its own.
        throw IllegalStateException(
          "no engine for transport=http: this runner launches ACP pods only, so the " +
            "lead's PodSpec (provider=${spec.provider.name.lowercase()}) is not launchable"
        )
    }
  }

  override fun drainHealthFaults(): List<String> {
    val out = mutableListOf<String>()
    val engineFailures = engine.eventReportFailures()
    if (engineFailures > reportedEngineFailures) {
      out +=
        "pod-engine event sink refused ${engineFailures - reportedEngineFailures} report(s) " +
          "(total $engineFailures) — engine facts are missing from the journal (AGENCY-028)"
      reportedEngineFailures = engineFailures
    }
    val bridgeFailures = bridge.reportFailures()
    if (bridgeFailures > reportedBridgeFailures) {
      out +=
        "permission-bridge event sink refused ${bridgeFailures - reportedBridgeFailures} " +
          "report(s) (total $bridgeFailures) — ask/decision facts are missing from the " +
          "journal; affected asks were denied unjournaled (AGENCY-028)"
      reportedBridgeFailures = bridgeFailures
    }
    return out
  }

  /** True when every spawned pod reached a terminal state and the engine's executors are
   * down — the clean-shutdown observable, passed through for rigs and the smoke. */
  fun closedCleanly(): Boolean = engine.closedCleanly()

  override fun close() {
    engine.close()
  }
}
