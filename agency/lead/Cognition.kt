package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalState

/**
 * The cognition seam: the model-bearing layer is a
 * strategy the model-free substrate HOSTS. Per wake the substrate renders an [AgentWakeContext]
 * view, calls [AgentCognition.decide], journals a usable output with origin = cognition (the
 * audit record) unless it has neither proposals nor call meta, as a scripted idle turn does, then
 * executes the proposals itself — the substrate is the sole journal writer and the sole actor.
 * While the output is unusable, the substrate calls [AgentCognition.decide] again, a bounded
 * number of times, and journals each unusable attempt with substrate origin and without the
 * model's text. A gate-open retry timer's wake does not call it while the timer's nonce is still
 * the one its gate waits on and no mail waits: the substrate sends the failed announce again
 * itself, and the gate still blocks the pipeline.
 *
 * The proposal vocabulary is deliberately narrow: cognition supplies JUDGMENT (when a
 * plan is ready to gate, what task a pod should run, what status to report, when to give
 * up and escalate); the substrate advances the MECHANICAL pipeline (claiming an offered
 * ticket, recording a finished pod's artifact, proposing the commit manifest, driving the
 * post-approval effect). Nothing cognition can output releases a gate: the fold's release
 * check keys on origin == auth layer, and cognition-origin entries can never satisfy it.
 *
 * [lead] is the folded state of a lead running some workflow: the host reads it only through
 * [HostView], and the workflow's own code reads the rest.
 */
data class AgentWakeContext<out S : HostView>(
  val reason: WakeReason,
  val lead: S,
  val shared: JournalState,
  val undeliveredMail: List<Pair<Long, String>>,
)

/** What the host's own code reads of a lead's folded state, whatever workflow the lead runs. */
interface HostView {
  val openGates: Map<String, OpenGate>
  val activePods: List<PodRecord>
  val staleReleases: List<Pair<Long, String>>
  val escalations: List<String>
  val cognitionSpendUsd: Double
  val pods: Map<String, PodRecord>
  val pendingSpawnIntents: Map<String, Long>
  val declinedEffects: Set<String>
  val escalatedStalls: Map<String, Set<String>>
  val issuedNonces: Map<String, IssuedNonce>
  val notifiedNonces: Set<String>
  val failedAnnounces: Map<String, Int>
  val notReadAnnounces: Map<String, Int>

  /** Whether [gateId] is approved on the digest it is open on now. */
  fun approvedOnCurrentDigest(gateId: String): Boolean

  /** [gate]'s usable nonce: issued for it, on the digest it is open on, and not consumed. */
  fun openNonceFor(gate: OpenGate): IssuedNonce?
}

sealed interface WakeReason {
  /** First pass after adopt (fresh start or kill-recovery). */
  data object Adopted : WakeReason

  data class MailArrived(val message: String) : WakeReason

  data class TimerFired(val timerId: String) : WakeReason

  data class PodCompleted(val podId: String) : WakeReason

  /** A pod ended WITHOUT a completion — preflight/artifact refusal, restarts exhausted,
   * or a deadline kill. [disposition] names the engine's terminal event. The substrate
   * has already journaled POD_ABANDONED by the time cognition sees this; the reason is
   * evidence for the judgment call (re-propose the task vs give up and escalate). */
  data class PodDisposed(val podId: String, val disposition: String) : WakeReason

  data class GateReleased(val gateId: String) : WakeReason
}

sealed interface Proposal {
  /**
   * Open an authorization gate bound to the exact artifact digest the approver will see.
   * The digest here is a CLAIM, not a command: at execution the substrate validates it
   * against its own recorded evidence for the gate kind (the plan sha, the manifest
   * digest) and escalates instead of opening on any mismatch — cognition decides WHEN to
   * gate, never WHAT the approver is shown.
   */
  data class ProposeGateOpen(val gateKind: String, val payloadDigest: String) : Proposal

  /** Spawn a pod for [taskRef]; the substrate assigns the artifact path. */
  data class ProposePodSpawn(val taskRef: String) : Proposal

  data class ProposeStatus(val status: String) : Proposal

  data class ProposeEscalate(val reason: String) : Proposal
}

/**
 * Whether the decider of a wake was presented the context it was handed: the evidence the daemon
 * needs before it marks that context's mail delivered, which has no inverse.
 *
 * The vocabulary stops at "presented" on purpose. The substrate can establish that a model turn
 * was SENT the rendered context and completed. It cannot establish that the model processed what
 * it was sent, so no value here claims that.
 */
enum class ContextPresentation {
  /** The decision was made with the context in front of the decider, as rendered: a model-backed
   * strategy sent the rendered context in a turn that completed, or a strategy decided from the
   * structured context itself. */
  PRESENTED,

  /** No decider was presented the context: no turn ran (a spend cap), or the turn failed. */
  NOT_PRESENTED,

  /** The strategy cannot say. Treated exactly as [NOT_PRESENTED]. */
  UNKNOWN;

  /** Only [PRESENTED] retires mail. */
  val retiresMail: Boolean
    get() = this == PRESENTED
}

/** One wake's cognition output: zero proposals = idle. [meta] carries strategy-specific
 * provenance (a model-backed strategy's sessionId and costUsd) into the journaled record.
 * [presentation] has no default: every strategy states whether its decider was presented the
 * context, because the daemon retires mail only on [ContextPresentation.PRESENTED]. */
data class CognitionOutput(
  val proposals: List<Proposal> = emptyList(),
  val reasoning: String = "",
  val meta: Map<String, String> = emptyMap(),
  /**
   * Non-null when the strategy could not read a usable decision out of its model's output.
   * The reason is the SUBSTRATE's classification of the failure, never the model's own
   * words — so the row stays an observation about an untrusted producer.
   *
   * A malformed turn journals [HostKinds.COGNITION_MALFORMED] and its [proposals] are never
   * executed: near-miss structured output (valid JSON, an unknown proposal type, a
   * hallucinated gate kind) is untrusted input at the substrate's boundary, not a decision.
   *
   * Deliberately NOT expressed as a [Proposal.ProposeEscalate]: "the model asked for a
   * human" and "the model emitted noise" are different facts, and collapsing them makes an
   * unreliable model indistinguishable in the fold from a deliberating one — which is
   * precisely the signal needed to notice that a smaller model is degrading.
   */
  val malformed: String? = null,
  val presentation: ContextPresentation,
) {
  companion object {
    /** An idle decision. The caller says whether it was made on the context: a scripted idle
     * was, a model-backed strategy idling at its spend cap without a turn was not. */
    fun idle(presentation: ContextPresentation) = CognitionOutput(reasoning = "idle", presentation = presentation)

    /** Shared constructor for the malformed outcome — every model-backed strategy classifies
     * unusable output the same way, and the daemon keys on [malformed] alone. Its presentation
     * is [ContextPresentation.UNKNOWN]: a malformed output is never a decision, and the daemon
     * retires no mail on it whatever this says. */
    fun malformed(reason: String, meta: Map<String, String> = emptyMap()) =
      CognitionOutput(
        reasoning = "unusable cognition output",
        meta = meta,
        malformed = reason,
        presentation = ContextPresentation.UNKNOWN,
      )
  }
}

interface AgentCognition<in S : HostView> {
  val name: String

  fun decide(context: AgentWakeContext<S>): CognitionOutput
}

/** Test wrapper: counts [decide] calls — the zero-spend-while-idle assertion's probe. Its
 * output, presentation included, is the wrapped strategy's own. */
class CountingCognition<S : HostView>(private val inner: AgentCognition<S>) : AgentCognition<S> {
  @Volatile var calls: Int = 0
    private set

  override val name = inner.name

  override fun decide(context: AgentWakeContext<S>): CognitionOutput {
    calls += 1
    return inner.decide(context)
  }
}
