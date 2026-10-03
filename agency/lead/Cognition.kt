package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalState

/**
 * The cognition seam: the model-bearing layer is a
 * strategy the model-free substrate HOSTS. Per wake the substrate renders a [WakeContext]
 * view, calls [CognitionStrategy.decide], journals a usable output with origin = cognition (the
 * audit record) unless it has neither proposals nor call meta, as a scripted idle turn does, then
 * executes the proposals itself — the substrate is the sole journal writer and the sole actor.
 * While the output is unusable, the substrate calls [CognitionStrategy.decide] again, a bounded
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
 */
data class WakeContext(
  val reason: WakeReason,
  val lead: LeadState,
  val shared: JournalState,
  val undeliveredMail: List<Pair<Long, String>>,
)

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
   * A malformed turn journals [LeadKinds.COGNITION_MALFORMED] and its [proposals] are never
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

interface CognitionStrategy {
  val name: String

  fun decide(context: WakeContext): CognitionOutput
}

/** The reason [ScriptedCognition] escalates a stale release with. */
private const val STALE_RELEASE_REASON = "stale gate release observed (digest mismatch)"

/**
 * Deterministic playbook on [WakeContext] predicates: drives the full ticket
 * walk — claim (substrate) → plan pod → plan gate → execute pod → commit gate → done
 * (substrate) — with zero model involvement, so every CI path is deterministic. This is
 * the deterministic half of the coverage; [ClaudeCognition] is the model-backed half.
 *
 * Predicates key on EVIDENCE (artifact present, gate open, an active pod exists), not on
 * strict phase progression — so the playbook is idempotent across wakes and self-heals
 * after kill-recovery abandons a pod mid-flight: the missing evidence simply gets
 * re-proposed. [LeadState.phase] stays the observability surface tests assert on.
 */
class ScriptedCognition : CognitionStrategy {
  override val name = "scripted"

  override fun decide(context: WakeContext): CognitionOutput {
    val lead = context.lead
    val ticket = lead.currentTicket ?: return IDLE

    // A stale release is escalated once. The check looks for that escalation only, so an escalation
    // of another kind, such as a gate-open no sink announced, does not silence it. The escalations
    // are a capped tail: once enough later ones push this one out, it is raised again.
    if (lead.staleReleases.isNotEmpty() && STALE_RELEASE_REASON !in lead.escalations) {
      return decided(
        listOf(Proposal.ProposeEscalate(STALE_RELEASE_REASON)),
        "a release did not match the gate as opened; a human should look",
      )
    }

    val planGate = lead.openGates[gateIdFor(GateKinds.PLAN_APPROVAL, ticket)]
    val commitGate = lead.openGates[gateIdFor(GateKinds.COMMIT_APPROVAL, ticket)]
    val planApproved = lead.approvedOnEvidence(GateKinds.PLAN_APPROVAL, ticket)
    fun activePodFor(taskRef: String) = lead.activePods.any { it.taskRef == taskRef }

    return when {
      lead.planArtifactSha == null && !activePodFor("plan:$ticket") ->
        decided(
          listOf(
            Proposal.ProposePodSpawn("plan:$ticket"),
            Proposal.ProposeStatus("planning $ticket"),
          ),
          "no plan artifact and no planner in flight; spawning a planner pod",
        )
      lead.planArtifactSha != null && planGate == null ->
        decided(
          listOf(
            Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, lead.planArtifactSha),
            Proposal.ProposeStatus("plan ready for approval: $ticket"),
          ),
          "plan artifact recorded; opening the plan-approval gate on its digest",
        )
      planApproved && lead.commitManifestDigest == null && !activePodFor("execute:$ticket") ->
        decided(
          listOf(
            Proposal.ProposePodSpawn("execute:$ticket"),
            Proposal.ProposeStatus("executing $ticket"),
          ),
          "plan approved and no manifest yet; spawning the execute pod",
        )
      lead.commitManifestDigest != null && commitGate == null ->
        decided(
          listOf(
            Proposal.ProposeGateOpen(GateKinds.COMMIT_APPROVAL, lead.commitManifestDigest),
            Proposal.ProposeStatus("commit ready for approval: $ticket"),
          ),
          "commit manifest proposed; opening the commit-approval gate on its digest",
        )
      else -> IDLE // waiting on a gate to be authorized or a pod to finish
    }
  }

  private companion object {
    /** The playbook decides from the structured context itself, with no render in between, so
     * every decision it makes, idling included, was made with that context in front of it. */
    val IDLE = CognitionOutput.idle(ContextPresentation.PRESENTED)

    fun decided(proposals: List<Proposal>, reasoning: String) =
      CognitionOutput(proposals, reasoning, presentation = ContextPresentation.PRESENTED)
  }
}

/** Deterministic gate identity: one gate per (kind, ticket) — idempotent across re-proposals. */
fun gateIdFor(gateKind: String, ticketRef: String): String = "$gateKind:$ticketRef"

/** Test wrapper: counts [decide] calls — the zero-spend-while-idle assertion's probe. Its
 * output, presentation included, is the wrapped strategy's own. */
class CountingCognition(private val inner: CognitionStrategy) : CognitionStrategy {
  @Volatile var calls: Int = 0
    private set

  override val name = inner.name

  override fun decide(context: WakeContext): CognitionOutput {
    calls += 1
    return inner.decide(context)
  }
}
