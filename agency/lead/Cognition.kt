package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalState

/**
 * The cognition seam: the model-bearing layer is a
 * strategy the model-free substrate HOSTS. Per wake the substrate renders a [WakeContext]
 * view, calls [CognitionStrategy.decide] exactly once, journals the output verbatim with
 * origin = cognition (the audit record), then executes the proposals itself — the
 * substrate is the sole journal writer and the sole actor.
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

/** One wake's cognition output: zero proposals = idle. [meta] carries strategy-specific
 * provenance (a model-backed strategy's sessionId and costUsd) into the journaled record. */
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
) {
  companion object {
    val IDLE = CognitionOutput(emptyList(), "idle")

    /** Shared constructor for the malformed outcome — every model-backed strategy classifies
     * unusable output the same way, and the daemon keys on [malformed] alone. */
    fun malformed(reason: String, meta: Map<String, String> = emptyMap()) =
      CognitionOutput(reasoning = "unusable cognition output", meta = meta, malformed = reason)
  }
}

interface CognitionStrategy {
  val name: String

  fun decide(context: WakeContext): CognitionOutput
}

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
    val ticket = lead.currentTicket ?: return CognitionOutput.IDLE

    if (lead.staleReleases.isNotEmpty() && lead.escalations.isEmpty()) {
      return CognitionOutput(
        listOf(Proposal.ProposeEscalate("stale gate release observed (digest mismatch)")),
        "a release did not match the gate as opened; a human should look",
      )
    }

    val planGate = lead.openGates[gateIdFor(GateKinds.PLAN_APPROVAL, ticket)]
    val commitGate = lead.openGates[gateIdFor(GateKinds.COMMIT_APPROVAL, ticket)]
    val planApproved = planGate != null && planGate.gateId in lead.releasedGates
    fun activePodFor(taskRef: String) = lead.activePods.any { it.taskRef == taskRef }

    return when {
      lead.planArtifactSha == null && !activePodFor("plan:$ticket") ->
        CognitionOutput(
          listOf(
            Proposal.ProposePodSpawn("plan:$ticket"),
            Proposal.ProposeStatus("planning $ticket"),
          ),
          "no plan artifact and no planner in flight; spawning a planner pod",
        )
      lead.planArtifactSha != null && planGate == null ->
        CognitionOutput(
          listOf(
            Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, lead.planArtifactSha),
            Proposal.ProposeStatus("plan ready for approval: $ticket"),
          ),
          "plan artifact recorded; opening the plan-approval gate on its digest",
        )
      planApproved && lead.commitManifestDigest == null && !activePodFor("execute:$ticket") ->
        CognitionOutput(
          listOf(
            Proposal.ProposePodSpawn("execute:$ticket"),
            Proposal.ProposeStatus("executing $ticket"),
          ),
          "plan approved and no manifest yet; spawning the execute pod",
        )
      lead.commitManifestDigest != null && commitGate == null ->
        CognitionOutput(
          listOf(
            Proposal.ProposeGateOpen(GateKinds.COMMIT_APPROVAL, lead.commitManifestDigest),
            Proposal.ProposeStatus("commit ready for approval: $ticket"),
          ),
          "commit manifest proposed; opening the commit-approval gate on its digest",
        )
      else -> CognitionOutput.IDLE // waiting on a gate to be authorized or a pod to finish
    }
  }
}

/** Deterministic gate identity: one gate per (kind, ticket) — idempotent across re-proposals. */
fun gateIdFor(gateKind: String, ticketRef: String): String = "$gateKind:$ticketRef"

/** Test wrapper: counts [decide] calls — the zero-spend-while-idle assertion's probe. */
class CountingCognition(private val inner: CognitionStrategy) : CognitionStrategy {
  @Volatile var calls: Int = 0
    private set

  override val name = inner.name

  override fun decide(context: WakeContext): CognitionOutput {
    calls += 1
    return inner.decide(context)
  }
}
