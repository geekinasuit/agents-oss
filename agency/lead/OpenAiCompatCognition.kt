package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.harness.OpenAiCompatHarness

/**
 * Model-backed cognition over an OpenAI-compatible endpoint: one chat
 * completion per wake, producing the same typed proposals every other strategy does.
 *
 * The prompt, the state rendering and the parse are [CognitionProtocol], identical to the
 * Claude path — the provider changes which model answers, never what the lead will accept
 * as a decision. Nothing returned here can release a gate; the fold keys on origin.
 *
 * **No budget cap, deliberately.** [ClaudeCognition] gates on
 * [LeadState.cognitionSpendUsd] because its turns are billed. A loopback endpoint has no
 * billing relationship, so there is no spend to bound and a cap would be ceremony over a
 * number that is always zero. What bounds this strategy is the wake loop itself: it is
 * consulted once per wake and the loop blocks between wakes, so an idle lead runs no
 * turns at all. That is also why this strategy writes no `costUsd` into
 * [CognitionOutput.meta] — see [decide].
 */
class OpenAiCompatCognition(
  private val harness: OpenAiCompatHarness,
  private val maxTokens: Int = OpenAiCompatHarness.DEFAULT_MAX_TOKENS,
  private val timeoutSec: Int = OpenAiCompatHarness.DEFAULT_TIMEOUT_SEC,
) : CognitionStrategy {
  override val name = harness.profile.name

  /**
   * [CognitionOutput.meta] is built from a fixed set of substrate-owned keys and never
   * from the provider's response object, so no field the endpoint controls can collide
   * with the substrate's own account of the turn when the row is journaled.
   *
   * It carries token counts and no `costUsd`. Cost is not the observable on a free local
   * model, and writing a 0.0 into the key [LeadState.cognitionSpendUsd] accumulates would
   * quietly change what that field means — from "what cognition has spent" to "what the
   * billed strategies have spent", weakening a number the budget cap reads. Tokens are
   * what this wire actually reports, so tokens are what gets recorded.
   */
  override fun decide(context: WakeContext): CognitionOutput {
    val turn =
      harness.chat(
        systemPrompt = CognitionProtocol.SYSTEM_PROMPT,
        userPrompt = CognitionProtocol.renderContext(context),
        maxTokens = maxTokens,
        timeoutSec = timeoutSec,
      )
    val meta = buildMap {
      put("model", harness.profile.model)
      turn.promptTokens?.let { put("promptTokens", it.toString()) }
      turn.completionTokens?.let { put("completionTokens", it.toString()) }
    }
    if (!turn.ok) {
      // A transport failure is not a malformed turn: the model never answered, so there is
      // no unusable output to classify and nothing about its reliability to record.
      return CognitionOutput(
        listOf(
          Proposal.ProposeEscalate(
            "cognition turn failed (status=${turn.status}): ${turn.error ?: "unknown failure"}"
          )
        ),
        reasoning = "harness turn did not complete cleanly",
        meta = meta,
      )
    }
    return CognitionProtocol.parseOutput(turn.text, meta)
  }

  companion object {
    /**
     * Cognition attempts to allow per wake when the lead is wired with this strategy
     * ([LeadDaemon.maxCognitionAttempts]).
     *
     * One, because a retry here asks an identical question and gets an identical answer.
     * The request pins `temperature: 0`, and [CognitionProtocol.renderContext] renders only
     * fields derived from the fold — none of which the substrate changes between attempts
     * within a wake (the malformed row is not rendered, and the escalation that would move
     * the rendered count is written only after the attempts are exhausted). So a second
     * attempt re-sends the same bytes.
     *
     * Measured, not assumed: three identical requests to `qwen3-coder:30b` on loopback
     * returned byte-identical content and identical token counts. If that ever stopped
     * holding, the cost of this value being wrong is bounded and visible — the wake
     * escalates where a retry might have succeeded, which shows up in the journal rather
     * than as silent spend.
     */
    const val MAX_ATTEMPTS_PER_WAKE = 1
  }
}
