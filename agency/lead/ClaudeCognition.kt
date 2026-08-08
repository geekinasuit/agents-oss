package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.harness.ClaudeHarness
import java.io.File

/**
 * Model-backed cognition, judgment kept thin day-one: one
 * headless Claude turn per wake, budget-capped, producing the same typed proposals the
 * scripted playbook does. The substrate journals the output (with this strategy's
 * sessionId + cost in [CognitionOutput.meta]) and executes it; nothing this class returns
 * can release a gate — the folds' provenance check is indifferent to how clever the
 * proposal text is.
 *
 * The prompt, the state rendering and the parse are [CognitionProtocol] — shared with
 * every other model-backed strategy so the lead accepts exactly one definition of a
 * decision regardless of which provider produced it. What this class owns is the Claude
 * transport: the headless CLI turn, its budget caps, and its session/cost provenance.
 *
 * Unusable output is [CognitionOutput.malformed], never a proposal: the lead does not
 * guess at intent, and "the model emitted noise" stays a distinct journal fact from "the
 * model asked for a human".
 *
 * Model selection comes from the capability descriptor; the wake-loop
 * blocking guarantee — zero turns while nothing happens — lives in the daemon, not here.
 */
class ClaudeCognition(
  private val harness: ClaudeHarness = ClaudeHarness(),
  private val model: String = ClaudeHarness.MODEL,
  private val workDir: File,
  private val maxBudgetUsd: Double = 0.25,
  /** Cumulative cap across the lead's LIFE, read from the journal-derived
   * [LeadState.cognitionSpendUsd] — not an in-memory counter, so restarts keep every cost
   * already journaled. At the cap: one visible escalation, then idle without spending (no
   * turn is run). KNOWN GAP, stated not hidden: the paid turn is NOT
   * journaled intent-before-effect, so a crash between the harness call returning and
   * [LeadDaemon.journalCognitionOutput] loses that turn's cost — cumulative spend can
   * UNDERCOUNT by at most one turn across a crash. Closing the window (journal an intent with
   * an estimated cost BEFORE the call, reconcile the real cost on completion) is future
   * budget work. Until then this is a FLOOR that bounds
   * unbounded wake-driven spend, not an exact meter. */
  private val maxTotalUsd: Double = 5.0,
  private val timeoutSec: Int = 120,
) : CognitionStrategy {
  override val name = "claude"

  override fun decide(context: WakeContext): CognitionOutput {
    if (context.lead.cognitionSpendUsd >= maxTotalUsd) {
      val alreadyRaised = context.lead.escalations.any { it.startsWith("cognition budget") }
      return if (alreadyRaised) CognitionOutput.IDLE
      else
        CognitionOutput(
          listOf(
            Proposal.ProposeEscalate(
              "cognition budget exhausted: journal-derived spend " +
                "${context.lead.cognitionSpendUsd} USD >= cap $maxTotalUsd USD; idling until raised"
            )
          ),
          reasoning = "cumulative spend cap reached before this wake; no turn was run",
        )
    }
    val turn =
      harness.turn(
        prompt = CognitionProtocol.renderContext(context),
        workDir = workDir,
        model = model,
        maxBudgetUsd = maxBudgetUsd,
        appendSystemPrompt = CognitionProtocol.SYSTEM_PROMPT,
        timeoutSec = timeoutSec,
      )
    val meta =
      mapOf(
        "model" to model,
        "sessionId" to turn.sessionId,
        "costUsd" to turn.costUsd.toString(),
      )
    if (!turn.ok) {
      return CognitionOutput(
        listOf(Proposal.ProposeEscalate("cognition turn failed (exit=${turn.proc.exit}, isError=${turn.isError})")),
        reasoning = "harness turn did not complete cleanly",
        meta = meta,
      )
    }
    return CognitionProtocol.parseOutput(turn.resultText, meta)
  }
}
