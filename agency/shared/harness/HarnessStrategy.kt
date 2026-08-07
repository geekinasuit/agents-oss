/**
 * Neutral harness seam for the Agency pod runtime.
 *
 * The extension point every agent harness implements: run a prompt in a working
 * directory, get back a model-agnostic [RunResult]. Adapters (claude today;
 * qwen/goose/opencode tracked as a follow-up) sit behind this interface so the pod
 * launcher depends on the seam, not a concrete harness.
 */
package com.geekinasuit.agency.shared.harness

import java.io.File

/**
 * Model-agnostic outcome of a single harness run — the common denominator across
 * every harness. Rich, harness-specific detail (claude's session id, cost, turn
 * count) is deliberately NOT flattened into this type; it stays on the adapter's own
 * result (e.g. [ClaudeHarness.TurnResult]) for callers driving session mechanics.
 */
data class RunResult(
    /**
     * The model's final response text on success; on a failed turn, the raw subprocess
     * output (truncated) as a diagnostic. NOT a control channel — check [ok], never a
     * text prefix.
     */
    val text: String,
    /** Tool/turn calls if the harness reports them; null when unavailable. */
    val toolCalls: Int?,
    /** Subprocess exit code (124 = timed out). */
    val exitCode: Int,
    /**
     * Whether the turn succeeded — the neutral failure signal. False on a non-zero exit,
     * unparseable output, OR the harness's own error flag: a bare [exitCode] can't carry
     * the last case (a harness can report a semantic error while the process still exits 0).
     */
    val ok: Boolean,
)

/**
 * One agent harness. Deliberately a plain interface, not a sealed hierarchy: new
 * adapters are added out-of-tree as the pod runtime grows.
 */
interface HarnessStrategy {
  /** Short harness id, e.g. "claude". */
  val name: String

  /**
   * Run [promptText] once in [workDir] and return the neutral result.
   * [appendSystemPrompt], when non-null, is appended to the system prompt (the
   * authority-framing channel).
   */
  fun execute(promptText: String, workDir: File, appendSystemPrompt: String? = null): RunResult
}
