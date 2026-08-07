/**
 * Claude Code adapter: the headless-claude harness behind the
 * neutral [HarnessStrategy] seam, and a SUPERSET of it — [execute] gives the neutral
 * single-turn path, while [turn]/[TurnResult] expose the session mechanics (resume,
 * fork, wrapper-assigned session id, cost, provenance). Reconciling TurnResult *down*
 * into the thin neutral RunResult would gut exactly those, so the rich result is kept
 * intact.
 */
package com.geekinasuit.agency.shared.harness

import java.util.UUID
import org.json.JSONObject
import java.io.File

class ClaudeHarness(val claudeBin: String = "claude") : HarnessStrategy {
  override val name = "claude"

  /** Parsed `--output-format json` result envelope. */
  data class TurnResult(
      val raw: String,
      val json: JSONObject?,
      val resultText: String,
      val sessionId: String,
      val subtype: String,
      val numTurns: Int,
      val costUsd: Double,
      val isError: Boolean,
      val proc: ProcResult,
  ) {
    val ok: Boolean
      get() = proc.exit == 0 && !isError
  }

  /**
   * Neutral single-turn path: run the turn, then map its rich result down through the
   * pure [neutralResult] seam. num_turns ≈ tool calls (each turn = one tool-call +
   * response cycle).
   */
  override fun execute(promptText: String, workDir: File, appendSystemPrompt: String?): RunResult =
      neutralResult(turn(promptText, workDir, appendSystemPrompt = appendSystemPrompt))

  /** Build the claude CLI argv for one headless turn (pure — the unit-tested seam). */
  fun turnCmd(
      prompt: String,
      model: String = MODEL,
      resume: String? = null,
      forkSession: Boolean = false,
      sessionId: String? = null,
      permissionMode: String? = null,
      settingsJson: String? = null,
      maxBudgetUsd: Double? = null,
      appendSystemPrompt: String? = null,
  ): List<String> {
    val cmd = mutableListOf(claudeBin, "-p", "--output-format", "json", "--model", model)
    if (resume != null) cmd += listOf("--resume", resume)
    if (forkSession) cmd += "--fork-session"
    if (sessionId != null) cmd += listOf("--session-id", sessionId)
    if (permissionMode != null) cmd += listOf("--permission-mode", permissionMode)
    if (settingsJson != null) cmd += listOf("--settings", settingsJson)
    if (maxBudgetUsd != null) cmd += listOf("--max-budget-usd", maxBudgetUsd.toString())
    if (appendSystemPrompt != null) cmd += listOf("--append-system-prompt", appendSystemPrompt)
    cmd += prompt
    return cmd
  }

  /** Run one headless claude turn under the hardened runtime (constructed env). */
  fun turn(
      prompt: String,
      workDir: File,
      model: String = MODEL,
      resume: String? = null,
      forkSession: Boolean = false,
      sessionId: String? = null,
      permissionMode: String? = null,
      settingsJson: String? = null,
      maxBudgetUsd: Double? = null,
      appendSystemPrompt: String? = null,
      env: Map<String, String> = emptyMap(),
      timeoutSec: Int = 180,
  ): TurnResult {
    val cmd =
        turnCmd(
            prompt, model, resume, forkSession, sessionId, permissionMode, settingsJson,
            maxBudgetUsd, appendSystemPrompt)
    return parseTurn(Subprocess.run(cmd, workDir, env, timeoutSec, cleanEnv = true))
  }

  fun claudeVersion(): String =
      Subprocess.run(listOf(claudeBin, "--version"), File("."), timeoutSec = 30, cleanEnv = true)
          .stdout
          .trim()

  companion object {
    const val MODEL = "claude-haiku-4-5-20251001"

    /** Cap on the raw-output diagnostic carried in a failed [RunResult.text]. */
    const val RAW_DIAGNOSTIC_CHARS = 2000

    val UUID_RE = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

    fun newUuid(): String = UUID.randomUUID().toString()

    /** Parse a claude `--output-format json` envelope into the rich [TurnResult]. */
    fun parseTurn(proc: ProcResult): TurnResult {
      val json =
          try {
            JSONObject(proc.stdout)
          } catch (_: Exception) {
            null
          }
      return TurnResult(
          raw = proc.stdout,
          json = json,
          resultText = json?.optString("result") ?: "",
          sessionId = json?.optString("session_id") ?: "",
          subtype = json?.optString("subtype") ?: "",
          numTurns = json?.optInt("num_turns", -1) ?: -1,
          costUsd = json?.optDouble("total_cost_usd", -1.0) ?: -1.0,
          isError = json?.optBoolean("is_error", true) ?: true,
          proc = proc,
      )
    }

    /**
     * Map a rich [TurnResult] down to the neutral [RunResult] — the pure seam every
     * neutral-path consumer depends on. [RunResult.ok] carries the failure signal a
     * bare exit code cannot: a claude turn can report is_error while the process still
     * exits 0, and unparseable output (json == null) is a failure even on exit 0. On
     * failure [RunResult.text] is the raw output (truncated) as a diagnostic, NOT a
     * sentinel consumers match on; toolCalls is null when num_turns was absent (-1).
     */
    fun neutralResult(t: TurnResult): RunResult =
        RunResult(
            text = if (t.json == null) t.raw.take(RAW_DIAGNOSTIC_CHARS) else t.resultText,
            toolCalls = t.numTurns.takeIf { it >= 0 },
            exitCode = t.proc.exit,
            ok = t.ok,
        )

    /** Provenance stamp: harness + version + model + session. */
    fun provenanceStamp(version: String, model: String, sessionId: String): JSONObject =
        JSONObject()
            .put("harness", "claude-code")
            .put("harnessVersion", version)
            .put("model", model)
            .put("sessionId", sessionId)
  }
}
