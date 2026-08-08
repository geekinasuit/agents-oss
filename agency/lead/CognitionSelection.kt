package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.harness.ClaudeHarness
import com.geekinasuit.agency.shared.harness.OpenAiCompatHarness
import com.geekinasuit.agency.shared.harness.OpenAiCompatProfile
import java.io.File

/**
 * A strategy together with the per-wake attempt cap it should be run under.
 *
 * The two travel as one value because whether a retry can help is a property of the
 * strategy — deterministic sampling means attempt two is attempt one — while the cap is a
 * [LeadDaemon] constructor argument with a default. Handing back a bare
 * [CognitionStrategy] would leave every caller to remember the pairing, and the failure
 * mode of forgetting is invisible: the lead simply pays twice for the same answer.
 *
 * Being a value does not make it unbypassable — a caller can still construct a strategy
 * and a daemon separately, as the tests do. What it removes is having to KNOW the pairing:
 * a caller that goes through here gets it, and one that does not is making a visible choice.
 */
data class CognitionChoice(
  val strategy: CognitionStrategy,
  val maxCognitionAttempts: Int,
)

/**
 * Where a lead's cognition strategy is chosen. Provider plurality is the point:
 * each entry differs only in transport, and all of them speak [CognitionProtocol].
 */
object CognitionSelection {
  /** Deterministic playbook, no model: the CI default. */
  fun scripted() = CognitionChoice(ScriptedCognition(), maxCognitionAttempts = 1)

  /** Headless Claude CLI. Billed, so the daemon's default retry allowance applies —
   * a resample can legitimately differ from the near-miss that preceded it. */
  fun claude(workDir: File, model: String = ClaudeHarness.MODEL) =
    CognitionChoice(
      ClaudeCognition(workDir = workDir, model = model),
      maxCognitionAttempts = DEFAULT_MAX_ATTEMPTS,
    )

  /** Local Ollama over loopback: no key, no egress, no bill. */
  fun ollama(model: String, baseUrl: String = OpenAiCompatProfile.OLLAMA_BASE_URL) =
    CognitionChoice(
      OpenAiCompatCognition(OpenAiCompatHarness(OpenAiCompatProfile.ollama(model, baseUrl))),
      maxCognitionAttempts = OpenAiCompatCognition.MAX_ATTEMPTS_PER_WAKE,
    )

  /**
   * Selection by name, for a lead configured from outside the process.
   *
   * `grok` is named here rather than omitted so that asking for it fails with the reason
   * instead of "unknown strategy", which reads as a typo. The keyed profile it needs is
   * refused at construction until the key lifecycle and its activation guard land.
   */
  fun byName(name: String, workDir: File, model: String?): CognitionChoice =
    when (name) {
      "scripted" -> scripted()
      "claude" -> claude(workDir, model ?: ClaudeHarness.MODEL)
      "ollama" ->
        ollama(model ?: error("cognition strategy 'ollama' requires an explicit model tag"))
      "grok" ->
        error(
          "cognition strategy 'grok' is not selectable yet: it needs a scoped " +
            "key, its lifecycle and an activation guard"
        )
      else -> error("unknown cognition strategy '${name.take(40)}'")
    }

  /** The daemon's own default, restated here so a choice that wants it says so. */
  private const val DEFAULT_MAX_ATTEMPTS = 2
}
