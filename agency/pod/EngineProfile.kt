package com.geekinasuit.agency.pod

import com.agentclientprotocol.model.SessionUpdate
import java.io.File
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * Per-provider engine profile: how [AcpPodEngine] launches one provider's
 * agent process and reads its cost surface. Profiles are LEAD-OWNED config, selected by
 * the substrate from a [PodSpec] the substrate constructed — nothing here is
 * reachable from cognition output.
 *
 * Profiles: [ClaudeAdapterProfile] (the LIVE Claude pod),
 * [FixtureAgentProfile] (the deterministic battery's fake binary) and [GrokNativeProfile]
 * (WRITTEN to shape the API, throws — the deferred exfil-capable pod, fenced until
 * network-egress enforcement exists).
 */
interface EngineProfile {
  val name: String

  /** The agent process argv. Called after the [PodSpec] fence check; a profile whose
   * provider is deferred throws here as defense in depth under [PodSpec.requireSpawnable]. */
  fun argv(spec: PodSpec, workdir: File): List<String>

  /** Explicit env for the agent process, applied on top of the constructed allowlist env
   * (cleanEnv=true always — a pod never inherits ambient env). */
  fun env(spec: PodSpec): Map<String, String> = emptyMap()

  /**
   * The `_meta` payload for session/new, or null when the profile has no session options.
   * This is the lead-owned CONFIGURATION channel: for the Claude adapter it
   * carries the SDK options that keep agent config workspace-INDEPENDENT (settingSources,
   * config-dir relocation) plus the turn/spend bounds. Computed ONCE at spawn and
   * reused for every session the pod's restart ladder establishes — a restart must not
   * re-derive config any more than it re-derives argv.
   */
  fun sessionMeta(spec: PodSpec): JsonElement? = null

  /**
   * The acp protocol version this profile's PINNED agent must negotiate, or null to skip
   * the check (fixtures). Compared against the initialize handshake (acp is pre-1.0
   * and a point release can silently move the protocol; a skewed agent must fail FAST at
   * launch, not misbehave mid-task). A mismatch is a launch failure — it burns a restart
   * attempt and exhausts into a visible escalation naming both versions.
   */
  fun expectedProtocolVersion(): String? = null

  /** Preflight sentinel prompt: must instruct an EXECUTE-kind tool use (file writes may
   * be auto-allowed and never route an ask). */
  fun preflightPrompt(): String

  /**
   * Extract the pod's cost in USD from the turn's session updates, or NULL when the
   * transport surfaced no measurement (null-not-zero: an unmeasured cost must never
   * be representable as a measured $0). The fixture profile measures nothing → null.
   */
  fun costUsdFrom(updates: List<SessionUpdate>): Double? = null
}

/**
 * The live Claude pod profile: launches the PINNED
 * `@agentclientprotocol/claude-agent-acp` adapter under node — the adapter speaks acp to
 * our client and drives Claude Code through the embedded Agent SDK. Every control below
 * is expressed against the adapter's own seams because the adapter exposes no inner-argv
 * seam (established by source-read plus a live run):
 *
 *  - VERSION PIN: argv execs [nodeBinary] on [adapterEntry] — an ABSOLUTE path into
 *    the lockfile-pinned install at agency/pod/adapter (npm ci --ignore-scripts; the
 *    lockfile is the pin, upgrades are reviewed acts). The INNER Claude Code binary
 *    defaults to the SDK-bundled build; [claudeExecutable] pins it by path via
 *    CLAUDE_CODE_EXECUTABLE when the lead wants a specific one. The negotiated protocol
 *    version is pinned via [expectedProtocolVersion]; the scheduled PodCanary validates
 *    the whole pinned handshake post-merge.
 *  - LEAD-OWNED WORKSPACE-INDEPENDENT CONFIG:
 *    session/new `_meta.claudeCode.options` sets `settingSources: []` — NO user/project/
 *    local settings discovery, so a pod-written look-alike settings file or hook is inert
 *    by configuration, not by luck — and CLAUDE_CONFIG_DIR relocates the config root to
 *    [configDir], a LEAD-owned directory that must live OUTSIDE any pod workspace. The
 *    adapter must not discover home-dir state as carried state.
 *  - SPEND/TURN BOUNDS: maxTurns + maxBudgetUsd forwarded as typed SDK options via
 *    the same `_meta` channel (probed present in the pinned SDK). The engine's wall clock
 *    remains the bound WE enforce; these are the agent-side bounds.
 *  - PHONE-HOME DENIAL: [PHONE_HOME_DENY_ENV] rides BOTH channels — the adapter's
 *    process env (inheritance into the inner CLI proven live) AND
 *    options.env (later in the adapter's env spread, so it survives an adapter release
 *    that stops inheriting). REQUESTED-denial, stated plainly: setting the vars
 *    is observable; honoring them is cooperative and server-toggleable. The hard
 *    boundary is the deferred egress floor's job.
 *
 * Auth is the MACHINE CREDENTIAL (the host's Claude login — macOS keychain), never an API
 * key in any env. Whether machine-credential auth composes with the relocated config dir
 * is answered by the env-gated smoke (agency/lead's RealAdapterSmokeTest) on a real host.
 */
class ClaudeAdapterProfile(
  /** The node runtime, ABSOLUTE (same rationale as [FixtureAgentProfile.command]: a pod's
   * cwd is the workspace and its env is the constructed allowlist, so PATH lookup and
   * relative paths resolve against the wrong world). */
  private val nodeBinary: File,
  /** The pinned adapter's entry file (…/node_modules/@agentclientprotocol/claude-agent-acp/
   * dist/index.js under the lockfile-governed install), ABSOLUTE. */
  private val adapterEntry: File,
  /** The lead-owned CLAUDE_CONFIG_DIR. Must be workspace-INDEPENDENT — never a
   * path any pod can write. The wiring owns that placement; this class can only demand
   * absoluteness. */
  private val configDir: File,
  /** Optional pin-by-path for the INNER Claude Code binary (CLAUDE_CODE_EXECUTABLE).
   * Null = the adapter's SDK-bundled build, which the lockfile already pins. */
  private val claudeExecutable: File? = null,
) : EngineProfile {
  init {
    require(nodeBinary.isAbsolute) { "nodeBinary must be absolute, got '$nodeBinary'" }
    require(adapterEntry.isAbsolute) { "adapterEntry must be absolute, got '$adapterEntry'" }
    require(configDir.isAbsolute) { "configDir must be absolute, got '$configDir'" }
    require(claudeExecutable?.isAbsolute != false) {
      "claudeExecutable must be absolute when supplied, got '$claudeExecutable'"
    }
  }

  override val name: String = "claudeAdapter"

  override fun argv(spec: PodSpec, workdir: File): List<String> =
    listOf(nodeBinary.path, adapterEntry.path)

  override fun env(spec: PodSpec): Map<String, String> = buildMap {
    put("CLAUDE_CONFIG_DIR", configDir.path)
    claudeExecutable?.let { put("CLAUDE_CODE_EXECUTABLE", it.path) }
    putAll(PHONE_HOME_DENY_ENV)
  }

  override fun sessionMeta(spec: PodSpec): JsonElement = buildJsonObject {
    putJsonObject("claudeCode") {
      putJsonObject("options") {
        // [] — the adapter's default ["user","project","local"] sits BEFORE this spread,
        // so the empty list WINS and no settings file anywhere is read.
        putJsonArray("settingSources") {}
        put("model", spec.model)
        spec.maxTurns?.let { put("maxTurns", it) }
        spec.maxBudgetUsd?.let { put("maxBudgetUsd", it) }
        putJsonObject("env") {
          put("CLAUDE_CONFIG_DIR", configDir.path)
          claudeExecutable?.let { put("CLAUDE_CODE_EXECUTABLE", it.path) }
          for ((k, v) in PHONE_HOME_DENY_ENV) put(k, v)
        }
      }
    }
  }

  override fun expectedProtocolVersion(): String = ClaudeAdapterPin.PROTOCOL_VERSION

  /** Execute-kind on purpose: a file write may be auto-allowed and
   * never route an ask, so only a shell/execute tool call exercises the ask channel the
   * preflight exists to observe. */
  override fun preflightPrompt(): String =
    "Preflight check: run the shell command `true` using your execute/Bash tool, then " +
      "stop. This one command verifies permission-ask routing before the real task; " +
      "please take no other action."

  /**
   * The adapter's cost surface: usage_update session updates carry a running
   * `cost {amount, currency}`; the LAST cost-bearing update of the turn is the total. A
   * turn with no cost-bearing update — or a cost in a currency other than USD, which this
   * extractor refuses to guess a conversion for — is UNMEASURED: null, never 0.0.
   */
  override fun costUsdFrom(updates: List<SessionUpdate>): Double? {
    val last = updates.filterIsInstance<SessionUpdate.UsageUpdate>().lastOrNull { it.cost != null }
    val cost = last?.cost ?: return null
    return if (cost.currency == "USD") cost.amount else null
  }

  companion object {
    // The adapter package/version/protocol pin lives in [ClaudeAdapterPin] (spec layer):
    // the descriptor's pinnedVersion field carries it, so it must sit below this profile.

    /**
     * Phone-home/telemetry/auto-update lanes, REQUESTED-denied. These are Claude
     * Code's documented opt-outs: the umbrella nonessential-traffic switch plus the
     * specific lanes it covers, set explicitly so the denial does not depend on the
     * umbrella's semantics holding across CLI versions. Cooperative by nature — the
     * contract is requested-denial, and the hard network boundary is deferred with the
     * egress floor.
     */
    val PHONE_HOME_DENY_ENV: Map<String, String> =
      mapOf(
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC" to "1",
        "DISABLE_AUTOUPDATER" to "1",
        "DISABLE_TELEMETRY" to "1",
        "DISABLE_ERROR_REPORTING" to "1",
        "DISABLE_BUG_COMMAND" to "1",
        "DISABLE_NON_ESSENTIAL_MODEL_CALLS" to "1",
      )
  }
}

/**
 * The deterministic battery's profile: launches the [FakeAcpAgent] subprocess binary
 * (a real child process speaking real NDJSON stdio — the engine's process red paths need
 * a killable OS process, not an in-process pipe pair). [agentArgs] select the fake's
 * variant/behavior per test cell.
 */
class FixtureAgentProfile(
  /**
   * The agent process command, fully resolved and ABSOLUTE. Absolute matters here beyond
   * tidiness: a pod's working directory is the WORKSPACE, not the launcher's, and its env
   * is the constructed allowlist — so anything resolved relative to CWD or found via a
   * loose PATH is resolved against the wrong world. (Discovered the hard way: the bazel
   * JVM launcher script derives its embedded JDK from the CWD, so launching the fixture
   * through it looked for `java` under the pod's temp workspace. The battery now execs
   * the JVM directly.)
   */
  private val command: List<String>,
  /**
   * Explicit env for the fixture agent, on top of the constructed allowlist — the same
   * channel a real profile uses for its own needs (explicit map, never
   * ambient-allowlisted; AGENCY-010's proxy/CA vars arrive this way).
   */
  private val extraEnv: Map<String, String> = emptyMap(),
) : EngineProfile {
  override val name: String = "fixture"

  override fun argv(spec: PodSpec, workdir: File): List<String> = command

  override fun env(spec: PodSpec): Map<String, String> = extraEnv

  override fun preflightPrompt(): String = "preflight-sentinel"
}

/**
 * The deferred Grok pod profile: WRITTEN so the provider-plural
 * profile surface is shaped by a real second provider, but every launch path THROWS —
 * the CLI binary is exfiltration-capable (v0.2.93 out-of-band trace upload) and has no
 * safe home until network-egress enforcement (broker or container floor).
 * Defense in depth: [PodSpec.requireSpawnable] already fences transport=acp non-Claude
 * profiles unconditionally; this throw covers the path where a future caller
 * reaches the profile without the spec fence.
 */
object GrokNativeProfile : EngineProfile {
  override val name: String = "grokNative"

  override fun argv(spec: PodSpec, workdir: File): List<String> =
    throw IllegalStateException(
      "grokNative pod profile is deferred: the Grok CLI agent is exfiltration-capable and " +
        "must not launch until network-egress enforcement exists"
    )

  override fun preflightPrompt(): String =
    throw IllegalStateException(
      "grokNative pod profile is deferred until network-egress enforcement exists"
    )
}
