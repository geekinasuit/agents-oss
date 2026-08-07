package com.geekinasuit.agency.pod

/**
 * Pod descriptor: WHAT the substrate spawns — provider, transport,
 * auth mode, pin — as lead-owned data. The descriptor is SUBSTRATE-CONSTRUCTED:
 * every [PodSpec] the daemon spawns comes from lead-owned config; cognition proposes a
 * TASK (a taskRef), never a descriptor. That constraint is structural — the proposal type
 * has no descriptor fields — and pinned by tests at both the parse and spawn boundaries.
 */
enum class PodProvider {
  CLAUDE,
  GROK,
  LOCAL,
}

/** How the engine drives the provider: an ACP agent process, or a plain HTTP API. */
enum class PodTransport {
  ACP,
  HTTP,
}

enum class PodAuthMode {
  /** The machine's own standing credential (the claude adapter's login). */
  MACHINE_CREDENTIAL,
  /** A key file read at point of use — never an env var, never into a prompt. */
  API_KEY_FILE,
  /** No authentication (local providers). */
  NONE,
}

/**
 * Egress-enforcement capability. Deliberately UNCONSTRUCTIBLE today:
 * the constructor is private and there is NO factory, so no code can present this
 * capability and the ACP non-Claude fence in [PodSpec.requireSpawnable] is unconditional.
 * The first real enforcement mechanism (network namespace, proxy allowlist)
 * adds its factory HERE, making the unblock reviewable in exactly one place.
 */
class EgressEnforcement private constructor()

/**
 * One pod profile. Values come from lead-owned config (workspace-independent,
 * substrate-read); [pinnedVersion] pins the agent/adapter build the profile launches
 * (pods launch pinned versions, upgrades are deliberate acts).
 */
data class PodSpec(
  val provider: PodProvider,
  val model: String,
  val baseUrl: String? = null,
  val authMode: PodAuthMode,
  val transport: PodTransport,
  val pinnedVersion: String,
  val maxTurns: Int? = null,
  /** Per-pod spend bound in USD, enforced by the agent side (the Claude adapter
   * forwards it as the SDK's maxBudgetUsd option). Null = the profile requests no bound —
   * legal for transports with no spend (fixtures, local models); the [claudeAdapter]
   * factory REQUIRES it, per the no-default rule on spend knobs. */
  val maxBudgetUsd: Double? = null,
) {
  /**
   * The fail-closed fence: spawning ANY transport=ACP profile whose provider is not
   * Claude THROWS unless an explicit egress-enforcement capability is supplied — and no
   * such capability is constructible today (see [EgressEnforcement]), so the throw is
   * unconditional for that combination. The ACP adapter surface hands an agent process
   * tools and workspace bytes, which is exfiltration-capable; a non-Claude agent behind
   * it requires ENFORCED egress control, not policy. HTTP profiles are not fenced here:
   * that transport carries prompts to an endpoint the lead chose, not a tool-wielding
   * agent process. Callers spawn-side (the daemon, every engine) call this before any
   * side effect.
   */
  fun requireSpawnable(egress: EgressEnforcement? = null) {
    if (transport == PodTransport.ACP && provider != PodProvider.CLAUDE && egress == null) {
      throw IllegalStateException(
        "fenced pod profile: transport=acp with provider=${provider.name.lowercase()} is not " +
          "spawnable without an egress-enforcement capability, and none exists yet — the ACP " +
          "adapter surface is exfiltration-capable, so non-Claude agents behind it require " +
          "enforced egress controls"
      )
    }
  }

  companion object {
    /**
     * The profile the scripted fake test pods stand in for, spawnable by construction.
     * Fixture rigs use this; [claudeAdapter] is the live profile.
     */
    fun fixture(): PodSpec =
      PodSpec(
        provider = PodProvider.CLAUDE,
        model = "fixture",
        authMode = PodAuthMode.MACHINE_CREDENTIAL,
        transport = PodTransport.ACP,
        pinnedVersion = "fixture",
      )

    /**
     * The live Claude pod: machine-credential auth through the pinned ACP
     * adapter ([ClaudeAdapterProfile] owns the launch mechanics). Both runaway knobs are
     * REQUIRED — no defaults — because a silently-unbounded turn count or spend on the one
     * live cloud pod is exactly the footgun the repo's no-default rule on safety toggles
     * exists for (the pod also carries the engine's wall clock, but that bounds TIME,
     * not turns or dollars).
     */
    fun claudeAdapter(model: String, maxTurns: Int, maxBudgetUsd: Double): PodSpec {
      require(maxTurns > 0) { "maxTurns must be positive, got $maxTurns" }
      require(maxBudgetUsd > 0.0 && maxBudgetUsd.isFinite()) {
        "maxBudgetUsd must be a positive finite bound, got $maxBudgetUsd"
      }
      return PodSpec(
        provider = PodProvider.CLAUDE,
        model = model,
        authMode = PodAuthMode.MACHINE_CREDENTIAL,
        transport = PodTransport.ACP,
        pinnedVersion = ClaudeAdapterPin.VERSION,
        maxTurns = maxTurns,
        maxBudgetUsd = maxBudgetUsd,
      )
    }
  }
}
