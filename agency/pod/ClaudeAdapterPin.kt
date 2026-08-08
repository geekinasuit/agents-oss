package com.geekinasuit.agency.pod

/**
 * The pinned Claude ACP adapter package: the ONE place the code states
 * which adapter build the live Claude pod launches. Must match agency/pod/adapter's
 * package.json AND its lockfile — PodCanary cross-checks those plus the installed
 * package's own version, so a drifted install or a half-updated pin fails loudly
 * instead of running skewed. Lives in the spec layer
 * (below the engine profiles) because the descriptor's pinnedVersion field carries it:
 * [PodSpec.claudeAdapter] stamps specs with it, [ClaudeAdapterProfile] launches by it.
 */
object ClaudeAdapterPin {
  const val PACKAGE = "@agentclientprotocol/claude-agent-acp"
  const val VERSION = "0.63.0"

  /** The acp protocol version the pinned adapter negotiates (probed live). A launch-time
   * handshake check compares this against the agent's initialize response (acp is
   * pre-1.0; a point release can silently move the protocol). */
  const val PROTOCOL_VERSION = "1"
}
