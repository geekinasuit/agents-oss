package com.geekinasuit.agency.pod

import java.io.File
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The canary's GATE logic against the wire-faithful fake. Two properties:
 * the PASS path pins that the pinned SDK actually negotiates
 * [ClaudeAdapterPin.PROTOCOL_VERSION] (a future SDK bump that moves the protocol trips
 * this cell → updating the pin const becomes a reviewed act), and the FAIL paths prove
 * version/protocol skew genuinely trips the gate — a canary that cannot fail is
 * telemetry-shaped noise. The pin-coherence gate runs against synthetic file layouts in
 * every drift direction.
 */
class PodCanaryCoreTest {

  private fun withHonestHandshake(block: (AcpClient.Handshake) -> Unit) {
    val toAgent = PipedOutputStream()
    val toClient = PipedOutputStream()
    val agent = FakeAcpAgent(FakeAgentVariant.HONEST, PipedInputStream(toAgent, PIPE_BUF), toClient)
    val client =
      AcpClient(
        agentStdout = PipedInputStream(toClient, PIPE_BUF),
        agentStdin = toAgent,
        decider = { PermissionDecision.RejectOnce },
        askDeadlineMs = 1_000,
        name = "canary-core-test",
      )
    try {
      block(client.initialize(10_000))
    } finally {
      client.close()
      agent.close()
    }
  }

  @Test
  fun `handshake gate passes a faithful agent and pins the SDK protocol version`() =
    withHonestHandshake { handshake ->
      // The fake self-reports version = variant name; expecting it makes the gate green.
      // expectedProtocol is the REAL pin const: this cell fails the moment the pinned SDK
      // negotiates anything other than what ClaudeAdapterPin claims.
      val failures =
        PodCanary.handshakeGate(handshake, ClaudeAdapterPin.PROTOCOL_VERSION, "HONEST")
      assertEquals(emptyList<String>(), failures)
    }

  @Test
  fun `handshake gate trips on adapter version skew naming both versions`() =
    withHonestHandshake { handshake ->
      val failures =
        PodCanary.handshakeGate(handshake, ClaudeAdapterPin.PROTOCOL_VERSION, "0.63.0")
      assertEquals(1, failures.size)
      assertTrue(failures[0], failures[0].contains("HONEST") && failures[0].contains("0.63.0"))
    }

  @Test
  fun `handshake gate trips on protocol skew naming both versions`() =
    withHonestHandshake { handshake ->
      val failures = PodCanary.handshakeGate(handshake, "999", "HONEST")
      assertEquals(1, failures.size)
      assertTrue(failures[0], failures[0].contains("999") && failures[0].contains("protocol"))
    }

  @Test
  fun `handshake gate trips on an agent that reports no version`() {
    val handshake =
      AcpClient.Handshake(
        protocolVersion = ClaudeAdapterPin.PROTOCOL_VERSION,
        agentName = "anon",
        agentVersion = null,
        loadSession = false,
      )
    val failures =
      PodCanary.handshakeGate(handshake, ClaudeAdapterPin.PROTOCOL_VERSION, "0.63.0")
    assertEquals(1, failures.size)
    assertTrue(failures[0], failures[0].contains("no version"))
  }

  // ---- the full lifecycle against a LIVE agent process ----

  @Test
  fun `handshake lifecycle reaps a live agent and returns instead of hanging`() {
    // The property under test is TERMINATION with the process dead: the fake agent — like
    // the real adapter — completes initialize and then stays alive serving, holding its
    // stdout open. The lifecycle must kill it to unpark the client's readers and return;
    // an ordering that closes the client while the agent lives parks this cell forever
    // (the target's timeout is the tripwire).
    val command =
      FakeAgentLauncher.agentCommand("--variant", FakeAgentVariant.HONEST.name)
        ?: return org.junit.Assume.assumeTrue("fake agent binary not staged (run under bazel)", false)
    val notes = mutableListOf<String>()
    val failures =
      PodCanary.handshakeWithProcess(
        argv = command,
        workdir = Files.createTempDirectory("canary-lifecycle-test").toFile(),
        env = emptyMap(),
        expectedProtocol = ClaudeAdapterPin.PROTOCOL_VERSION,
        expectedVersion = FakeAgentVariant.HONEST.name,
        timeoutMs = 20_000,
        notes = notes,
      )
    assertEquals(emptyList<String>(), failures)
    assertTrue(
      "the handshake evidence line is recorded, got $notes",
      notes.any { it.contains("acp v${ClaudeAdapterPin.PROTOCOL_VERSION}") },
    )
  }

  // ---- pin coherence over synthetic adapter layouts ----

  private fun adapterDir(
    declared: String? = ClaudeAdapterPin.VERSION,
    locked: String? = ClaudeAdapterPin.VERSION,
    installed: String? = ClaudeAdapterPin.VERSION,
  ): File {
    val pkg = ClaudeAdapterPin.PACKAGE
    val dir = Files.createTempDirectory("canary-pin-test").toFile()
    declared?.let {
      File(dir, "package.json").writeText("""{"dependencies":{"$pkg":"$it"}}""")
    }
    locked?.let {
      File(dir, "package-lock.json")
        .writeText("""{"packages":{"node_modules/$pkg":{"version":"$it"}}}""")
    }
    installed?.let {
      val p = File(dir, "node_modules/$pkg/package.json")
      p.parentFile.mkdirs()
      p.writeText("""{"name":"$pkg","version":"$it"}""")
    }
    return dir
  }

  @Test
  fun `pin gate passes a coherent layout with one evidence note per authority`() {
    val (failures, notes) = PodCanary.pinGate(adapterDir(), ClaudeAdapterPin.VERSION)
    assertEquals(emptyList<String>(), failures)
    assertEquals(3, notes.size)
  }

  @Test
  fun `pin gate trips on a drifted package json`() {
    val (failures, _) = PodCanary.pinGate(adapterDir(declared = "0.62.0"), ClaudeAdapterPin.VERSION)
    assertEquals(1, failures.size)
    assertTrue(failures[0], failures[0].contains("package.json declares") && failures[0].contains("0.62.0"))
  }

  @Test
  fun `pin gate trips on a missing lockfile`() {
    val (failures, _) = PodCanary.pinGate(adapterDir(locked = null), ClaudeAdapterPin.VERSION)
    assertEquals(1, failures.size)
    assertTrue(failures[0], failures[0].contains("package-lock.json missing"))
  }

  @Test
  fun `pin gate trips on an absent install with the exact remedy verb`() {
    val (failures, _) = PodCanary.pinGate(adapterDir(installed = null), ClaudeAdapterPin.VERSION)
    assertEquals(1, failures.size)
    assertTrue(failures[0], failures[0].contains("not installed") && failures[0].contains("npm") && failures[0].contains("ci --ignore-scripts"))
  }

  @Test
  fun `pin gate trips on a drifted installed tree`() {
    val (failures, _) = PodCanary.pinGate(adapterDir(installed = "0.64.0"), ClaudeAdapterPin.VERSION)
    assertEquals(1, failures.size)
    assertTrue(failures[0], failures[0].contains("installed adapter is") && failures[0].contains("0.64.0"))
  }

  private companion object {
    const val PIPE_BUF = 1 shl 16
  }
}
