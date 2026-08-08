package com.geekinasuit.agency.pod

import com.agentclientprotocol.model.ContentBlock
import com.agentclientprotocol.model.SessionUpdate
import java.io.File
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Deterministic battery for [AcpClient] against [FakeAcpAgent]: both ends of
 * an in-process pipe run the pinned SDK's protocol machinery, so these cells exercise real
 * NDJSON wire framing — while honestly covering OUR HANDLING OF OUR MODEL of acp
 * (the wire itself is the canary's job).
 *
 * The red paths pinned here are the protocol-level half of the client contract: rp →
 * approve/deny, the ask DEADLINE failing closed, a decider crash failing closed, an
 * interrupt-SWALLOWING decider still failing closed on our clock (the detached-async
 * shape), the adversarial no-reject menu resolving as Cancelled (never a defaulted
 * allow), the two-allow menu resolving as Cancelled (ambiguity refusal — the agent cannot
 * steer WHICH allow wins by menu order), the NON-ASKING profile leaving askCount at 0
 * (the preflight's observable), the DELAYED-BYPASS profile passing that observable by
 * construction (why gate release must be structurally impossible — the engine/daemon half
 * of that claim lives with the engine), the stalled turn dying on OUR clock with a
 * BOUNDED overshoot, a dead agent failing calls fast (dead-on-arrival AND death mid-turn
 * — a corpse is distinguishable from a stall), wire garbage not wedging the client, wire
 * ABUSE (overlong line, cumulative flood) poisoning the transport fail-closed instead of
 * OOMing the lead, a concurrent call refused fast (single-caller ENFORCED), and shutdown
 * reaping the owned executors. Process-level red paths (kill/re-spawn, process groups,
 * restart backoff) belong to the engine's tests.
 */
class AcpClientTest {

  private companion object {
    const val CALL_TIMEOUT_MS = 20_000L
    const val PIPE_BUF = 1 shl 16
  }

  /** Two half-duplex pipes with the fake agent on one side and the client under test on
   * the other. [toClient] is exposed so a cell can inject raw bytes into the client's
   * inbound stream (wire-garbage path). */
  private class Rig(
    variant: FakeAgentVariant,
    decider: PermissionDecider,
    askDeadlineMs: Long = 10_000,
    maxLineChars: Int = 1 shl 20,
    maxTotalChars: Long = 256L shl 20,
  ) : AutoCloseable {
    private val toAgent = PipedOutputStream()
    val toClient = PipedOutputStream()
    val asks = CopyOnWriteArrayList<PermissionAsk>()
    val agent = FakeAcpAgent(variant, PipedInputStream(toAgent, PIPE_BUF), toClient)
    val client =
      AcpClient(
        agentStdout = PipedInputStream(toClient, PIPE_BUF),
        agentStdin = toAgent,
        decider = { ask ->
          asks += ask
          decider.decide(ask)
        },
        askDeadlineMs = askDeadlineMs,
        maxLineChars = maxLineChars,
        maxTotalChars = maxTotalChars,
      )
    lateinit var handshake: AcpClient.Handshake

    /** initialize + session/new; returns the session id. */
    fun start(): String {
      handshake = client.initialize(CALL_TIMEOUT_MS)
      return client.newSession(File(workdir()), CALL_TIMEOUT_MS)
    }

    private fun workdir(): String =
      System.getenv("TEST_TMPDIR") ?: System.getProperty("java.io.tmpdir")

    override fun close() {
      client.close()
      agent.close()
    }
  }

  private val allow = PermissionDecider { PermissionDecision.AllowOnce }
  private val deny = PermissionDecider { PermissionDecision.RejectOnce }
  private val neverConsulted = PermissionDecider {
    throw AssertionError("decider must not be consulted by this variant")
  }

  /** Renders a turn's updates to compact strings so a single assertEquals pins CONTENT and
   * ORDER at once — an ordering regression cannot pass. */
  private fun render(r: TurnResult): List<String> =
    r.updates.map { u ->
      when (u) {
        is SessionUpdate.AgentMessageChunk -> "say:${(u.content as ContentBlock.Text).text}"
        is SessionUpdate.ToolCall -> "tool-call:${u.toolCallId.value}:${u.kind?.name}:${u.status?.name}"
        is SessionUpdate.ToolCallUpdate -> "tool-update:${u.toolCallId.value}:${u.status?.name}"
        else -> "other:${u::class.simpleName}"
      }
    }

  private val honestApproved =
    listOf(
      "tool-call:tc-0:EXECUTE:PENDING",
      "say:perm-outcome:selected:opt-allow",
      "tool-update:tc-0:COMPLETED",
      "say:tool-effect:ran",
    )

  private val honestRejected =
    listOf(
      "tool-call:tc-0:EXECUTE:PENDING",
      "say:perm-outcome:selected:opt-reject",
      "tool-update:tc-0:FAILED",
      "say:tool-effect:withheld",
    )

  @Test
  fun honestTurnRoutesTheAskAndCapturesUpdatesInOrder() {
    Rig(FakeAgentVariant.HONEST, allow).use { rig ->
      val sid = rig.start()
      // Handshake surfaces agent identity (the canary's version-pin gate builds on this:
      // the fake self-reports version = variant name).
      assertEquals("fake-acp-agent", rig.handshake.agentName)
      assertEquals("HONEST", rig.handshake.agentVersion)
      assertFalse(rig.handshake.loadSession)

      val turn = rig.client.prompt(sid, "do the task", CALL_TIMEOUT_MS)

      assertEquals("END_TURN", turn.stopReason)
      assertEquals(honestApproved, render(turn))
      assertEquals(1, rig.client.askCount.get())
      // The surfaced ask is OUR narrow model of the rp — identity + kind + menu kinds —
      // attributed to the REAL asking session, not a placeholder.
      val ask = rig.asks.single()
      assertEquals(sid, ask.sessionId)
      assertEquals("tc-0", ask.toolCallId)
      assertEquals("write artifact", ask.title)
      assertEquals("EXECUTE", ask.toolKind)
      assertEquals(listOf("ALLOW_ONCE", "REJECT_ONCE"), ask.optionKinds)
    }
  }

  @Test
  fun sessionNewCarriesTheLeadOwnedMetaVerbatimToTheAgent() {
    // The `_meta` configuration channel: what the lead sends on session/new is
    // exactly what the AGENT half receives — asserted against the fake's capture of the
    // SDK-parsed parameters, so the claim covers the real wire framing, not a mock.
    Rig(FakeAgentVariant.HONEST, allow).use { rig ->
      rig.client.initialize(CALL_TIMEOUT_MS)
      val meta =
        buildJsonObject {
          putJsonObject("claudeCode") {
            putJsonObject("options") {
              putJsonArray("settingSources") {}
              put("model", "m")
              put("maxTurns", 3)
            }
          }
        }
      val cwd = File(System.getenv("TEST_TMPDIR") ?: System.getProperty("java.io.tmpdir"))
      rig.client.newSession(cwd, CALL_TIMEOUT_MS, meta)
      assertEquals(meta, rig.agent.capturedSessionParams.single()._meta)
    }
  }

  @Test
  fun sessionNewWithoutMetaSendsNone() {
    Rig(FakeAgentVariant.HONEST, allow).use { rig ->
      rig.start()
      assertEquals(null, rig.agent.capturedSessionParams.single()._meta)
    }
  }

  @Test
  fun denyDecisionSelectsTheRejectOptionAndTheEffectIsWithheld() {
    Rig(FakeAgentVariant.HONEST, deny).use { rig ->
      val sid = rig.start()
      val turn = rig.client.prompt(sid, "do the task", CALL_TIMEOUT_MS)
      assertEquals(honestRejected, render(turn))
      assertEquals(1, rig.client.askCount.get())
    }
  }

  @Test
  fun unansweredAskFailsClosedAsRejectAtTheDeadline() {
    // The decider parks forever — a gate that never answers. The ask deadline (ours, not
    // the agent's) must resolve the rp as a REJECTION and let the turn complete; without
    // it this cell would hang to the prompt timeout instead of finishing rejected.
    val never = CountDownLatch(1)
    try {
      val parked = PermissionDecider {
        never.await()
        PermissionDecision.AllowOnce // unreachable until cleanup; must NOT be the outcome
      }
      Rig(FakeAgentVariant.HONEST, parked, askDeadlineMs = 300).use { rig ->
        val sid = rig.start()
        val turn = rig.client.prompt(sid, "do the task", CALL_TIMEOUT_MS)
        assertEquals(honestRejected, render(turn))
      }
    } finally {
      never.countDown() // unpark the abandoned decider thread
    }
  }

  @Test
  fun deciderCrashFailsClosedAsReject() {
    val crashing = PermissionDecider { throw IllegalStateException("decider blew up") }
    Rig(FakeAgentVariant.HONEST, crashing).use { rig ->
      val sid = rig.start()
      val turn = rig.client.prompt(sid, "do the task", CALL_TIMEOUT_MS)
      assertEquals(honestRejected, render(turn))
    }
  }

  @Test
  fun allowOnlyMenuPlusDenyResolvesAsCancelledNeverADefaultedAllow() {
    // Adversarial menu: the agent offers ONLY allow options. A deny must come back as
    // Cancelled — the client must never "pick the least-bad allow" from a menu the agent
    // controls. The agent's own report proves which outcome crossed the wire.
    Rig(FakeAgentVariant.NO_REJECT_MENU, deny).use { rig ->
      val sid = rig.start()
      val turn = rig.client.prompt(sid, "do the task", CALL_TIMEOUT_MS)
      assertEquals(
        listOf(
          "tool-call:tc-0:EXECUTE:PENDING",
          "say:perm-outcome:cancelled",
          "tool-update:tc-0:FAILED",
          "say:tool-effect:withheld",
        ),
        render(turn),
      )
      assertEquals(listOf("ALLOW_ONCE", "ALLOW_ALWAYS"), rig.asks.single().optionKinds)
    }
  }

  @Test
  fun nonAskingAgentLeavesAskCountAtZero() {
    // The bypass profile: the tool effect happens with no rp on the wire. askCount==0 is
    // the observable the engine's rp-liveness preflight keys on. (The throwing decider is
    // belt-and-suspenders, not the detector: if an ask DID arrive, its throw becomes a
    // fail-closed reject whose perm-outcome evidence would break the update assertion —
    // askCount plus the exact update sequence are what actually catch a routed ask.)
    Rig(FakeAgentVariant.NON_ASKING, neverConsulted).use { rig ->
      val sid = rig.start()
      val turn = rig.client.prompt(sid, "do the task", CALL_TIMEOUT_MS)
      assertEquals(
        listOf("tool-call:tc-0:EXECUTE:COMPLETED", "say:tool-effect:ran-without-asking"),
        render(turn),
      )
      assertEquals(0, rig.client.askCount.get())
    }
  }

  @Test
  fun delayedBypassAsksForTheSentinelThenStopsRouting() {
    // The sharpest red path: turn one asks (so a naive "did it ever ask?" preflight
    // PASSES by construction), then the agent silently stops routing. This cell pins the
    // protocol-level fact; the systemic consequence — a pod must be structurally unable to
    // release a gate NO MATTER what it stops routing — is asserted where the full loop
    // runs (engine/daemon tests).
    Rig(FakeAgentVariant.DELAYED_BYPASS, allow).use { rig ->
      val sid = rig.start()
      val first = rig.client.prompt(sid, "sentinel", CALL_TIMEOUT_MS)
      assertEquals(honestApproved, render(first))
      assertEquals(1, rig.client.askCount.get())

      val second = rig.client.prompt(sid, "real work", CALL_TIMEOUT_MS)
      assertEquals(
        listOf("tool-call:tc-1:EXECUTE:COMPLETED", "say:tool-effect:ran-without-asking"),
        render(second),
      )
      assertEquals(1, rig.client.askCount.get()) // no second ask ever arrived
    }
  }

  @Test
  fun stalledTurnThrowsAcpDeadlineExceededOnOurClock() {
    Rig(FakeAgentVariant.STALL, neverConsulted).use { rig ->
      val sid = rig.start()
      val startNs = System.nanoTime()
      val e =
        assertThrows(AcpDeadlineExceeded::class.java) {
          rig.client.prompt(sid, "do the task", 800)
        }
      val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
      assertTrue("names the operation: ${e.message}", e.message!!.contains("session/prompt"))
      // TIMING is the property under test: the deadline actually elapsed (no instant
      // failure for a wrong reason) and the overshoot is the BOUNDED cancel courtesy plus
      // scheduling slack — never open-ended (a 1s+ SDK default here would read as the
      // agent's clock, not ours).
      assertTrue("fired after ${elapsedMs}ms, before the 800ms deadline", elapsedMs >= 700)
      assertTrue("took ${elapsedMs}ms — overshoot must stay bounded", elapsedMs < 4_000)
      // Pins the CONFIGURED courtesy: the message text is compile-coupled to the same
      // GRACEFUL_CANCEL_MS constant wired into ProtocolOptions, so a change to the value
      // must show up here. The 4s ceiling stays generous on purpose: tightening it enough
      // to catch a regression to the SDK's 1s default (~1.8s nominal here) would trade
      // real CI-flake risk for detecting a minor-latency-only regression — no fail-closed
      // property depends on the courtesy bound.
      assertTrue("names the bounded courtesy: ${e.message}", e.message!!.contains("100ms"))
    }
  }

  @Test
  fun deadAgentFailsCallsFastNotAtFullDeadline() {
    // No agent at all: both agent-side pipe ends are closed before the first call — EOF
    // greets the client immediately. The call must fail AcpCallFailed FAST (the entry
    // guard on a closed transport, or the transport-death watcher cancelling the call
    // job — whichever side of the race lands), never burn the 30s deadline treating
    // the corpse as merely slow.
    val toAgent = PipedOutputStream()
    val agentIn = PipedInputStream(toAgent, PIPE_BUF)
    val toClient = PipedOutputStream()
    val clientIn = PipedInputStream(toClient, PIPE_BUF)
    agentIn.close()
    toClient.close()
    val client = AcpClient(clientIn, toAgent, neverConsulted, askDeadlineMs = 10_000)
    try {
      val startNs = System.nanoTime()
      assertThrows(AcpCallFailed::class.java) { client.initialize(30_000) }
      val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
      assertTrue("failed in ${elapsedMs}ms — must be well under the 30s deadline", elapsedMs < 5_000)
    } finally {
      client.close()
    }
  }

  @Test
  fun agentDeathMidTurnFailsTheTurnFastNotAtFullDeadline() {
    // The stall and the corpse must be DISTINGUISHABLE: a turn already in flight when the
    // agent dies fails via the transport-close hook within moments, instead of stalling
    // to the full 30s deadline as if the agent were alive but slow.
    Rig(FakeAgentVariant.STALL, neverConsulted).use { rig ->
      val sid = rig.start()
      val exec = Executors.newSingleThreadExecutor()
      try {
        val turn = exec.submit<TurnResult> { rig.client.prompt(sid, "do the task", 30_000) }
        // Bounded wait until the turn is provably in flight (the stall chunk arrived).
        val spinDeadlineNs = System.nanoTime() + 5_000_000_000L
        while (rig.client.allUpdates.isEmpty() && System.nanoTime() < spinDeadlineNs) {
          Thread.sleep(10)
        }
        assertTrue("turn never became observable", rig.client.allUpdates.isNotEmpty())
        rig.agent.close() // the agent dies mid-turn
        val startNs = System.nanoTime()
        val e = assertThrows(ExecutionException::class.java) { turn.get(10, TimeUnit.SECONDS) }
        val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
        assertTrue("cause was ${e.cause}", e.cause is AcpCallFailed)
        assertTrue("failed in ${elapsedMs}ms — must be well under the 30s deadline", elapsedMs < 5_000)
      } finally {
        exec.shutdownNow()
      }
    }
  }

  @Test
  fun garbageLineOnTheWireIsSkippedNotFatal() {
    Rig(FakeAgentVariant.HONEST, allow).use { rig ->
      val sid = rig.start()
      // The agent is quiescent between the session/new response and the next request, so
      // the test thread can interleave a raw non-JSON line into the client's inbound pipe.
      rig.toClient.write("this is not a json-rpc frame\n".toByteArray(Charsets.UTF_8))
      rig.toClient.flush()
      val turn = rig.client.prompt(sid, "do the task", CALL_TIMEOUT_MS)
      assertEquals("END_TURN", turn.stopReason)
      assertEquals(honestApproved, render(turn))
    }
  }

  @Test
  fun closeReapsTheOwnedExecutorsAndIsIdempotent() {
    val rig = Rig(FakeAgentVariant.HONEST, allow)
    rig.start()
    rig.client.close()
    assertTrue(rig.client.supervisorTerminated())
    rig.client.close() // second close must be a no-op, not a crash
    rig.agent.close()
  }

  @Test
  fun allowAgainstTwoAllowMenuResolvesAsCancelledAmbiguityRefused() {
    // Adversarial menu, allow edition: TWO ALLOW_ONCE options, broad listed first — an
    // agent steering WHICH allow wins by menu order. Even an explicit AllowOnce decision
    // must refuse to guess between agent-ordered allows: Cancelled, effect withheld. A
    // naive firstOrNull(ALLOW_ONCE) pick would run the broad one.
    Rig(FakeAgentVariant.TWO_ALLOW_MENU, allow).use { rig ->
      val sid = rig.start()
      val turn = rig.client.prompt(sid, "do the task", CALL_TIMEOUT_MS)
      assertEquals(
        listOf(
          "tool-call:tc-0:EXECUTE:PENDING",
          "say:perm-outcome:cancelled",
          "tool-update:tc-0:FAILED",
          "say:tool-effect:withheld",
        ),
        render(turn),
      )
      assertEquals(listOf("ALLOW_ONCE", "ALLOW_ONCE"), rig.asks.single().optionKinds)
    }
  }

  @Test
  fun interruptSwallowingDeciderStillFailsClosedOnOurClock() {
    // A decider that blocks NON-INTERRUPTIBLY (swallows InterruptedException and
    // re-parks). The old runInterruptible-inside-withTimeout shape would inherit
    // structured concurrency's wait on the child and wedge past the deadline; the
    // detached-async shape must answer the wire as a reject at ~askDeadlineMs on OUR
    // clock regardless, abandoning the stubborn thread.
    val never = CountDownLatch(1)
    try {
      val stubborn = PermissionDecider {
        while (true) {
          try {
            never.await()
            break
          } catch (_: InterruptedException) {
            // swallowed on purpose — the worst-case decider
          }
        }
        PermissionDecision.AllowOnce // late answer; must be discarded, never the outcome
      }
      Rig(FakeAgentVariant.HONEST, stubborn, askDeadlineMs = 300).use { rig ->
        val sid = rig.start()
        val startNs = System.nanoTime()
        val turn = rig.client.prompt(sid, "do the task", CALL_TIMEOUT_MS)
        val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
        assertEquals(honestRejected, render(turn))
        assertTrue("took ${elapsedMs}ms — must not wedge on the stubborn decider", elapsedMs < 5_000)
      }
    } finally {
      never.countDown() // unpark the abandoned decider thread
    }
  }

  @Test
  fun overlongWireLinePoisonsTheTransportFailClosed() {
    // A single newline-free blob past the per-line cap is un-skippable wire abuse (no
    // safe resync) and, uncapped, an OOM primitive against the LEAD. It must poison the
    // transport: the next call (or the in-flight one — race-tolerant either way) fails
    // fast as AcpCallFailed, never a hang and never unbounded buffering.
    Rig(FakeAgentVariant.HONEST, allow, maxLineChars = 4_096).use { rig ->
      val sid = rig.start()
      val blob = ByteArray(8_192) { 'x'.code.toByte() }
      rig.toClient.write(blob)
      rig.toClient.write('\n'.code)
      rig.toClient.flush()
      val startNs = System.nanoTime()
      assertThrows(AcpCallFailed::class.java) { rig.client.prompt(sid, "do the task", 30_000) }
      val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
      assertTrue("failed in ${elapsedMs}ms — must be well under the 30s deadline", elapsedMs < 5_000)
    }
  }

  @Test
  fun wireFloodBeyondTotalCapPoisonsTheTransportFailClosed() {
    // Many small (individually skippable) lines whose SUM passes the cumulative cap: the
    // flood shape of the same OOM primitive. The cap must poison the transport the same
    // fail-closed way.
    Rig(FakeAgentVariant.HONEST, allow, maxTotalChars = 16_384).use { rig ->
      val sid = rig.start()
      val line = "x".repeat(400) + "\n"
      repeat(50) { rig.toClient.write(line.toByteArray(Charsets.UTF_8)) } // 20k > 16_384
      rig.toClient.flush()
      val startNs = System.nanoTime()
      assertThrows(AcpCallFailed::class.java) { rig.client.prompt(sid, "do the task", 30_000) }
      val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
      assertTrue("failed in ${elapsedMs}ms — must be well under the 30s deadline", elapsedMs < 5_000)
    }
  }

  @Test
  fun concurrentCallOnSingleCallerClientIsRefusedFast() {
    // The single-caller contract is ENFORCED, not trusted: with a turn provably in
    // flight, a second call must be refused immediately with AcpCallFailed — not
    // interleave collectors and watchers on the one wire.
    Rig(FakeAgentVariant.STALL, neverConsulted).use { rig ->
      val sid = rig.start()
      val exec = Executors.newSingleThreadExecutor()
      try {
        val turn = exec.submit<TurnResult> { rig.client.prompt(sid, "do the task", 30_000) }
        val spinDeadlineNs = System.nanoTime() + 5_000_000_000L
        while (rig.client.allUpdates.isEmpty() && System.nanoTime() < spinDeadlineNs) {
          Thread.sleep(10)
        }
        assertTrue("turn never became observable", rig.client.allUpdates.isNotEmpty())
        val startNs = System.nanoTime()
        val e =
          assertThrows(AcpCallFailed::class.java) { rig.client.initialize(CALL_TIMEOUT_MS) }
        val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
        assertTrue("names the refusal: ${e.message}", e.message!!.contains("concurrent call"))
        assertTrue("refused in ${elapsedMs}ms — must be immediate", elapsedMs < 1_000)
        assertFalse("stalled turn must still be in flight", turn.isDone)
      } finally {
        exec.shutdownNow()
      }
    }
  }
}
