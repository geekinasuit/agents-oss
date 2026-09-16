package com.geekinasuit.agency.nostr

import java.net.ServerSocket
import java.time.Duration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The transport's structural cells, native-free: connect-failure classification, fragment
 * reassembly, that an un-answered relay leaves auth fail-closed, that the stream survives a relay
 * ping, and the three ingress bounds (size, JSON-nesting depth, queued-message count). None of
 * these sign, so like [NostrWireTest] this needs no secp256k1 native. The NIP-42 auth paths that
 * do sign are in [RelayConnectionAuthTest].
 *
 * A [FakeRelay] is a controllable test double, NOT a real relay — it proves framing and bounds
 * behaviour, never that our NIP-42 bytes satisfy a real relay (that is the manual real-relay cell).
 */
class RelayConnectionTest {
  private val key = "0000000000000000000000000000000000000000000000000000000000000003"

  private fun config(url: String) = RelayConfig(relayUrl = url, leadSecretKeyHex = key)

  private fun waitUntil(timeoutMillis: Long, cond: () -> Boolean): Boolean {
    val deadline = System.currentTimeMillis() + timeoutMillis
    while (System.currentTimeMillis() < deadline) {
      if (cond()) return true
      Thread.sleep(20)
    }
    return cond()
  }

  @Test
  fun `RelayConfig rejects a non-websocket URL`() {
    try {
      RelayConfig("https://relay.example.com", key)
      throw AssertionError("expected an IllegalArgumentException for a non-ws URL")
    } catch (e: IllegalArgumentException) {
      assertTrue(e.message!!.contains("ws://"))
    }
  }

  @Test
  fun `RelayConfig rejects a malformed secret key`() {
    try {
      RelayConfig("wss://relay.example.com", "abc")
      throw AssertionError("expected an IllegalArgumentException for a short key")
    } catch (e: IllegalArgumentException) {
      assertTrue(e.message!!.contains("64 hex"))
    }
  }

  @Test
  fun `connect to a closed port classifies as REFUSED, never throws`() {
    // Bind then release a port so nothing is listening on it: a connect there is refused.
    val probe = ServerSocket(0)
    val port = probe.localPort
    probe.close()
    val result = RelayConnection(config("ws://127.0.0.1:$port")).connect(Duration.ofSeconds(2))
    assertTrue("expected Failed, got $result", result is ConnectResult.Failed)
    assertEquals(ConnectFailure.REFUSED, (result as ConnectResult.Failed).failure)
  }

  @Test
  fun `connect to a server that never completes the handshake classifies as TIMEOUT`() {
    // A raw server that accepts the socket but never sends the 101 upgrade: the WebSocket handshake
    // never completes, so the connect deadline fires.
    ServerSocket(0).use { silent ->
      val accepter =
        Thread {
          try {
            silent.accept()
            Thread.sleep(5_000)
          } catch (_: Exception) {}
        }
      accepter.isDaemon = true
      accepter.start()
      val result =
        RelayConnection(config("ws://127.0.0.1:${silent.localPort}")).connect(Duration.ofMillis(400))
      assertTrue("expected Failed, got $result", result is ConnectResult.Failed)
      assertEquals(ConnectFailure.TIMEOUT, (result as ConnectResult.Failed).failure)
    }
  }

  @Test
  fun `connect to an unresolvable host fails closed, never throws`() {
    // .invalid never resolves (RFC 6761). Classification is DNS-environment-dependent (UNKNOWN_HOST
    // on a clean resolver), so assert only the contract that matters: a Failed, never a throw and
    // never a Connected.
    val result = RelayConnection(config("ws://nonexistent.invalid")).connect(Duration.ofSeconds(3))
    assertTrue("expected Failed, got $result", result is ConnectResult.Failed)
  }

  @Test
  fun `a fragmented relay message is reassembled before parsing`() {
    FakeRelay().use { relay ->
      // One logical ["NOTICE","hello"] split mid-string across two frames. Without accumulation the
      // first fragment would reach the parser as junk and the message would be lost.
      relay.serve { it.sendTextFragments(listOf("[\"NOTICE\",\"hel", "lo\"]")) }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      val message = conn.receive(Duration.ofSeconds(2))
      assertEquals(RelayMessage.Notice("hello"), message)
      conn.close()
    }
  }

  @Test
  fun `the stream survives a relay ping between messages`() {
    FakeRelay().use { relay ->
      // Locks in the empirical finding (ws-probe2): the JDK default onPing replenishes demand and
      // auto-pongs, so a ping does not deafen the connection. Both notices must arrive.
      relay.serve {
        it.sendText("[\"NOTICE\",\"one\"]")
        it.sendPing("keepalive".toByteArray())
        it.sendText("[\"NOTICE\",\"two\"]")
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      assertEquals(RelayMessage.Notice("one"), conn.receive(Duration.ofSeconds(2)))
      assertEquals(RelayMessage.Notice("two"), conn.receive(Duration.ofSeconds(2)))
      conn.close()
    }
  }

  @Test
  fun `authenticate fails closed when the relay sends no challenge`() {
    FakeRelay().use { relay ->
      relay.serve { Thread.sleep(3_000) } // connected, but silent: no AUTH challenge ever
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      val result = conn.authenticate(Duration.ofMillis(400))
      assertTrue("expected Failed, got $result", result is AuthResult.Failed)
      assertTrue((result as AuthResult.Failed).detail.contains("no AUTH challenge"))
      conn.close()
    }
  }

  @Test
  fun `the SIZE bound closes the connection on an oversized accumulated message`() {
    FakeRelay().use { relay ->
      // ONE logical message in 12 fragments of 100_000 chars (only the last is final). The
      // accumulator sums them and must breach around the 11th fragment (>1 MiB) rather than buffer
      // without limit — the breach arrives before any final frame, which is exactly the case a
      // per-frame cap would miss.
      relay.serve { session ->
        try {
          val chunk = "a".repeat(100_000)
          session.sendTextFragments(List(12) { chunk })
        } catch (_: Exception) {} // the client aborts on breach; the remaining sends fail, expected
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      assertTrue(
        "connection should have failed on the size bound",
        waitUntil(5_000) { conn.hasFailed() },
      )
      // "characters", not "exceeded": all three bound breaches say "exceeded", so only the char unit
      // distinguishes the SIZE bound from the DEPTH ("openers") and COUNT ("unconsumed") breaches.
      assertTrue(conn.failureReason()!!.contains("characters"))
      conn.close()
    }
  }

  @Test
  fun `the DEPTH bound closes the connection on excessive JSON nesting`() {
    FakeRelay().use { relay ->
      // One opener past MAX_JSON_OPENERS, but tiny in bytes: the size cap cannot catch this, so the
      // opener-count guard is what rejects it — before the parser runs, and independent of whether
      // the parser could itself have handled a frame this shallow (at MAX+1 it could; the guard fires
      // regardless). The separate, load-bearing fact — that MAX_JSON_OPENERS itself parses safely —
      // is what the ceiling-depth test below proves.
      val deep = "[".repeat(RelayConnection.MAX_JSON_OPENERS + 1) + "]".repeat(RelayConnection.MAX_JSON_OPENERS + 1)
      relay.serve { session ->
        try {
          session.sendText(deep)
        } catch (_: Exception) {}
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      assertTrue(
        "connection should have failed on the depth bound",
        waitUntil(5_000) { conn.hasFailed() },
      )
      assertTrue(conn.failureReason()!!.contains("openers"))
      conn.close()
    }
  }

  @Test
  fun `a message nested to the opener ceiling is parsed safely on the listener thread`() {
    FakeRelay().use { relay ->
      // The load-bearing proof that MAX_JSON_OPENERS sits BELOW the parser's StackOverflow floor on
      // the actual listener thread — not a standalone measurement that can rot, but a property CI
      // re-checks every run. A frame with EXACTLY MAX_JSON_OPENERS openers passes the guard (which
      // breaches only ABOVE the ceiling) and reaches kotlinx's recursive parser on the JDK
      // WebSocket's own executor thread — the very thread the guard protects. If that parse
      // overflowed, the JDK routes the Error to onError, the connection fails, and the trailing
      // NOTICE never arrives; the NOTICE arriving is the evidence that the ceiling-depth parse
      // survived on that thread. (The deep frame itself parses to a nested array whose first element
      // is not a string tag, so parseRelayMessage returns null and it is dropped — no breach.)
      val atCeiling =
        "[".repeat(RelayConnection.MAX_JSON_OPENERS) + "]".repeat(RelayConnection.MAX_JSON_OPENERS)
      relay.serve { session ->
        session.sendText(atCeiling)
        session.sendText("[\"NOTICE\",\"alive\"]")
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      assertEquals(RelayMessage.Notice("alive"), conn.receive(Duration.ofSeconds(3)))
      assertTrue("connection must survive a ceiling-depth parse on the listener thread", !conn.hasFailed())
      conn.close()
    }
  }

  @Test
  fun `the COUNT bound closes the connection on a flood of unconsumed messages`() {
    FakeRelay().use { relay ->
      // More complete messages than the queue holds, with no draining on this side: the listener
      // must not block (it offers, never puts), and a flood past the bound is treated as abuse.
      relay.serve { session ->
        try {
          repeat(RelayConnection.MAX_QUEUED_MESSAGES + 5) { session.sendText("[\"NOTICE\",\"x\"]") }
        } catch (_: Exception) {} // the client aborts on breach; the remaining sends fail, expected
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      // Deliberately do NOT drain: the queue fills and the offer for message 1025 breaches.
      assertTrue(
        "connection should have failed on the queue-count bound",
        waitUntil(5_000) { conn.hasFailed() },
      )
      // The reason is DETERMINISTICALLY the count breach, not a "relay closed" — this is an ordering
      // guarantee, not a timing one, which is why a single fast sample is trustworthy. breach()
      // records the reason BEFORE it aborts the socket, `failure` is a first-writer-wins
      // AtomicReference, and the FakeRelay holds the socket open until this use-block's close() runs
      // (after this assertion). So no onClose/onError can beat the breach to the slot.
      assertTrue(conn.failureReason()!!.contains("unconsumed"))
      conn.close()
    }
  }
}
