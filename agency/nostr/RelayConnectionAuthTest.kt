package com.geekinasuit.agency.nostr

import java.time.Duration
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test

/**
 * The NIP-42 auth handshake over the real BIP-340 primitive: the client signs a kind-22242 event
 * with the lead key and the relay verdicts on it. These sign, so — like [NostrWireSignTest] — they
 * need the secp256k1 native at runtime; the native-free structural cells are in
 * [RelayConnectionTest].
 *
 * A [FakeRelay] here proves the client's SIDE of the exchange (it builds and sends a well-formed
 * signed AUTH event, waits for the matching OK, and fails closed otherwise). It cannot prove those
 * bytes satisfy a REAL relay — that is a separate manual real-relay cell, because a fake relay only
 * agrees with the test author's reading of NIP-42.
 *
 * One cell drives a WebSocket double ([webSocketClient]) in place of a [FakeRelay]. It needs the OK
 * to arrive, and the relay's close to follow, before authenticate waits for that OK: an order that
 * a real socket leaves to the scheduler.
 */
class RelayConnectionAuthTest {
  private val key = "0000000000000000000000000000000000000000000000000000000000000003"

  private fun config(url: String) = RelayConfig(relayUrl = url, leadSecretKey = SecretKeyHex.ofHexString(key))

  private fun clientEventId(authFrame: String): String =
    Json.parseToJsonElement(authFrame).jsonArray[1].jsonObject["id"]!!.jsonPrimitive.content

  companion object {
    // Force the secp256k1 native load ONCE, outside any deadline, before the timed cells run. The
    // first sign in a fresh JVM can take seconds under CPU contention, and authenticate() signs
    // between computing its deadline and awaiting the OK, so a cold sign inside a timed cell eats that
    // deadline. Warming here keeps each cell's own sign fast and its deadline meaningful: without it
    // the Authenticated/Refused cells could time out, and the wrong-id cell would get the distinct
    // "deadline elapsed while preparing" detail (RelayConnection classifies a spent budget as that,
    // not "no OK") instead of the "no OK" it asserts. No try/catch: a warm-up failure must fail the
    // class loudly.
    @JvmStatic
    @BeforeClass
    fun warmUpNativeSigning() {
      buildAuthEvent(
        secretKeyHex = "0000000000000000000000000000000000000000000000000000000000000003",
        relayUrl = "ws://warmup.invalid",
        challenge = "warmup",
        createdAt = 0L,
        auxRandHex = "00".repeat(32),
      )
    }
  }

  @Test
  fun `authenticate succeeds when the relay accepts the signed auth event`() {
    FakeRelay().use { relay ->
      relay.serve { session ->
        session.sendText("[\"AUTH\",\"challenge-abc\"]")
        val authFrame = session.nextClientText(3_000) ?: error("no auth frame from client")
        // Echo the client's own event id in the OK, as a real relay does.
        session.sendText("[\"OK\",\"${clientEventId(authFrame)}\",true,\"\"]")
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      assertEquals(AuthResult.Authenticated, conn.authenticate(Duration.ofSeconds(3)))
      relay.assertScriptClean()
      conn.close()
    }
  }

  @Test
  fun `authenticate is Refused when the relay rejects the auth event`() {
    FakeRelay().use { relay ->
      relay.serve { session ->
        session.sendText("[\"AUTH\",\"challenge-abc\"]")
        val authFrame = session.nextClientText(3_000) ?: error("no auth frame from client")
        session.sendText("[\"OK\",\"${clientEventId(authFrame)}\",false,\"auth-required: rejected\"]")
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      val result = conn.authenticate(Duration.ofSeconds(3))
      assertTrue("expected Refused, got $result", result is AuthResult.Refused)
      assertEquals("auth-required: rejected", (result as AuthResult.Refused).message)
      relay.assertScriptClean()
      conn.close()
    }
  }

  @Test
  fun `authenticate fails closed on a challenge holding an unpaired surrogate`() {
    // The challenge is relay-supplied text the client signs into its auth event. The JSON escape for
    // U+D800 parses to a lone surrogate, which has no UTF-8 encoding and so no event id: signing
    // refuses, and authenticate reports that as a classified failure rather than throwing.
    FakeRelay().use { relay ->
      relay.serve { session -> session.sendText("[\"AUTH\",\"a" + "\\" + "ud800b\"]") }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      assertEquals(
        AuthResult.Failed("could not sign auth event: IllegalArgumentException"),
        conn.authenticate(Duration.ofSeconds(3)),
      )
      relay.assertScriptClean()
      conn.close()
    }
  }

  @Test
  fun `authenticate ignores an OK for a different event id and fails closed`() {
    FakeRelay().use { relay ->
      relay.serve { session ->
        session.sendText("[\"AUTH\",\"challenge-abc\"]")
        session.nextClientText(3_000) ?: error("no auth frame from client")
        // An OK (even accepted=true) for an id that is NOT our event's: a relay must not be able to
        // authenticate us by acknowledging someone else's event. We keep waiting, then time out.
        session.sendText("[\"OK\",\"${"d".repeat(64)}\",true,\"\"]")
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      val result = conn.authenticate(Duration.ofMillis(600))
      assertTrue("expected Failed, got $result", result is AuthResult.Failed)
      assertTrue((result as AuthResult.Failed).detail.contains("no OK for our auth event"))
      relay.assertScriptClean()
      conn.close()
    }
  }

  @Test
  fun `authenticate interrupted while it waits for the OK says so and keeps the interrupt set`() {
    // The relay interrupts the client once it waits for the OK, and not while its send is still in
    // flight, where an interrupt is the send's own failure. The client's stack says which wait it is
    // in. No OK is ever sent, so the wait can end only by the interrupt or the deadline. A wait that
    // ran on to the deadline would return the same result, so the call must also come back well
    // inside it.
    val client = Thread.currentThread()
    FakeRelay().use { relay ->
      relay.serve { session ->
        session.sendText("[\"AUTH\",\"challenge-abc\"]")
        session.nextClientText(3_000) ?: error("no auth frame from client")
        check(waitUntil(5_000) { client.stackTrace.any { it.methodName == "pollUntilDeadline" } }) {
          "the client never waited for the OK"
        }
        client.interrupt()
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      val started = System.nanoTime()
      val result = conn.authenticate(Duration.ofSeconds(10))
      val millis = (System.nanoTime() - started) / 1_000_000
      // Thread.interrupted() reads the status and clears it, so no later cell runs interrupted.
      val stillInterrupted = Thread.interrupted()
      assertEquals(AuthResult.Failed("interrupted while awaiting OK for our auth event"), result)
      assertTrue("the interrupt is still set when authenticate returns", stillInterrupted)
      assertTrue("came back after $millis ms, not well inside its 10 s deadline", millis < 5_000)
      relay.assertScriptClean()
      conn.close()
    }
  }

  @Test
  fun `authenticate on a connection that failed after its OK arrived fails, not Authenticated`() {
    // The double delivers the challenge as the socket is built, so it waits in the inbound queue for
    // authenticate. Inside the send, the double hands the listener an accepting OK for the auth
    // event, which waits in authenticate's ack slot, and then reports the relay's close. The
    // connection has failed before authenticate waits for the OK, so that wait ends on the fault
    // without taking the buffered OK, and authenticate never says Authenticated.
    val conn =
      RelayConnection(
        config("ws://127.0.0.1:1"),
        webSocketClient { listener ->
          OkThenCloseOnSendWebSocket(listener, ::clientEventId).also {
            listener.onText(it, "[\"AUTH\",\"challenge-abc\"]", true)
          }
        },
      )
    assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
    assertEquals(
      AuthResult.Failed("connection failed: relay closed: 1000 'bye'"),
      conn.authenticate(Duration.ofSeconds(3)),
    )
    conn.close()
  }
}
