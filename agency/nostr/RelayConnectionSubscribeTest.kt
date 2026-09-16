package com.geekinasuit.agency.nostr

import java.time.Duration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The subscription transport (step 3b-2): subscribe() sends a REQ, its EVENT/EOSE/CLOSED arrive
 * through receive(), and closeSubscription() sends a CLOSE. Native-free like [RelayConnectionTest] —
 * subscribe frames and sends, and the events it delivers are structural literals the transport never
 * verifies (verify() is a separate trust step the fold makes, not receive()), so no crypto native.
 *
 * The heart of this file is the A4-3 HOSTILE-RELAY MATRIX. A fully compromised relay can WITHHOLD,
 * REORDER, DELAY, or REPLAY events; it cannot forge (no key). The transport's contract is to be a
 * FAITHFUL PIPE — deliver exactly what the relay sent, in the order it sent it, adding no dedup, no
 * reordering, and no freshness window of its own. That is what makes the substrate hostile-relay
 * tolerant BY CONSTRUCTION: dedup is the single-use nonce's job and ordering/causality is the
 * journal's (both the mechanical layer, not here), so this layer must not paper over any of the four
 * with a false guarantee. These cells assert client DELIVERY, not fold outcomes — no fold is wired
 * at this layer.
 *
 * A [FakeRelay] is a controllable test double, NOT a real relay: it agrees with the test author's
 * reading of NIP-01 and cannot model a real relay's timing or behaviour (that is the step-5
 * on-device cell). It exists here precisely because full control over what bytes arrive, and in what
 * order, IS the point of an adversarial matrix.
 */
class RelayConnectionSubscribeTest {
  private val key = "0000000000000000000000000000000000000000000000000000000000000003"

  private fun config(url: String) = RelayConfig(relayUrl = url, leadSecretKeyHex = key)

  // A structurally-valid event with a caller-chosen id and created_at, built WITHOUT signing (like
  // RelayConnectionTest's testEvent). The transport delivers events; it never verifies them.
  private fun testEvent(id: String, createdAt: Long = 1_700_000_000L) =
    NostrEvent(
      id = id,
      pubkey = "00".repeat(32),
      createdAt = createdAt,
      kind = 1,
      tags = emptyList(),
      content = "hello",
      sig = "00".repeat(64),
    )

  private val oneFilter = listOf(NostrFilter(kinds = listOf(1)))

  // ---- subscribe / closeSubscription: framing and the round-trip ----

  @Test
  fun `subscribe sends a REQ and its EVENT then EOSE arrive through receive`() {
    FakeRelay().use { relay ->
      val event = testEvent("aa".repeat(32))
      relay.serve { session ->
        val req = session.nextClientText(3_000) ?: error("no REQ from client")
        assertTrue("expected a REQ frame, got $req", req.startsWith("[\"REQ\",\"sub-approvals\","))
        assertTrue("the REQ must carry the filter", req.contains("\"kinds\":[30078]"))
        session.sendText(eventFrame("sub-approvals", event))
        session.sendText(eoseFrame("sub-approvals"))
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      assertEquals(
        SubscribeResult.Sent,
        conn.subscribe("sub-approvals", listOf(NostrFilter(kinds = listOf(30078))), Duration.ofSeconds(3)),
      )
      val first = conn.receive(Duration.ofSeconds(3))
      assertTrue("expected an EVENT, got $first", first is RelayMessage.Event)
      assertEquals("sub-approvals", (first as RelayMessage.Event).subscriptionId)
      assertEquals(event, first.event)
      assertEquals(RelayMessage.Eose("sub-approvals"), conn.receive(Duration.ofSeconds(3)))
      relay.assertScriptClean()
      conn.close()
    }
  }

  @Test
  fun `closeSubscription sends a CLOSE the relay receives`() {
    FakeRelay().use { relay ->
      relay.serve { session ->
        session.nextClientText(3_000) ?: error("no REQ from client")
        val close = session.nextClientText(3_000) ?: error("no CLOSE from client")
        assertEquals("[\"CLOSE\",\"s\"]", close)
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      assertEquals(SubscribeResult.Sent, conn.subscribe("s", oneFilter, Duration.ofSeconds(3)))
      assertEquals(SubscribeResult.Sent, conn.closeSubscription("s", Duration.ofSeconds(3)))
      relay.assertScriptClean()
      conn.close()
    }
  }

  @Test
  fun `subscribe surfaces a relay CLOSED through receive, not as a fault`() {
    FakeRelay().use { relay ->
      // A4-3: a relay may REFUSE or DROP a subscription with CLOSED. That is data the caller reacts
      // to (re-subscribe, back off, journal), surfaced through the same feed as EVENT/EOSE — not a
      // transport fault. The client neither hides it nor treats it as a broken connection.
      relay.serve { session ->
        session.nextClientText(3_000) ?: error("no REQ from client")
        session.sendText(closedFrame("s", "auth-required: cannot serve"))
        Thread.sleep(1_000) // hold the socket open so !hasFailed() means "not a fault", not "not yet closed"
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      assertEquals(SubscribeResult.Sent, conn.subscribe("s", oneFilter, Duration.ofSeconds(3)))
      assertEquals(
        RelayMessage.Closed("s", "auth-required: cannot serve"),
        conn.receive(Duration.ofSeconds(3)),
      )
      assertTrue("a CLOSED is data, not a fault", !conn.hasFailed())
      relay.assertScriptClean()
      conn.close()
    }
  }

  // ---- subscribe / closeSubscription: caller-error and fail-closed guards ----

  @Test
  fun `subscribe rejects an empty or over-long subscription id`() {
    val conn = RelayConnection(config("ws://127.0.0.1:1"))
    for (bad in listOf("", "x".repeat(65))) {
      try {
        conn.subscribe(bad, oneFilter, Duration.ofSeconds(1))
        throw AssertionError("expected IllegalArgumentException for a ${bad.length}-char subscription id")
      } catch (e: IllegalArgumentException) {
        assertTrue(e.message!!.contains("subscription id"))
      }
    }
  }

  @Test
  fun `subscribe requires at least one filter`() {
    val conn = RelayConnection(config("ws://127.0.0.1:1"))
    try {
      conn.subscribe("s", emptyList(), Duration.ofSeconds(1))
      throw AssertionError("expected IllegalArgumentException for no filters")
    } catch (e: IllegalArgumentException) {
      assertTrue(e.message!!.contains("filter"))
    }
  }

  @Test
  fun `subscribe fails closed when not connected, never throws`() {
    val conn = RelayConnection(config("ws://127.0.0.1:1"))
    val result = conn.subscribe("s", oneFilter, Duration.ofSeconds(1))
    assertTrue("expected Failed, got $result", result is SubscribeResult.Failed)
    assertTrue((result as SubscribeResult.Failed).detail.contains("not connected"))
  }

  // ---- A4-3 hostile-relay matrix: the transport is a faithful pipe ----

  @Test
  fun `subscribe delivers events in the relay's wire order, never reordered by created_at`() {
    FakeRelay().use { relay ->
      // `late` has a LATER created_at than `early`; a client that (wrongly) sorted by created_at
      // would deliver `early` first. The relay sends `late` FIRST, then `early`; the client must
      // deliver them in that wire order — created_at is not a clock (A4-3), neither read nor sorted.
      val early = testEvent("a0".repeat(32), createdAt = 1_000L)
      val late = testEvent("b0".repeat(32), createdAt = 2_000L)
      relay.serve { session ->
        session.nextClientText(3_000) ?: error("no REQ from client")
        session.sendText(eventFrame("s", late)) // later created_at, sent FIRST
        session.sendText(eventFrame("s", early)) // earlier created_at, sent SECOND
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      assertEquals(SubscribeResult.Sent, conn.subscribe("s", oneFilter, Duration.ofSeconds(3)))
      assertEquals(late, (conn.receive(Duration.ofSeconds(3)) as RelayMessage.Event).event)
      assertEquals(early, (conn.receive(Duration.ofSeconds(3)) as RelayMessage.Event).event)
      relay.assertScriptClean()
      conn.close()
    }
  }

  @Test
  fun `subscribe delivers a replayed event twice, never dedups`() {
    FakeRelay().use { relay ->
      // A hostile relay sends the same event twice. Dedup is the single-use nonce's job (the
      // mechanical layer), NOT the transport's: both copies must be delivered so the layer that can
      // actually reject a replay sees it. (Contrast a duplicate OK, which IS dropped — an OK is an
      // ack, an EVENT is subscription data.)
      val ev = testEvent("c0".repeat(32))
      relay.serve { session ->
        session.nextClientText(3_000) ?: error("no REQ from client")
        session.sendText(eventFrame("s", ev))
        session.sendText(eventFrame("s", ev))
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      assertEquals(SubscribeResult.Sent, conn.subscribe("s", oneFilter, Duration.ofSeconds(3)))
      assertEquals(ev, (conn.receive(Duration.ofSeconds(3)) as RelayMessage.Event).event)
      assertEquals(ev, (conn.receive(Duration.ofSeconds(3)) as RelayMessage.Event).event)
      relay.assertScriptClean()
      conn.close()
    }
  }

  @Test
  fun `subscribe surfaces exactly what the relay sends — a withheld event is not fabricated`() {
    FakeRelay().use { relay ->
      // A4-3: a hostile relay can WITHHOLD an event. The client must surface exactly what arrives and
      // never invent the missing one. NON-VACUOUS by a CONTROL: the relay sends `delivered` and
      // withholds a second event on the SAME live subscription — `delivered` arriving proves the pipe
      // was live and the relay COULD have sent more, so the absence that follows is the relay's choice
      // faithfully surfaced, not a dead connection. (A cell that passed on a relay sending nothing at
      // all would be worthless.)
      val delivered = testEvent("d0".repeat(32))
      relay.serve { session ->
        session.nextClientText(3_000) ?: error("no REQ from client")
        session.sendText(eventFrame("s", delivered)) // delivered
        // a second event is WITHHELD — never sent
        Thread.sleep(1_000) // hold the socket open so the next receive() means "nothing", not "closed"
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      assertEquals(SubscribeResult.Sent, conn.subscribe("s", oneFilter, Duration.ofSeconds(3)))
      // The pipe is live: the delivered event arrives.
      assertEquals(delivered, (conn.receive(Duration.ofSeconds(3)) as RelayMessage.Event).event)
      // Nothing is fabricated for the withheld event: a further receive() finds nothing, no fault.
      assertNull(conn.receive(Duration.ofMillis(400)))
      assertTrue("withholding is not a connection fault", !conn.hasFailed())
      relay.assertScriptClean()
      conn.close()
    }
  }

  @Test
  fun `subscribe delivers a late event unchanged — no expiry on delay`() {
    FakeRelay().use { relay ->
      // A4-3: a hostile relay can DELAY delivery arbitrarily. The transport applies no freshness
      // window (2a.4 defines no approval-validity time; created_at is not a clock), so an event
      // delivered after a delay must arrive IDENTICAL to a prompt one. The assertion is event
      // EQUALITY, never wall-clock timing.
      val ev = testEvent("e0".repeat(32))
      relay.serve { session ->
        session.nextClientText(3_000) ?: error("no REQ from client")
        Thread.sleep(600) // deliver late
        session.sendText(eventFrame("s", ev))
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      assertEquals(SubscribeResult.Sent, conn.subscribe("s", oneFilter, Duration.ofSeconds(3)))
      assertEquals(ev, (conn.receive(Duration.ofSeconds(3)) as RelayMessage.Event).event)
      relay.assertScriptClean()
      conn.close()
    }
  }

  @Test
  fun `subscribe delivers an event with an absurd created_at unchanged — carried, never read`() {
    FakeRelay().use { relay ->
      // created_at is CARRIED (it is part of the id preimage) but NEVER READ as a clock (A4-3): the
      // transport does not reject, reorder, or expire on it. An event stamped far in the future, or
      // at the epoch, round-trips through receive() byte-identical, exactly as a present-time one
      // would — a client that treated created_at as a freshness signal would drop or reorder these.
      val future = testEvent("f0".repeat(32), createdAt = 99_999_999_999L)
      val epoch = testEvent("f1".repeat(32), createdAt = 0L)
      relay.serve { session ->
        session.nextClientText(3_000) ?: error("no REQ from client")
        session.sendText(eventFrame("s", future))
        session.sendText(eventFrame("s", epoch))
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(2)))
      assertEquals(SubscribeResult.Sent, conn.subscribe("s", oneFilter, Duration.ofSeconds(3)))
      assertEquals(future, (conn.receive(Duration.ofSeconds(3)) as RelayMessage.Event).event)
      assertEquals(epoch, (conn.receive(Duration.ofSeconds(3)) as RelayMessage.Event).event)
      relay.assertScriptClean()
      conn.close()
    }
  }
}

// Server-to-client frame builders for the relay side of these tests. They live HERE, not on
// FakeRelay: the double is deliberately dependency-free (its BUILD target depends on nothing), and
// framing an EVENT needs :nostr's NostrEvent.serialize(), which this test already links. subId and
// message are test-controlled literals, so plain interpolation is safe — serialize() supplies the
// event object's exact JSON.
private fun eventFrame(subscriptionId: String, event: NostrEvent): String =
  "[\"EVENT\",\"$subscriptionId\"," + event.serialize() + "]"

private fun eoseFrame(subscriptionId: String): String = "[\"EOSE\",\"$subscriptionId\"]"

private fun closedFrame(subscriptionId: String, message: String): String =
  "[\"CLOSED\",\"$subscriptionId\",\"$message\"]"
