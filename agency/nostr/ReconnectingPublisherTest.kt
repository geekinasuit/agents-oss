package com.geekinasuit.agency.nostr

import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test

/**
 * [ReconnectingPublisher] against [FakeRelay]s: when it replaces its connection, that it sends no
 * event twice, what it reports when it cannot connect or authenticate, that
 * [ReconnectingPublisher.close] waits for a publish in progress, and [RelayNotifier]'s fan-out over
 * it. A [FakeRelay] accepts one connection per [FakeRelay.serve], so a cell that
 * expects a reconnect gives the factory a second relay, or serves the same relay again once the
 * first connection has ended.
 *
 * Some cells sign (the NIP-42 handshake, and the notifier's gift wraps), so the class needs the
 * secp256k1 native at runtime, like [RelayConnectionAuthTest].
 */
class ReconnectingPublisherTest {
  private val key = "0000000000000000000000000000000000000000000000000000000000000003"
  // A connect to a local relay can take seconds when the machine is loaded, and no cell waits for a
  // connect to time out: the failed connect is refused at once.
  private val connectTimeout = Duration.ofSeconds(10)
  private val authTimeout = Duration.ofSeconds(3)
  private val publishTimeout = Duration.ofSeconds(3)

  // One level past the depth bound: a relay that sends this breaches the connection.
  private val overDeep =
    "[".repeat(RelayConnection.MAX_JSON_DEPTH + 1) + "]".repeat(RelayConnection.MAX_JSON_DEPTH + 1)

  companion object {
    // What a relay script records when the client closes the connection without sending a frame.
    // Such a read waits 10 s, longer than the cell's 5 s poll for it, so a frame sent late is still
    // seen, and a client that never closes fails the poll rather than passing on the read's timeout.
    private const val NOTHING = "<nothing>"

    // Load the secp256k1 native once, before the cells that sign inside a deadline, as
    // RelayConnectionAuthTest does: a cold load can take seconds under contention.
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

  /** Builds each connection to the next of [urls], around its own config and key, and keeps both so
   * a cell can check what the publisher did with them. */
  private inner class Connections(private vararg val urls: String) {
    val configs = mutableListOf<RelayConfig>()
    val opened = mutableListOf<RelayConnection>()

    fun next(): RelayConnection {
      val config = RelayConfig(urls[configs.size], SecretKeyHex.ofHexString(key))
      configs += config
      return RelayConnection(config).also { opened += it }
    }
  }

  private fun publisher(connections: Connections, auth: RelayAuth) =
    ReconnectingPublisher(connections::next, connectTimeout, auth)

  /** An event the transport carries without checking it. [n] sets its id, which an OK must echo. */
  private fun event(n: Int) =
    NostrEvent(
      id = "%064x".format(n),
      pubkey = "00".repeat(32),
      createdAt = 1_700_000_000L,
      kind = 1059,
      tags = emptyList(),
      content = "",
      sig = "00".repeat(64),
    )

  private fun zeroed(config: RelayConfig) = config.leadSecretKey.hexChars.all { it == Char(0) }

  private fun clientEventId(frame: String): String =
    Json.parseToJsonElement(frame).jsonArray[1].jsonObject["id"]!!.jsonPrimitive.content

  /** Read the client's next frame, check that it is the EVENT for [expected], and answer it. */
  private fun answer(
    session: FakeRelay.Session,
    expected: NostrEvent,
    accepted: Boolean,
    message: String = "",
  ) {
    val frame = session.nextClientText(3_000) ?: error("no EVENT from the client")
    check(frame.startsWith("[\"EVENT\"") && clientEventId(frame) == expected.id) {
      "expected the EVENT for ${expected.id}, got $frame"
    }
    session.sendText("[\"OK\",\"${expected.id}\",$accepted,\"$message\"]")
  }

  /** Challenge the client, check that its next frame is an AUTH, and accept it. */
  private fun acceptAuth(session: FakeRelay.Session) {
    session.sendText("[\"AUTH\",\"challenge\"]")
    val frame = session.nextClientText(3_000) ?: error("no AUTH from the client")
    check(frame.startsWith("[\"AUTH\"")) { "expected an AUTH first, got $frame" }
    session.sendText("[\"OK\",\"${clientEventId(frame)}\",true,\"\"]")
  }

  @Test
  fun `a connection breached during a publish is replaced before the next publish`() {
    FakeRelay().use { first ->
      FakeRelay().use { second ->
        // The first relay answers the first event with a frame nested past the depth bound, which
        // breaches the connection while the publish awaits its OK.
        first.serve { session ->
          val frame = session.nextClientText(3_000) ?: error("no EVENT from the client")
          check(clientEventId(frame) == event(1).id) { "expected the first EVENT, got $frame" }
          try {
            session.sendText(overDeep)
          } catch (_: Exception) {} // the client aborts the socket on the breach
        }
        second.serve { session -> answer(session, event(2), accepted = true) }
        val connections = Connections(first.url, second.url)
        val publisher = publisher(connections, RelayAuth.None)

        val failed = publisher.publish(event(1), publishTimeout)
        assertTrue("expected Failed, got $failed", failed is PublishResult.Failed)
        assertTrue((failed as PublishResult.Failed).detail.contains("depth"))
        assertEquals("the failed publish made one connection attempt", 1, connections.configs.size)
        assertEquals(PublishResult.Accepted, publisher.publish(event(2), publishTimeout))
        assertEquals(2, connections.configs.size)
        assertTrue("the replaced connection is closed", zeroed(connections.configs[0]))
        first.assertScriptClean()
        second.assertScriptClean()
        publisher.close()
      }
    }
  }

  @Test
  fun `a connection the relay closes between publishes is replaced before the next publish`() {
    FakeRelay().use { first ->
      FakeRelay().use { second ->
        // The relay closes only once the first publish has returned: a close that came with the OK
        // would end that publish's wait before it took the OK.
        val publishReturned = CountDownLatch(1)
        first.serve { session ->
          answer(session, event(1), accepted = true)
          publishReturned.await(5, TimeUnit.SECONDS)
          session.sendClose() // as a relay that ends an idle connection does
        }
        second.serve { session -> answer(session, event(2), accepted = true) }
        val connections = Connections(first.url, second.url)
        val publisher = publisher(connections, RelayAuth.None)

        assertEquals(PublishResult.Accepted, publisher.publish(event(1), publishTimeout))
        publishReturned.countDown()
        assertTrue(
          "the first connection should record the relay's close",
          waitUntil(5_000) { connections.opened[0].hasFailed() },
        )
        assertEquals(PublishResult.Accepted, publisher.publish(event(2), publishTimeout))
        assertEquals(2, connections.configs.size)
        assertTrue("the replaced connection is closed", zeroed(connections.configs[0]))
        first.assertScriptClean()
        second.assertScriptClean()
        publisher.close()
      }
    }
  }

  @Test
  fun `a publish that gets no verdict replaces the connection before the next publish`() {
    FakeRelay().use { first ->
      FakeRelay().use { second ->
        // The first relay takes the event and never answers, as over a half-open socket: the send
        // succeeds, no OK comes back, and the connection records no fault. The relay then records
        // the client's next frame, and there must be none before the client closes the connection:
        // the event is not sent again on it.
        val seen = LinkedBlockingQueue<String>()
        first.serve { session ->
          session.nextClientText(3_000) ?: error("no EVENT from the client")
          seen.put(session.nextClientText(10_000) ?: NOTHING)
        }
        second.serve { session -> answer(session, event(2), accepted = true) }
        val connections = Connections(first.url, second.url)
        val publisher = publisher(connections, RelayAuth.None)

        val failed = publisher.publish(event(1), Duration.ofMillis(500))
        assertTrue("expected Failed, got $failed", failed is PublishResult.Failed)
        assertTrue((failed as PublishResult.Failed).detail.contains("no OK"))
        assertEquals("the failed publish made one connection attempt", 1, connections.configs.size)
        assertTrue("no fault was recorded", !connections.opened[0].hasFailed())
        assertEquals(NOTHING, seen.poll(5, TimeUnit.SECONDS))
        assertEquals(PublishResult.Accepted, publisher.publish(event(2), publishTimeout))
        assertEquals(2, connections.configs.size)
        assertTrue("the replaced connection is closed", zeroed(connections.configs[0]))
        first.assertScriptClean()
        second.assertScriptClean()
        publisher.close()
      }
    }
  }

  @Test
  fun `a publish that gets a verdict keeps the connection`() {
    FakeRelay().use { relay ->
      relay.serve { session ->
        answer(session, event(1), accepted = true)
        answer(session, event(2), accepted = false, message = "blocked: not today")
        answer(session, event(3), accepted = true)
      }
      val connections = Connections(relay.url)
      val publisher = publisher(connections, RelayAuth.None)

      assertEquals(PublishResult.Accepted, publisher.publish(event(1), publishTimeout))
      assertEquals(
        PublishResult.Rejected("blocked: not today"),
        publisher.publish(event(2), publishTimeout),
      )
      assertEquals(PublishResult.Accepted, publisher.publish(event(3), publishTimeout))
      assertEquals(1, connections.configs.size)
      relay.assertScriptClean()
      publisher.close()
    }
  }

  @Test
  fun `a failed connect is reported and the next publish connects again`() {
    FakeRelay().use { relay ->
      relay.serve { session -> answer(session, event(2), accepted = true) }
      val connections = Connections(REFUSED_URL, relay.url)
      val publisher = publisher(connections, RelayAuth.None)

      val failed = publisher.publish(event(1), publishTimeout)
      assertTrue("expected Failed, got $failed", failed is PublishResult.Failed)
      assertTrue(
        "expected a refusal, got $failed",
        (failed as PublishResult.Failed).detail.startsWith("could not connect: connection refused"),
      )
      assertTrue("the connection that did not connect is closed", zeroed(connections.configs[0]))
      assertEquals(PublishResult.Accepted, publisher.publish(event(2), publishTimeout))
      assertEquals(2, connections.configs.size)
      relay.assertScriptClean()
      publisher.close()
    }
  }

  @Test
  fun `a factory that throws is reported by the exception's class alone`() {
    val publisher =
      ReconnectingPublisher(
        { throw IllegalStateException("key file held 0123abcd") },
        connectTimeout,
        RelayAuth.None,
      )
    assertEquals(
      PublishResult.Failed("could not create a connection: IllegalStateException"),
      publisher.publish(event(1), publishTimeout),
    )
    // Thread.interrupted() clears the status as it reads it, so a failure here reaches no later cell.
    assertFalse("the thread is not interrupted", Thread.interrupted())
    publisher.close()
  }

  @Test
  fun `a factory that throws InterruptedException leaves the thread interrupted`() {
    val publisher = ReconnectingPublisher({ throw InterruptedException() }, connectTimeout, RelayAuth.None)
    try {
      assertEquals(
        PublishResult.Failed("could not create a connection: InterruptedException"),
        publisher.publish(event(1), publishTimeout),
      )
      assertTrue("the thread is interrupted again", Thread.currentThread().isInterrupted)
    } finally {
      // Clear the status, so it does not reach the next cell on this thread.
      Thread.interrupted()
    }
    publisher.close()
  }

  @Test
  fun `a connection that fails to authenticate publishes nothing`() {
    FakeRelay().use { relay ->
      val seen = LinkedBlockingQueue<String>()
      // No AUTH challenge, so authentication times out. The relay then records the client's next
      // frame, and there must be none before the client closes the connection.
      relay.serve { session -> seen.put(session.nextClientText(10_000) ?: NOTHING) }
      val connections = Connections(relay.url)
      val publisher =
        publisher(connections, RelayAuth.Nip42(Duration.ofMillis(400)))

      assertEquals(
        PublishResult.Failed("could not authenticate: no AUTH challenge within deadline"),
        publisher.publish(event(1), publishTimeout),
      )
      assertTrue("the connection is closed", zeroed(connections.configs[0]))
      assertEquals(NOTHING, seen.poll(5, TimeUnit.SECONDS))
      relay.assertScriptClean()
      publisher.close()
    }
  }

  @Test
  fun `a factory that reuses one config fails every reconnect at authentication`() {
    FakeRelay().use { relay ->
      // One config for every connection, so closing the first connection zeroes the key that the
      // next one is built around.
      val shared = RelayConfig(relay.url, SecretKeyHex.ofHexString(key))
      val publisher =
        ReconnectingPublisher(
          { RelayConnection(shared) },
          connectTimeout,
          RelayAuth.Nip42(Duration.ofMillis(400)),
        )
      // The first connection gets no challenge, fails to authenticate, and is closed.
      relay.serve { session -> session.nextClientText(3_000) }
      assertEquals(
        PublishResult.Failed("could not authenticate: no AUTH challenge within deadline"),
        publisher.publish(event(1), publishTimeout),
      )
      assertTrue("closing the first connection zeroes the shared key", zeroed(shared))

      // The second connection is challenged and cannot sign with the zeroed key. It is served only
      // now, so that it cannot take the first connection.
      val seen = LinkedBlockingQueue<String>()
      relay.serve { session ->
        session.sendText("[\"AUTH\",\"challenge\"]")
        seen.put(session.nextClientText(10_000) ?: NOTHING)
      }
      assertEquals(
        PublishResult.Failed(
          "could not authenticate: could not sign auth event: IllegalArgumentException"
        ),
        publisher.publish(event(2), publishTimeout),
      )
      assertEquals(NOTHING, seen.poll(5, TimeUnit.SECONDS))
      relay.assertScriptClean()
      publisher.close()
    }
  }

  @Test
  fun `close closes the connection and refuses every later publish`() {
    FakeRelay().use { relay ->
      val seen = LinkedBlockingQueue<String>()
      relay.serve { session ->
        answer(session, event(1), accepted = true)
        seen.put(session.nextClientText(10_000) ?: NOTHING)
      }
      val connections = Connections(relay.url)
      val publisher = publisher(connections, RelayAuth.None)

      assertEquals(PublishResult.Accepted, publisher.publish(event(1), publishTimeout))
      publisher.close()
      assertTrue("close closes the connection", zeroed(connections.configs[0]))
      assertEquals(PublishResult.Failed("publisher closed"), publisher.publish(event(2), publishTimeout))
      assertEquals(1, connections.configs.size)
      assertEquals(NOTHING, seen.poll(5, TimeUnit.SECONDS))
      publisher.close()
      relay.assertScriptClean()
    }
  }

  @Test
  fun `close waits for a publish in progress`() {
    FakeRelay().use { relay ->
      // The relay takes the event and never answers, so the publish holds the publisher until its
      // timeout. The relay then measures how long the connection stays open after the event: a close
      // that did not wait for the publish would end the connection at once.
      val eventSeen = CountDownLatch(1)
      val openMillis = LinkedBlockingQueue<Long>()
      relay.serve { session ->
        session.nextClientText(3_000) ?: error("no EVENT from the client")
        val seenAt = System.nanoTime()
        eventSeen.countDown()
        session.nextClientText(5_000)
        openMillis.put((System.nanoTime() - seenAt) / 1_000_000)
      }
      val connections = Connections(relay.url)
      val publisher = publisher(connections, RelayAuth.None)
      val results = LinkedBlockingQueue<PublishResult>()
      val publishing = Thread { results.put(publisher.publish(event(1), Duration.ofSeconds(2))) }
      publishing.start()
      assertTrue("the relay should see the event", eventSeen.await(5, TimeUnit.SECONDS))

      publisher.close()
      val open = openMillis.poll(5, TimeUnit.SECONDS)
      assertTrue(
        "the connection stays open until the publish times out, but closed after $open ms",
        open != null && open >= 1_000,
      )
      val result = results.poll(5, TimeUnit.SECONDS)
      assertTrue(
        "the publish ends at its own timeout, got $result",
        result is PublishResult.Failed && result.detail.contains("no OK"),
      )
      assertTrue("the connection is closed", zeroed(connections.configs[0]))
      assertEquals(PublishResult.Failed("publisher closed"), publisher.publish(event(2), publishTimeout))
      assertEquals(1, connections.configs.size)
      publishing.join(5_000)
      relay.assertScriptClean()
    }
  }

  @Test
  fun `close waits for a publish that is still opening its connection`() {
    FakeRelay().use { relay ->
      // The factory holds the publish inside opening its connection until the cell releases it, so
      // close is called in that window. The relay accepts the event, so the publish keeps its
      // connection, and only close can zero that connection's key.
      relay.serve { session -> answer(session, event(1), accepted = true) }
      val connections = Connections(relay.url)
      val inFactory = CountDownLatch(1)
      val release = CountDownLatch(1)
      val publisher =
        ReconnectingPublisher(
          {
            inFactory.countDown()
            release.await(5, TimeUnit.SECONDS)
            connections.next()
          },
          connectTimeout,
          RelayAuth.None,
        )
      val results = LinkedBlockingQueue<PublishResult>()
      val publishing = Thread { results.put(publisher.publish(event(1), publishTimeout)) }
      publishing.start()
      assertTrue("the publish should reach the factory", inFactory.await(5, TimeUnit.SECONDS))
      val closing = Thread { publisher.close() }
      closing.start()
      assertTrue(
        "close should block behind the publish or return",
        waitUntil(5_000) { closing.state !in setOf(Thread.State.NEW, Thread.State.RUNNABLE) },
      )
      val closeReturnedEarly = !closing.isAlive
      release.countDown()
      closing.join(10_000)
      publishing.join(10_000)
      assertEquals(PublishResult.Accepted, results.poll(5, TimeUnit.SECONDS))
      assertTrue(
        "close returned early=$closeReturnedEarly, and the connection the publish opened kept its key",
        zeroed(connections.configs[0]),
      )
      relay.assertScriptClean()
    }
  }

  @Test
  fun `each new connection authenticates once, before its first publish`() {
    FakeRelay().use { first ->
      FakeRelay().use { second ->
        // The relay closes only once the first publish has returned, as in the cell for a relay
        // that closes between publishes. Each relay challenges once, so a publish on a kept
        // connection that tried to authenticate again would wait for a challenge that never comes.
        val publishReturned = CountDownLatch(1)
        first.serve { session ->
          acceptAuth(session)
          answer(session, event(1), accepted = true)
          publishReturned.await(5, TimeUnit.SECONDS)
          session.sendClose()
        }
        second.serve { session ->
          acceptAuth(session)
          answer(session, event(2), accepted = true)
          answer(session, event(3), accepted = true)
        }
        val connections = Connections(first.url, second.url)
        val publisher = publisher(connections, RelayAuth.Nip42(authTimeout))

        assertEquals(PublishResult.Accepted, publisher.publish(event(1), publishTimeout))
        publishReturned.countDown()
        assertTrue(
          "the first connection should record the relay's close",
          waitUntil(5_000) { connections.opened[0].hasFailed() },
        )
        assertEquals(PublishResult.Accepted, publisher.publish(event(2), publishTimeout))
        assertEquals(PublishResult.Accepted, publisher.publish(event(3), publishTimeout))
        assertEquals(2, connections.configs.size)
        first.assertScriptClean()
        second.assertScriptClean()
        publisher.close()
      }
    }
  }

  @Test
  fun `a relay that refuses authentication gets no event`() {
    FakeRelay().use { relay ->
      val seen = LinkedBlockingQueue<String>()
      relay.serve { session ->
        session.sendText("[\"AUTH\",\"challenge\"]")
        val frame = session.nextClientText(3_000) ?: error("no AUTH from the client")
        session.sendText("[\"OK\",\"${clientEventId(frame)}\",false,\"restricted: not on the list\"]")
        seen.put(session.nextClientText(10_000) ?: NOTHING)
      }
      val connections = Connections(relay.url)
      val publisher = publisher(connections, RelayAuth.Nip42(authTimeout))

      assertEquals(
        PublishResult.Failed("relay refused authentication: restricted: not on the list"),
        publisher.publish(event(1), publishTimeout),
      )
      assertTrue("the connection is closed", zeroed(connections.configs[0]))
      assertEquals(NOTHING, seen.poll(5, TimeUnit.SECONDS))
      relay.assertScriptClean()
      publisher.close()
    }
  }

  @Test
  fun `a breach during one recipient's publish does not fail the next recipient`() {
    val recipientA =
      RecipientKey.of(Bip340.xonlyPubkeyHex("0000000000000000000000000000000000000000000000000000000000000002"))
    val recipientB =
      RecipientKey.of(Bip340.xonlyPubkeyHex("0000000000000000000000000000000000000000000000000000000000000004"))
    FakeRelay().use { first ->
      FakeRelay().use { second ->
        first.serve { session ->
          session.nextClientText(3_000) ?: error("no EVENT from the client")
          try {
            session.sendText(overDeep)
          } catch (_: Exception) {} // the client aborts the socket on the breach
        }
        second.serve { session ->
          val frame = session.nextClientText(3_000) ?: error("no EVENT from the client")
          session.sendText("[\"OK\",\"${clientEventId(frame)}\",true,\"\"]")
        }
        val publisher = publisher(Connections(first.url, second.url), RelayAuth.None)
        val notifier =
          RelayNotifier(
            SecretKeyHex.ofHexString("0000000000000000000000000000000000000000000000000000000000000001"),
            publisher,
          )

        // A linked set, so that the fan-out publishes to recipientA and then to recipientB.
        val report =
          notifier.notifyGateOpen(
            GateOpenNotice("gate-1", "digest", "nonce", "artifact"),
            linkedSetOf(recipientA, recipientB),
            publishTimeout,
          )
        val outcomeA = report.outcomes[recipientA]
        assertTrue("expected Failed, got $outcomeA", outcomeA is NotifyOutcome.Failed)
        assertTrue(
          "the first recipient fails on the breach, got $outcomeA",
          (outcomeA as NotifyOutcome.Failed).detail.contains("depth"),
        )
        assertEquals(NotifyOutcome.Delivered, report.outcomes[recipientB])
        first.assertScriptClean()
        second.assertScriptClean()
        notifier.close()
        publisher.close()
      }
    }
  }
}
