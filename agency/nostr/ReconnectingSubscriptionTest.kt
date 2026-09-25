package com.geekinasuit.agency.nostr

import com.geekinasuit.agency.nostr.ReconnectingSubscription.Delivery
import java.net.ServerSocket
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
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
 * [ReconnectingSubscription] against [FakeRelay]s: the REQ it sends again on a new connection after a
 * relay close, a breach, or a CLOSED for its subscription; messages for another subscription id,
 * passed on; the delay before each attempt and when it resets; authentication before each REQ; what
 * it reports when a connection cannot be opened; and [ReconnectingSubscription.close]. A [FakeRelay]
 * accepts one connection per [FakeRelay.serve], so a cell that expects a reconnect gives the factory
 * a second relay.
 *
 * The NIP-42 cells sign, so the class needs the secp256k1 native at runtime, like
 * [ReconnectingPublisherTest].
 */
class ReconnectingSubscriptionTest {
  private val key = "0000000000000000000000000000000000000000000000000000000000000003"
  // A connect to a local relay can take seconds when the machine is loaded, and no cell waits for a
  // connect to time out: a refused connect fails at once.
  private val connectTimeout = Duration.ofSeconds(10)
  private val authTimeout = Duration.ofSeconds(3)
  // How long a cell lets next() wait. Each such call returns on what the relay sends, well before.
  private val wait = Duration.ofSeconds(5)
  private val backoff = ReconnectingSubscription.Backoff(Duration.ofMillis(50), Duration.ofMillis(200))
  private val filters = listOf(NostrFilter(kinds = listOf(1)))

  // One level past the depth bound: a relay that sends this breaches the connection.
  private val overDeep =
    "[".repeat(RelayConnection.MAX_JSON_DEPTH + 1) + "]".repeat(RelayConnection.MAX_JSON_DEPTH + 1)

  companion object {
    private const val SUB = "approvals"

    // What a relay script records when the client closes the connection without sending a frame.
    // Such a read waits 10 s, longer than the cell's 5 s poll for it, so a frame sent late is still
    // seen, and a client that never closes fails the poll rather than passing on the read's timeout.
    private const val NOTHING = "<nothing>"

    // Load the secp256k1 native once, before the cells that sign inside a deadline, as
    // ReconnectingPublisherTest does: a cold load can take seconds under contention.
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

  /** Builds each connection to the next of [urls], around its own config and key, and keeps each
   * config so a cell can check that the subscription closed its connection. */
  private inner class Connections(private vararg val urls: String) {
    val configs = mutableListOf<RelayConfig>()

    fun next(): RelayConnection {
      val config = RelayConfig(urls[configs.size], SecretKeyHex.ofHexString(key))
      configs += config
      return RelayConnection(config)
    }
  }

  private fun subscription(
    newConnection: () -> RelayConnection,
    auth: RelayAuth,
    backoff: ReconnectingSubscription.Backoff = this.backoff,
  ) = ReconnectingSubscription(newConnection, connectTimeout, auth, SUB, filters, backoff)

  /** An event the transport carries without checking it. [n] sets its id. */
  private fun event(n: Int) =
    NostrEvent(
      id = "%064x".format(n),
      pubkey = "00".repeat(32),
      createdAt = 1_700_000_000L,
      kind = 1,
      tags = emptyList(),
      content = "",
      sig = "00".repeat(64),
    )

  private fun received(event: NostrEvent, subscriptionId: String = SUB) =
    Delivery.Received(RelayMessage.Event(subscriptionId, event))

  private fun zeroed(config: RelayConfig) = config.leadSecretKey.hexChars.all { it == Char(0) }

  private fun refusedUrl(): String = "ws://127.0.0.1:" + ServerSocket(0).use { it.localPort }

  private fun clientEventId(frame: String): String =
    Json.parseToJsonElement(frame).jsonArray[1].jsonObject["id"]!!.jsonPrimitive.content

  /** Read the client's next frame, check that it is the REQ for [SUB], and return it. */
  private fun awaitReq(session: FakeRelay.Session): String {
    val frame = session.nextClientText(3_000) ?: error("no REQ from the client")
    check(frame.startsWith("[\"REQ\",\"$SUB\",")) { "expected the REQ for $SUB, got $frame" }
    return frame
  }

  /** Challenge the client, check that its next frame is an AUTH, and accept it. */
  private fun acceptAuth(session: FakeRelay.Session) {
    session.sendText("[\"AUTH\",\"challenge\"]")
    val frame = session.nextClientText(3_000) ?: error("no AUTH from the client")
    check(frame.startsWith("[\"AUTH\"")) { "expected an AUTH first, got $frame" }
    session.sendText("[\"OK\",\"${clientEventId(frame)}\",true,\"\"]")
  }

  @Test
  fun `after the relay closes the connection, the same REQ is sent on a new connection`() {
    FakeRelay().use { first ->
      FakeRelay().use { second ->
        val reqs = LinkedBlockingQueue<String>()
        first.serve { session ->
          reqs.put(awaitReq(session))
          session.sendText(eventFrame(SUB, event(1)))
          session.sendClose()
        }
        // The second relay sends event 1 again, as a relay sends its stored events to a new REQ.
        second.serve { session ->
          reqs.put(awaitReq(session))
          session.sendText(eventFrame(SUB, event(1)))
          session.sendText(eventFrame(SUB, event(2)))
        }
        val connections = Connections(first.url, second.url)
        val subscription = subscription(connections::next, RelayAuth.None)

        assertEquals(Delivery.Subscribed, subscription.next(wait))
        assertEquals(received(event(1)), subscription.next(wait))
        val interrupted = subscription.next(wait)
        assertTrue(
          "expected an interruption naming the relay's close, got $interrupted",
          interrupted is Delivery.Interrupted && interrupted.detail.contains("relay closed"),
        )
        assertTrue("the interrupted connection is closed", zeroed(connections.configs[0]))
        assertEquals(Delivery.Subscribed, subscription.next(wait))
        assertEquals("a repeat is delivered again", received(event(1)), subscription.next(wait))
        assertEquals(received(event(2)), subscription.next(wait))
        val firstReq = reqs.poll(5, TimeUnit.SECONDS)
        assertTrue("the first relay saw a REQ", firstReq != null)
        assertEquals("the new connection's REQ is the same", firstReq, reqs.poll(5, TimeUnit.SECONDS))
        first.assertScriptClean()
        second.assertScriptClean()
        subscription.close()
      }
    }
  }

  @Test
  fun `after the relay breaches the connection, the same REQ is sent on a new connection`() {
    FakeRelay().use { first ->
      FakeRelay().use { second ->
        val reqs = LinkedBlockingQueue<String>()
        first.serve { session ->
          reqs.put(awaitReq(session))
          session.sendText(eventFrame(SUB, event(1)))
          try {
            session.sendText(overDeep)
          } catch (_: Exception) {} // the client aborts the socket on the breach
        }
        second.serve { session ->
          reqs.put(awaitReq(session))
          session.sendText(eventFrame(SUB, event(2)))
        }
        val connections = Connections(first.url, second.url)
        val subscription = subscription(connections::next, RelayAuth.None)

        assertEquals(Delivery.Subscribed, subscription.next(wait))
        assertEquals(received(event(1)), subscription.next(wait))
        val interrupted = subscription.next(wait)
        assertTrue(
          "expected an interruption naming the breach, got $interrupted",
          interrupted is Delivery.Interrupted && interrupted.detail.contains("depth"),
        )
        assertEquals(Delivery.Subscribed, subscription.next(wait))
        assertEquals(received(event(2)), subscription.next(wait))
        val firstReq = reqs.poll(5, TimeUnit.SECONDS)
        assertTrue("the first relay saw a REQ", firstReq != null)
        assertEquals("the new connection's REQ is the same", firstReq, reqs.poll(5, TimeUnit.SECONDS))
        first.assertScriptClean()
        second.assertScriptClean()
        subscription.close()
      }
    }
  }

  @Test
  fun `a CLOSED for the subscription ends it, and the REQ is sent on a new connection`() {
    FakeRelay().use { first ->
      FakeRelay().use { second ->
        // After its CLOSED, the first relay records the client's next frame. There must be none
        // before the client closes the connection.
        val seen = LinkedBlockingQueue<String>()
        first.serve { session ->
          awaitReq(session)
          session.sendText(closedFrame(SUB, "error: shutting down"))
          seen.put(session.nextClientText(10_000) ?: NOTHING)
        }
        second.serve { session ->
          awaitReq(session)
          session.sendText(eventFrame(SUB, event(2)))
        }
        val connections = Connections(first.url, second.url)
        val subscription = subscription(connections::next, RelayAuth.None)

        assertEquals(Delivery.Subscribed, subscription.next(wait))
        assertEquals(
          Delivery.Interrupted("relay closed the subscription: error: shutting down", Duration.ofMillis(50)),
          subscription.next(wait),
        )
        assertTrue("the connection is closed", zeroed(connections.configs[0]))
        assertEquals(NOTHING, seen.poll(5, TimeUnit.SECONDS))
        assertEquals(Delivery.Subscribed, subscription.next(wait))
        assertEquals(received(event(2)), subscription.next(wait))
        first.assertScriptClean()
        second.assertScriptClean()
        subscription.close()
      }
    }
  }

  @Test
  fun `messages for another subscription id are passed on and leave the subscription open`() {
    FakeRelay().use { relay ->
      relay.serve { session ->
        awaitReq(session)
        session.sendText(closedFrame("other", "error: not yours"))
        session.sendText(eventFrame("other", event(1)))
        session.sendText(eoseFrame("other"))
        session.sendText(eventFrame(SUB, event(2)))
      }
      val connections = Connections(relay.url)
      val subscription = subscription(connections::next, RelayAuth.None)

      assertEquals(Delivery.Subscribed, subscription.next(wait))
      assertEquals(
        Delivery.Received(RelayMessage.Closed("other", "error: not yours")),
        subscription.next(wait),
      )
      assertEquals(received(event(1), "other"), subscription.next(wait))
      assertEquals(Delivery.Received(RelayMessage.Eose("other")), subscription.next(wait))
      assertEquals(received(event(2)), subscription.next(wait))
      assertEquals("a quiet timeout reports nothing", null, subscription.next(Duration.ofMillis(300)))
      assertEquals(1, connections.configs.size)
      assertTrue("the connection is still open", !zeroed(connections.configs[0]))
      relay.assertScriptClean()
      subscription.close()
    }
  }

  @Test
  fun `the delay before each attempt doubles up to the maximum, and each attempt waits for it`() {
    val url = refusedUrl()
    val attempts = AtomicInteger()
    val subscription =
      subscription(
        {
          attempts.incrementAndGet()
          RelayConnection(RelayConfig(url, SecretKeyHex.ofHexString(key)))
        },
        RelayAuth.None,
      )

    val started = System.nanoTime()
    val results = (1..4).map { subscription.next(wait) }
    val elapsedMillis = (System.nanoTime() - started) / 1_000_000
    assertTrue(
      "every attempt is refused, got $results",
      results.all { it is Delivery.Unavailable && it.detail.startsWith("could not connect: connection refused") },
    )
    assertEquals(
      listOf(50L, 100L, 200L, 200L),
      results.map { (it as Delivery.Unavailable).retryAfter.toMillis() },
    )
    assertEquals("one connection per attempt", 4, attempts.get())
    assertTrue(
      "the attempts wait 50, 100 and 200 ms between them, but all four took $elapsedMillis ms",
      elapsedMillis >= 350,
    )
    subscription.close()
  }

  @Test
  fun `EOSE for the subscription resets the delay, and EOSE for another id does not`() {
    FakeRelay().use { first ->
      FakeRelay().use { second ->
        first.serve { session ->
          awaitReq(session)
          session.sendText(eoseFrame("other"))
          session.sendClose()
        }
        second.serve { session ->
          awaitReq(session)
          session.sendText(eoseFrame(SUB))
          session.sendClose()
        }
        // Two refused attempts first, so the delay has grown before the first relay is reached.
        val connections = Connections(refusedUrl(), refusedUrl(), first.url, second.url)
        val subscription = subscription(connections::next, RelayAuth.None)

        assertEquals(Duration.ofMillis(50), (subscription.next(wait) as Delivery.Unavailable).retryAfter)
        assertEquals(Duration.ofMillis(100), (subscription.next(wait) as Delivery.Unavailable).retryAfter)
        assertEquals(Delivery.Subscribed, subscription.next(wait))
        assertEquals(Delivery.Received(RelayMessage.Eose("other")), subscription.next(wait))
        assertEquals(
          "an EOSE for another id leaves the delay as it was",
          Duration.ofMillis(200),
          (subscription.next(wait) as Delivery.Interrupted).retryAfter,
        )
        assertEquals(Delivery.Subscribed, subscription.next(wait))
        assertEquals(Delivery.Received(RelayMessage.Eose(SUB)), subscription.next(wait))
        assertEquals(
          "an EOSE for the subscription resets the delay",
          Duration.ofMillis(50),
          (subscription.next(wait) as Delivery.Interrupted).retryAfter,
        )
        first.assertScriptClean()
        second.assertScriptClean()
        subscription.close()
      }
    }
  }

  @Test
  fun `each new connection authenticates before its REQ`() {
    FakeRelay().use { first ->
      FakeRelay().use { second ->
        // Each relay challenges first and then expects the REQ, so a REQ sent before the AUTH, or no
        // AUTH at all, fails the relay's script.
        first.serve { session ->
          acceptAuth(session)
          awaitReq(session)
          session.sendText(eventFrame(SUB, event(1)))
          session.sendClose()
        }
        second.serve { session ->
          acceptAuth(session)
          awaitReq(session)
          session.sendText(eventFrame(SUB, event(2)))
        }
        val connections = Connections(first.url, second.url)
        val subscription = subscription(connections::next, RelayAuth.Nip42(authTimeout))

        assertEquals(Delivery.Subscribed, subscription.next(wait))
        assertEquals(received(event(1)), subscription.next(wait))
        assertTrue(subscription.next(wait) is Delivery.Interrupted)
        assertEquals(Delivery.Subscribed, subscription.next(wait))
        assertEquals(received(event(2)), subscription.next(wait))
        first.assertScriptClean()
        second.assertScriptClean()
        subscription.close()
      }
    }
  }

  @Test
  fun `a connection that fails to authenticate sends no REQ`() {
    FakeRelay().use { relay ->
      val seen = LinkedBlockingQueue<String>()
      relay.serve { session ->
        session.sendText("[\"AUTH\",\"challenge\"]")
        val frame = session.nextClientText(3_000) ?: error("no AUTH from the client")
        session.sendText("[\"OK\",\"${clientEventId(frame)}\",false,\"restricted: not on the list\"]")
        seen.put(session.nextClientText(10_000) ?: NOTHING)
      }
      val connections = Connections(relay.url)
      val subscription = subscription(connections::next, RelayAuth.Nip42(authTimeout))

      assertEquals(
        Delivery.Unavailable("relay refused authentication: restricted: not on the list", Duration.ofMillis(50)),
        subscription.next(wait),
      )
      assertTrue("the connection is closed", zeroed(connections.configs[0]))
      assertEquals(NOTHING, seen.poll(5, TimeUnit.SECONDS))
      relay.assertScriptClean()
      subscription.close()
    }
  }

  @Test
  fun `a factory that throws is reported by the exception's class alone`() {
    val subscription =
      subscription({ throw IllegalStateException("key file held 0123abcd") }, RelayAuth.None)
    assertEquals(
      Delivery.Unavailable("could not create a connection: IllegalStateException", Duration.ofMillis(50)),
      subscription.next(wait),
    )
    // Thread.interrupted() clears the status as it reads it, so a failure here reaches no later cell.
    assertFalse("the thread is not interrupted", Thread.interrupted())
    subscription.close()
  }

  @Test
  fun `a factory that throws InterruptedException leaves the thread interrupted, and next makes no further attempt`() {
    val attempts = AtomicInteger()
    val subscription =
      subscription({ attempts.incrementAndGet(); throw InterruptedException() }, RelayAuth.None)
    try {
      assertEquals(
        Delivery.Unavailable("could not create a connection: InterruptedException", Duration.ofMillis(50)),
        subscription.next(wait),
      )
      assertTrue("the thread is interrupted again", Thread.currentThread().isInterrupted)
      assertEquals("an attempt is due after 50 ms, but nothing is reported", null, subscription.next(wait))
    } finally {
      // Clear the status, so it does not reach the next cell on this thread.
      Thread.interrupted()
    }
    assertEquals("no attempt after the interrupted one", 1, attempts.get())
    subscription.close()
  }

  @Test
  fun `close closes the connection, and every later next returns Stopped`() {
    FakeRelay().use { relay ->
      val seen = LinkedBlockingQueue<String>()
      relay.serve { session ->
        awaitReq(session)
        seen.put(session.nextClientText(10_000) ?: NOTHING)
      }
      val connections = Connections(relay.url)
      val subscription = subscription(connections::next, RelayAuth.None)

      assertEquals(Delivery.Subscribed, subscription.next(wait))
      subscription.close()
      assertTrue("close closes the connection", zeroed(connections.configs[0]))
      assertEquals(NOTHING, seen.poll(5, TimeUnit.SECONDS))
      assertEquals(Delivery.Stopped, subscription.next(wait))
      assertEquals(Delivery.Stopped, subscription.next(wait))
      assertEquals(1, connections.configs.size)
      subscription.close()
      relay.assertScriptClean()
    }
  }

  @Test
  fun `close does not wait out a next that is waiting for a message`() {
    FakeRelay().use { relay ->
      relay.serve { session ->
        awaitReq(session)
        session.nextClientText(10_000)
      }
      val connections = Connections(relay.url)
      val subscription = subscription(connections::next, RelayAuth.None)
      assertEquals(Delivery.Subscribed, subscription.next(wait))

      val results = LinkedBlockingQueue<Delivery>()
      val waiting = Thread { subscription.next(Duration.ofSeconds(10))?.let { results.put(it) } }
      waiting.start()
      assertTrue(
        "the next call should be waiting for a message",
        waitUntil(5_000) { waiting.state == Thread.State.TIMED_WAITING },
      )
      val started = System.nanoTime()
      subscription.close()
      val closeMillis = (System.nanoTime() - started) / 1_000_000
      assertEquals(Delivery.Stopped, results.poll(5, TimeUnit.SECONDS))
      assertTrue("close took $closeMillis ms of the next call's 10 s", closeMillis < 5_000)
      assertTrue("close closes the connection", zeroed(connections.configs[0]))
      waiting.join(10_000)
      relay.assertScriptClean()
    }
  }

  @Test
  fun `close during a connection attempt closes the connection the attempt opened`() {
    FakeRelay().use { relay ->
      // The factory holds the attempt until the cell releases it, so close is called in that window.
      // The relay then records the client's first frame: there must be none, since no REQ is sent
      // on a connection opened after close.
      val seen = LinkedBlockingQueue<String>()
      relay.serve { session -> seen.put(session.nextClientText(10_000) ?: NOTHING) }
      val connections = Connections(relay.url)
      val inFactory = CountDownLatch(1)
      val release = CountDownLatch(1)
      val subscription =
        subscription(
          {
            inFactory.countDown()
            release.await(5, TimeUnit.SECONDS)
            connections.next()
          },
          RelayAuth.None,
        )
      val results = LinkedBlockingQueue<Delivery>()
      val attempting = Thread { subscription.next(wait)?.let { results.put(it) } }
      attempting.start()
      assertTrue("the attempt should reach the factory", inFactory.await(5, TimeUnit.SECONDS))
      val closing = Thread { subscription.close() }
      closing.start()
      assertTrue(
        "close should wait for the attempt",
        waitUntil(5_000) { closing.state == Thread.State.BLOCKED },
      )
      release.countDown()
      closing.join(10_000)
      attempting.join(10_000)
      assertEquals(Delivery.Stopped, results.poll(5, TimeUnit.SECONDS))
      assertTrue("the connection the attempt opened is closed", zeroed(connections.configs[0]))
      assertEquals(NOTHING, seen.poll(5, TimeUnit.SECONDS))
      relay.assertScriptClean()
    }
  }

  @Test
  fun `a fault is reported without waiting out the next call's timeout`() {
    FakeRelay().use { relay ->
      relay.serve { session ->
        awaitReq(session)
        Thread.sleep(200)
        session.sendClose()
      }
      val connections = Connections(relay.url)
      val subscription = subscription(connections::next, RelayAuth.None)
      assertEquals(Delivery.Subscribed, subscription.next(wait))

      val started = System.nanoTime()
      val interrupted = subscription.next(Duration.ofSeconds(10))
      val millis = (System.nanoTime() - started) / 1_000_000
      assertTrue("expected Interrupted, got $interrupted", interrupted is Delivery.Interrupted)
      assertTrue("the interruption came $millis ms into a 10 s wait", millis < 5_000)
      relay.assertScriptClean()
      subscription.close()
    }
  }

  @Test
  fun `a next whose timeout ends before the delay makes no attempt and reports nothing`() {
    val url = refusedUrl()
    val attempts = AtomicInteger()
    val subscription =
      subscription(
        {
          attempts.incrementAndGet()
          RelayConnection(RelayConfig(url, SecretKeyHex.ofHexString(key)))
        },
        RelayAuth.None,
        ReconnectingSubscription.Backoff(Duration.ofSeconds(5), Duration.ofSeconds(5)),
      )
    assertTrue(subscription.next(wait) is Delivery.Unavailable)

    val started = System.nanoTime()
    val result = subscription.next(Duration.ofMillis(100))
    val millis = (System.nanoTime() - started) / 1_000_000
    assertEquals("nothing to report before the 5 s delay passes", null, result)
    assertTrue("next(100 ms) took $millis ms, waiting toward the 5 s delay", millis < 2_500)
    assertEquals("no attempt before the delay passes", 1, attempts.get())
    subscription.close()
  }

  @Test
  fun `after an interruption the next attempt waits for its retryAfter`() {
    // Long enough that next(100 ms) still starts well before the delay passes when the test thread
    // stalls on a loaded machine.
    val delay = Duration.ofSeconds(3)
    FakeRelay().use { first ->
      FakeRelay().use { second ->
        first.serve { session ->
          awaitReq(session)
          session.sendClose()
        }
        second.serve { session -> awaitReq(session) }
        val connections = Connections(first.url, second.url)
        val subscription =
          subscription(connections::next, RelayAuth.None, ReconnectingSubscription.Backoff(delay, delay))
        assertEquals(Delivery.Subscribed, subscription.next(wait))

        val started = System.nanoTime()
        val interrupted = subscription.next(wait)
        assertEquals(
          "expected Interrupted after a 3 s delay, got $interrupted",
          delay,
          (interrupted as? Delivery.Interrupted)?.retryAfter,
        )
        assertEquals("nothing to report before the delay passes", null, subscription.next(Duration.ofMillis(100)))
        assertEquals("no attempt before the delay passes", 1, connections.configs.size)
        assertEquals(Delivery.Subscribed, subscription.next(wait.plus(delay)))
        val millis = (System.nanoTime() - started) / 1_000_000
        assertTrue(
          "the new connection was subscribed $millis ms after the old one's wait began",
          millis >= delay.toMillis(),
        )
        first.assertScriptClean()
        second.assertScriptClean()
        subscription.close()
      }
    }
  }

  @Test
  fun `on an interrupted thread next makes no attempt and leaves the thread interrupted`() {
    val attempts = AtomicInteger()
    val subscription =
      subscription({ attempts.incrementAndGet(); error("no attempt expected") }, RelayAuth.None)
    Thread.currentThread().interrupt()
    try {
      assertEquals("an attempt is due, but nothing is reported", null, subscription.next(wait))
      assertTrue("the thread is still interrupted", Thread.currentThread().isInterrupted)
    } finally {
      // Clear the status, so it does not reach the next cell on this thread.
      Thread.interrupted()
    }
    assertEquals("no attempt on an interrupted thread", 0, attempts.get())
    subscription.close()
  }

  @Test
  fun `a negative timeout counts as zero`() {
    val attempts = AtomicInteger()
    val subscription =
      subscription(
        { attempts.incrementAndGet(); throw IllegalStateException("no relay") },
        RelayAuth.None,
        ReconnectingSubscription.Backoff(Duration.ofSeconds(5), Duration.ofSeconds(5)),
      )
    assertTrue(subscription.next(wait) is Delivery.Unavailable)

    // A timeout this negative converts to Long.MIN_VALUE ns. Added with no lower clamp, that puts the
    // deadline so far back that the subtraction comparing it wraps, and the deadline reads as far ahead.
    val started = System.nanoTime()
    val result = subscription.next(Duration.ofMillis(Long.MIN_VALUE))
    val millis = (System.nanoTime() - started) / 1_000_000
    assertEquals("nothing to report before the 5 s delay passes", null, result)
    assertTrue("next took $millis ms, waiting toward the 5 s delay", millis < 2_500)
    assertEquals("no attempt before the delay passes", 1, attempts.get())
    subscription.close()
  }

  @Test
  fun `a timeout too long to count in nanoseconds does not throw, and next still waits for the delay`() {
    val attempts = AtomicInteger()
    val subscription =
      subscription(
        { attempts.incrementAndGet(); throw IllegalStateException("no relay") },
        RelayAuth.None,
        ReconnectingSubscription.Backoff(Duration.ofMillis(300), Duration.ofMillis(600)),
      )
    val forever = Duration.ofMillis(Long.MAX_VALUE)
    val started = System.nanoTime()
    assertEquals(
      Delivery.Unavailable("could not create a connection: IllegalStateException", Duration.ofMillis(300)),
      subscription.next(forever),
    )
    // The second call waits out the 300 ms delay and tries again, rather than returning at once.
    assertEquals(
      Delivery.Unavailable("could not create a connection: IllegalStateException", Duration.ofMillis(600)),
      subscription.next(forever),
    )
    val millis = (System.nanoTime() - started) / 1_000_000
    assertTrue("the second attempt came $millis ms after the first call began, before its 300 ms delay", millis >= 300)
    assertEquals(2, attempts.get())
    subscription.close()
  }
}

// Server-to-client frames for the relay side of these cells, as in RelayConnectionSubscribeTest.
// subscriptionId and message are test literals, so plain interpolation is safe; serialize() supplies
// the event object's exact JSON.
private fun eventFrame(subscriptionId: String, event: NostrEvent): String =
  "[\"EVENT\",\"$subscriptionId\"," + event.serialize() + "]"

private fun eoseFrame(subscriptionId: String): String = "[\"EOSE\",\"$subscriptionId\"]"

private fun closedFrame(subscriptionId: String, message: String): String =
  "[\"CLOSED\",\"$subscriptionId\",\"$message\"]"
