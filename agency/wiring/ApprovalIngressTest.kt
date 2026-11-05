package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.lead.AgentHost
import com.geekinasuit.agency.lead.ApprovalAccept
import com.geekinasuit.agency.lead.ApprovalCandidate
import com.geekinasuit.agency.lead.FakePodRunner
import com.geekinasuit.agency.lead.FileTicketSource
import com.geekinasuit.agency.lead.GateKinds
import com.geekinasuit.agency.lead.LeadAuth
import com.geekinasuit.agency.lead.ScriptedCognition
import com.geekinasuit.agency.lead.TimerService
import com.geekinasuit.agency.lead.gateIdFor
import com.geekinasuit.agency.lead.ticketLead
import com.geekinasuit.agency.nostr.APPROVAL_RUMOR_KIND
import com.geekinasuit.agency.nostr.ApprovalSigning
import com.geekinasuit.agency.nostr.GateOpenNotice
import com.geekinasuit.agency.nostr.Bip340
import com.geekinasuit.agency.nostr.Bip340ApprovalVerifier
import com.geekinasuit.agency.nostr.FakeRelay
import com.geekinasuit.agency.nostr.GiftWrapEncoding
import com.geekinasuit.agency.nostr.Nip59
import com.geekinasuit.agency.nostr.NostrEvent
import com.geekinasuit.agency.nostr.ReconnectingSubscription
import com.geekinasuit.agency.nostr.RecipientKey
import com.geekinasuit.agency.nostr.RelayAuth
import com.geekinasuit.agency.nostr.RelayConfig
import com.geekinasuit.agency.nostr.RelayConnection
import com.geekinasuit.agency.nostr.Rumor
import com.geekinasuit.agency.nostr.SecretKeyHex
import com.geekinasuit.agency.nostr.StoredEventRelay
import com.geekinasuit.agency.nostr.encodeApproval
import com.geekinasuit.agency.nostr.serialize
import com.geekinasuit.agency.lead.LeadKinds
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertThrows
import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.shared.auth.AllowList
import com.geekinasuit.agency.shared.auth.Principal
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.oneOfOne
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The approval ingress over a scripted relay ([FakeRelay], one connection per relay): what reaches the
 * accept boundary, what is dropped as malformed, the resubscription after the boundary throws, and one
 * run end to end into a real host, whose gate the approval releases. Against a relay with a store
 * ([StoredEventRelay]): the walk back past a relay's cap on replay.
 */
class ApprovalIngressTest {

  @get:Rule val tmp = TemporaryFolder()

  private class RecordingSink(private val answer: (Int) -> ApprovalAccept) : ApprovalSink {
    val seen = CopyOnWriteArrayList<ApprovalCandidate>()

    override fun accept(candidate: ApprovalCandidate): ApprovalAccept {
      seen += candidate
      return answer(seen.size)
    }
  }

  private inner class Connections(private vararg val urls: String) {
    var opened = 0

    fun next(): RelayConnection = RelayConnection(RelayConfig(urls[opened++], SecretKeyHex.ofHexString(LEAD_SECRET)))
  }

  private fun ingress(
    connections: Connections,
    sink: ApprovalSink,
    resubscribeBackoff: ReconnectingSubscription.Backoff =
      ReconnectingSubscription.Backoff(Duration.ofMillis(10), Duration.ofMillis(50)),
    approvalsAwaited: () -> Boolean = { false },
  ) =
    ApprovalIngress(
      newConnection = connections::next,
      connectTimeout = Duration.ofSeconds(3),
      auth = RelayAuth.None,
      backoff = ReconnectingSubscription.Backoff(Duration.ofMillis(10), Duration.ofMillis(50)),
      resubscribeBackoff = resubscribeBackoff,
      leadKey = SecretKeyHex.ofHexString(LEAD_SECRET),
      approvalsAwaited = approvalsAwaited,
      sink = sink,
    )

  /** Step [ingress] until [done] holds, for at most ten seconds. */
  private fun ApprovalIngress.runUntil(done: () -> Boolean) {
    val deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos()
    while (!done() && System.nanoTime() < deadline) step(Duration.ofMillis(100))
    assertTrue("condition not reached; counts ${counts()}", done())
  }

  /** Serve the REQ with [events], then EOSE, then hold the connection open. */
  private fun FakeRelay.replays(vararg events: NostrEvent) = serve { session ->
    val req = session.nextClientText(5_000) ?: error("no REQ")
    check(req.startsWith("[\"REQ\",\"${ApprovalIngress.SUBSCRIPTION_ID}\",")) { "unexpected first frame $req" }
    for (e in events) session.sendText("[\"EVENT\",\"${ApprovalIngress.SUBSCRIPTION_ID}\"," + e.serialize() + "]")
    session.sendText("[\"EOSE\",\"${ApprovalIngress.SUBSCRIPTION_ID}\"]")
    session.nextClientText(10_000)
  }

  @Test
  fun aWrapToTheLeadReachesTheBoundaryAsACandidate() =
    FakeRelay().use { relay ->
      val wrap = approvalWrap("plan-approval:t1", "n".repeat(64), "d".repeat(64))
      relay.replays(wrap)
      val sink = RecordingSink { ApprovalAccept.RECORDED }
      val ingress = ingress(Connections(relay.url), sink)
      ingress.runUntil { sink.seen.size == 1 }
      val c = sink.seen.single()
      assertEquals("plan-approval:t1", c.gateId)
      assertEquals("n".repeat(64), c.nonce)
      assertEquals("d".repeat(64), c.payloadDigest)
      val rumorId = checkNotNull(Nip59.unwrap(bytes(LEAD_SECRET), wrap)).id
      assertEquals("the artifact id is the rumor's", JsonPrimitive(rumorId), c.evidence["carrierArtifactId"])
      assertEquals(mapOf(ApprovalAccept.RECORDED to 1L), ingress.counts().accepted)
      ingress.close()
    }

  @Test
  fun whatCarriesNoApprovalIsCountedAndDroppedAndAValidOneStillGetsThrough() =
    FakeRelay().use { relay ->
      val notAWrap = approvalWrap("g", "n", "d").let { it.copy(kind = 1) }
      val toAnotherKey = approvalWrap("g", "n", "d", lead = RecipientKey.of(Bip340.xonlyPubkeyHex(OTHER_SECRET)))
      val command = """{"type":"release","gateId":"g"}"""
      val commandShaped = rumorWrap(Rumor(APPROVER_PUB, 1_700_000_000, 1, emptyList(), command))
      val commandOfTheApprovalKind = rumorWrap(Rumor(APPROVER_PUB, 1_700_000_000, APPROVAL_RUMOR_KIND, emptyList(), command))
      val valid = approvalWrap("g", "n", "d")
      relay.replays(notAWrap, toAnotherKey, commandShaped, commandOfTheApprovalKind, valid)
      val sink = RecordingSink { ApprovalAccept.REJECTED }
      val ingress = ingress(Connections(relay.url), sink)
      ingress.runUntil { sink.seen.size == 1 && ingress.counts().malformed == 4L }
      assertEquals("g", sink.seen.single().gateId)
      ingress.close()
    }

  @Test
  fun anApprovalTheBoundaryFailsToRecordIsReplayedOnANewSubscription() =
    FakeRelay().use { first ->
      FakeRelay().use { second ->
        val wrap = approvalWrap("g", "n", "d")
        first.replays(wrap)
        second.replays(wrap)
        val sink =
          object : ApprovalSink {
            val seen = CopyOnWriteArrayList<ApprovalCandidate>()

            override fun accept(candidate: ApprovalCandidate): ApprovalAccept {
              seen += candidate
              if (seen.size == 1) throw IllegalStateException("append refused")
              return ApprovalAccept.RECORDED
            }
          }
        val connections = Connections(first.url, second.url)
        val ingress = ingress(connections, sink)
        ingress.runUntil { ingress.counts().accepted[ApprovalAccept.RECORDED] == 1L }
        assertEquals("the replay came on a second connection", 2, connections.opened)
        assertEquals(sink.seen[0], sink.seen[1])
        val counts = ingress.counts()
        assertEquals(1L, counts.sinkFailures)
        assertEquals(1L, counts.resubscriptions)
        ingress.close()
      }
    }

  @Test
  fun aBoundaryThatKeepsThrowingIsResubscribedOnAGrowingDelayNotInALoop() {
    // Every relay replays the approval and the sink refuses each, so each resubscription waits out
    // the delay before it: 40, then 80, then 160 ms before the fourth. Without the delay the four
    // come within tens of milliseconds.
    val relays = List(6) { FakeRelay() }
    try {
      val wrap = approvalWrap("g", "n", "d")
      relays.forEach { it.replays(wrap) }
      val ingress =
        ingress(
          Connections(*relays.map { it.url }.toTypedArray()),
          { throw IllegalStateException("approval refused: the approval boundary has stopped") },
          ReconnectingSubscription.Backoff(Duration.ofMillis(40), Duration.ofMillis(160)),
        )
      val started = System.nanoTime()
      ingress.runUntil { ingress.counts().resubscriptions == 4L }
      val elapsedMillis = (System.nanoTime() - started) / 1_000_000
      assertTrue("four resubscriptions took $elapsedMillis ms, under the 280 ms of delays", elapsedMillis >= 280)
      assertEquals(4L, ingress.counts().sinkFailures)
      ingress.close()
    } finally {
      relays.forEach { it.close() }
    }
  }

  @Test
  fun onAnInterruptedThreadAStepEndsTheLoopAndKeepsTheInterrupt() {
    val ingress = ingress(Connections(), { ApprovalAccept.RECORDED })
    Thread.currentThread().interrupt()
    try {
      assertEquals(false, ingress.step(Duration.ofSeconds(1)))
      assertTrue(Thread.currentThread().isInterrupted)
    } finally {
      Thread.interrupted()
      ingress.close()
    }
  }

  @Test
  fun aSinkInterruptedMidAcceptIsResubscribedAndTheLoopThenEnds() =
    FakeRelay().use { relay ->
      relay.replays(approvalWrap("g", "n", "d"))
      val ingress = ingress(Connections(relay.url), { throw InterruptedException() })
      try {
        ingress.runUntil { ingress.counts().sinkFailures == 1L }
        assertTrue("the interrupt is kept", Thread.currentThread().isInterrupted)
        assertEquals("the unrecorded approval is due a replay", 1L, ingress.counts().resubscriptions)
        assertEquals(false, ingress.step(Duration.ofSeconds(1)))
      } finally {
        Thread.interrupted()
        ingress.close()
      }
    }

  @Test
  fun aStartedIngressDeliversOnItsOwnThreadAndCloseEndsIt() =
    FakeRelay().use { relay ->
      relay.replays(approvalWrap("g", "n", "d"))
      val sink = RecordingSink { ApprovalAccept.RECORDED }
      val ingress = ingress(Connections(relay.url), sink)
      val exits = CopyOnWriteArrayList<String>()
      ingress.start { exits += it }
      val deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos()
      while (sink.seen.isEmpty() && System.nanoTime() < deadline) Thread.sleep(20)
      assertEquals(1, sink.seen.size)
      ingress.close()
      assertTrue(
        "the worker ended",
        Thread.getAllStackTraces().keys.none { it.name == "approval-ingress" && it.isAlive },
      )
      assertEquals("a close is not an exit to report", emptyList<String>(), exits)
    }

  /** Serve the REQ with [event] and EOSE, then count [closed] down when the client closes the
   * subscription or the connection, within ten seconds. */
  private fun FakeRelay.replaysAndWatchesForClose(event: NostrEvent, closed: CountDownLatch) = serve { session ->
    session.nextClientText(5_000) ?: error("no REQ")
    session.sendText("[\"EVENT\",\"${ApprovalIngress.SUBSCRIPTION_ID}\"," + event.serialize() + "]")
    session.sendText("[\"EOSE\",\"${ApprovalIngress.SUBSCRIPTION_ID}\"]")
    val started = System.nanoTime()
    session.nextClientText(10_000)
    if (System.nanoTime() - started < Duration.ofSeconds(9).toNanos()) closed.countDown()
  }

  /** Start [ingress], wait for its worker to report an exit, and return the reason. The report waits up
   * to five seconds for [closed], so it also asserts that the subscription closed before the report. */
  private fun startAndAwaitExit(ingress: ApprovalIngress, closed: CountDownLatch): String {
    val exit = LinkedBlockingQueue<Pair<String, Boolean>>()
    ingress.start { exit.put(it to closed.await(5, TimeUnit.SECONDS)) }
    val (reason, closedFirst) =
      checkNotNull(exit.poll(10, TimeUnit.SECONDS)) { "the worker did not report an exit; counts ${ingress.counts()}" }
    assertTrue("the subscription was closed before the report", closedFirst)
    return reason
  }

  @Test
  fun anExitReportMayCloseTheIngressWithoutWaitingOnItself() =
    FakeRelay().use { relay ->
      relay.replays(approvalWrap("g", "n", "d"))
      val ingress = ingress(Connections(relay.url), { throw AssertionError("the sink broke") })
      val closedIn = LinkedBlockingQueue<Long>()
      ingress.start {
        val started = System.nanoTime()
        ingress.close()
        closedIn.put((System.nanoTime() - started) / 1_000_000)
      }
      val millis = checkNotNull(closedIn.poll(10, TimeUnit.SECONDS)) { "the worker did not report an exit" }
      assertTrue("close from the report took $millis ms", millis < 2_000)
    }

  @Test
  fun aWorkerEndedByAnErrorFromTheSinkClosesItsSubscriptionAndReportsWhy() =
    FakeRelay().use { relay ->
      val closed = CountDownLatch(1)
      relay.replaysAndWatchesForClose(approvalWrap("g", "n", "d"), closed)
      val ingress = ingress(Connections(relay.url), { throw AssertionError("the sink broke") })
      try {
        val reason = startAndAwaitExit(ingress, closed)
        assertTrue(reason, reason.contains("java.lang.AssertionError: the sink broke"))
      } finally {
        ingress.close()
      }
    }

  @Test
  fun aWorkerEndedByAnInterruptClosesItsSubscriptionAndReportsWhy() =
    FakeRelay().use { relay ->
      val closed = CountDownLatch(1)
      relay.replaysAndWatchesForClose(approvalWrap("g", "n", "d"), closed)
      // The sink runs on the worker, so this interrupts the worker; the delivery itself succeeds.
      val ingress =
        ingress(Connections(relay.url), {
          Thread.currentThread().interrupt()
          ApprovalAccept.RECORDED
        })
      try {
        assertEquals("the ingress thread was interrupted", startAndAwaitExit(ingress, closed))
        assertEquals(mapOf(ApprovalAccept.RECORDED to 1L), ingress.counts().accepted)
      } finally {
        ingress.close()
      }
    }

  /** A relay holding [older] behind newer wraps it replays first, at a clamp of [clamp]. */
  private fun crowded(order: StoredEventRelay.UntilOrder, older: NostrEvent, clamp: Int = 3) =
    StoredEventRelay(order, clamp).also {
      it.store(older, filler(1, 200), filler(2, 300), filler(3, 500), filler(4, 501), filler(5, 502))
    }

  @Test
  fun anApprovalCrowdedOutBehindAJournaledOneComesBackByPaging() {
    for (order in StoredEventRelay.UntilOrder.entries) {
      val older = approvalWrap("g-older", "n".repeat(64), "d".repeat(64), at = 100)
      crowded(order, older).use { relay ->
        // The newest wrap is an approval the boundary already holds: seeing it must not end the walk.
        relay.store(approvalWrap("g-newer", "m".repeat(64), "d".repeat(64), at = 503))
        relay.serveOneConnection()
        val sink = RecordingSink { ApprovalAccept.DUPLICATE }
        val ingress = ingress(Connections(relay.url), sink, approvalsAwaited = { true })
        ingress.runUntil { sink.seen.any { it.gateId == "g-older" } }
        assertEquals("under $order", 0L, ingress.counts().stalledWalks)
        relay.assertClean()
        ingress.close()
      }
    }
  }

  @Test
  fun aWalkEndsOnAPageThatGetsNoLowerAndClosesItsSubscription() {
    for (order in StoredEventRelay.UntilOrder.entries) {
      val older = approvalWrap("g-older", "n".repeat(64), "d".repeat(64), at = 100)
      crowded(order, older).use { relay ->
        relay.serveOneConnection()
        val sink = RecordingSink { ApprovalAccept.RECORDED }
        val ingress = ingress(Connections(relay.url), sink, approvalsAwaited = { true })
        // A page's CLOSE comes before the next page's REQ, so the two counts meet only at the end.
        ingress.runUntil { ingress.counts().pages > 0L && relay.closed.size.toLong() == ingress.counts().pages }
        assertEquals("under $order", 0L, ingress.counts().stalledWalks)
        val pages = relay.requests.size
        repeat(3) { ingress.step(Duration.ofMillis(50)) }
        assertEquals("under $order: no page after the last", pages, relay.requests.size)
        ingress.close()
      }
    }
  }

  @Test
  fun aFullPageStampedInOneSecondStallsTheWalkAndCountsIt() {
    StoredEventRelay(StoredEventRelay.UntilOrder.AT_OR_BEFORE, clamp = ApprovalIngress.PAGE_LIMIT + 10).use { relay ->
      val older = approvalWrap("g-older", "n".repeat(64), "d".repeat(64), at = 50)
      relay.store(older)
      relay.store(*Array(ApprovalIngress.PAGE_LIMIT + 10) { filler(it + 1, 100) })
      relay.serveOneConnection()
      val sink = RecordingSink { ApprovalAccept.RECORDED }
      val ingress = ingress(Connections(relay.url), sink, approvalsAwaited = { true })
      ingress.runUntil { ingress.counts().stalledWalks == 1L }
      assertEquals("the stated limit: the older approval stays held", 0, sink.seen.size)
      ingress.close()
    }
  }

  @Test
  fun aLeadWithNothingAwaitedSendsNoPage() =
    StoredEventRelay(StoredEventRelay.UntilOrder.AT_OR_BEFORE).use { relay ->
      relay.store(filler(1, 100))
      relay.serveOneConnection()
      val ingress = ingress(Connections(relay.url), RecordingSink { ApprovalAccept.RECORDED })
      ingress.runUntil { ingress.counts().malformed == 1L }
      repeat(3) { ingress.step(Duration.ofMillis(50)) }
      assertEquals(1, relay.requests.size)
      assertEquals(0L, ingress.counts().pages)
      ingress.close()
    }

  @Test
  fun aWalkEndsWhenApprovalsAreNoLongerAwaited() =
    StoredEventRelay(StoredEventRelay.UntilOrder.BEFORE, clamp = 2).use { relay ->
      relay.store(filler(1, 100), filler(2, 200), filler(3, 300))
      relay.serveOneConnection()
      val asked = AtomicInteger()
      val ingress =
        ingress(
          Connections(relay.url),
          RecordingSink { ApprovalAccept.RECORDED },
          approvalsAwaited = { asked.incrementAndGet() == 1 },
        )
      ingress.runUntil { asked.get() == 2 && "${ApprovalIngress.PAGE_SUBSCRIPTION_PREFIX}1" in relay.closed }
      assertEquals("the replay's REQ and one page", 2, relay.requests.size)
      ingress.close()
    }

  @Test
  fun anApprovalPublishedDuringAWalkArrivesOnTheSubscription() =
    StoredEventRelay(StoredEventRelay.UntilOrder.AT_OR_BEFORE).use { relay ->
      relay.store(filler(1, 100))
      relay.serveOneConnection()
      val published = approvalWrap("g-live", "n".repeat(64), "d".repeat(64), at = 5_000)
      val sink = RecordingSink { ApprovalAccept.RECORDED }
      val asked = AtomicInteger()
      val ingress =
        ingress(
          Connections(relay.url),
          sink,
          approvalsAwaited = {
            if (asked.incrementAndGet() == 1) relay.publish(published)
            true
          },
        )
      ingress.runUntil { sink.seen.any { it.gateId == "g-live" } }
      ingress.close()
    }

  @Test
  fun aNewConnectionWalksAgain() =
    StoredEventRelay(StoredEventRelay.UntilOrder.AT_OR_BEFORE, clamp = 2).use { relay ->
      relay.store(approvalWrap("g-older", "n".repeat(64), "d".repeat(64), at = 100), filler(1, 200), filler(2, 300))
      relay.serveOneConnection()
      relay.serveOneConnection()
      val sink = RecordingSink { ApprovalAccept.DUPLICATE }
      val ingress = ingress(Connections(relay.url, relay.url), sink, approvalsAwaited = { true })
      ingress.runUntil { sink.seen.size == 1 }
      relay.dropConnection()
      ingress.runUntil { sink.seen.size == 2 }
      relay.publish(approvalWrap("g-live", "n".repeat(64), "d".repeat(64), at = 5_000))
      ingress.runUntil { sink.seen.any { it.gateId == "g-live" } }
      assertEquals("the one drop", 1L, ingress.counts().interruptions)
      relay.assertClean()
      ingress.close()
    }

  @Test
  fun aPagedApprovalTheSinkFailsToRecordComesBackOnANewSubscription() =
    StoredEventRelay(StoredEventRelay.UntilOrder.AT_OR_BEFORE, clamp = 2).use { relay ->
      relay.store(approvalWrap("g-older", "n".repeat(64), "d".repeat(64), at = 100), filler(1, 200), filler(2, 300))
      relay.serveOneConnection()
      relay.serveOneConnection()
      val attempts = AtomicInteger()
      val ingress =
        ingress(
          Connections(relay.url, relay.url),
          {
            check(attempts.incrementAndGet() > 1) { "the append failed" }
            ApprovalAccept.RECORDED
          },
          approvalsAwaited = { true },
        )
      ingress.runUntil { ingress.counts().accepted[ApprovalAccept.RECORDED] == 1L }
      assertEquals(1L, ingress.counts().resubscriptions)
      ingress.close()
    }

  @Test
  fun aFailureToAskWhetherApprovalsAreAwaitedResubscribes() =
    StoredEventRelay(StoredEventRelay.UntilOrder.AT_OR_BEFORE).use { relay ->
      relay.store(filler(1, 100))
      relay.serveOneConnection()
      relay.serveOneConnection()
      val asked = AtomicInteger()
      val ingress =
        ingress(
          Connections(relay.url, relay.url),
          RecordingSink { ApprovalAccept.RECORDED },
          approvalsAwaited = {
            check(asked.incrementAndGet() > 1) { "the read failed" }
            true
          },
        )
      ingress.runUntil { ingress.counts().pages == 1L }
      assertEquals(1L, ingress.counts().resubscriptions)
      ingress.close()
    }

  @Test
  fun aRelayThatRefusesAPageEndsTheWalkCountedAndKeepsTheSubscription() =
    FakeRelay().use { relay ->
      val live = approvalWrap("g-live", "n".repeat(64), "d".repeat(64), at = 5_000)
      relay.serve { session ->
        session.nextClientText(5_000) ?: error("no REQ")
        val id = ApprovalIngress.SUBSCRIPTION_ID
        session.sendText("[\"EVENT\",\"$id\"," + filler(1, 100).serialize() + "]")
        session.sendText("[\"EOSE\",\"$id\"]")
        val page = session.nextClientText(5_000) ?: error("no page")
        check(page.startsWith("[\"REQ\",\"${ApprovalIngress.PAGE_SUBSCRIPTION_PREFIX}1\",")) { "unexpected $page" }
        session.sendText("[\"CLOSED\",\"${ApprovalIngress.PAGE_SUBSCRIPTION_PREFIX}1\",\"restricted: no\"]")
        session.sendText("[\"EVENT\",\"$id\"," + live.serialize() + "]")
        session.nextClientText(10_000)
      }
      val sink = RecordingSink { ApprovalAccept.RECORDED }
      val ingress = ingress(Connections(relay.url), sink, approvalsAwaited = { true })
      ingress.runUntil { sink.seen.size == 1 }
      assertEquals(1L, ingress.counts().stalledWalks)
      assertEquals(0L, ingress.counts().interruptions)
      relay.assertScriptClean()
      ingress.close()
    }

  @Test
  fun aLowStampedWrapArrivingBetweenPagesDoesNotMoveTheWalk() {
    for (order in StoredEventRelay.UntilOrder.entries) {
      StoredEventRelay(order, clamp = 2).use { relay ->
        val older = approvalWrap("g-older", "n".repeat(64), "d".repeat(64), at = 100)
        relay.store(older, filler(1, 200), filler(2, 300), filler(3, 400), filler(4, 500))
        relay.serveOneConnection()
        val sink = RecordingSink { ApprovalAccept.RECORDED }
        val asked = AtomicInteger()
        val ingress =
          ingress(
            Connections(relay.url),
            sink,
            approvalsAwaited = {
              // Asked at a page's EOSE, before its CLOSE, so this reaches the page and the subscription.
              if (asked.incrementAndGet() == 2) relay.publish(filler(5, 1))
              true
            },
          )
        ingress.runUntil { sink.seen.any { it.gateId == "g-older" } }
        assertEquals("under $order", 0L, ingress.counts().stalledWalks)
        ingress.close()
      }
    }
  }

  @Test
  fun aMailboxPastTheConnectionsQueueIsWalkedWithoutBreakingTheConnection() =
    StoredEventRelay(StoredEventRelay.UntilOrder.AT_OR_BEFORE, clamp = 5_000).use { relay ->
      assertTrue(ApprovalIngress.PAGE_LIMIT < RelayConnection.MAX_QUEUED_MESSAGES)
      val wraps = RelayConnection.MAX_QUEUED_MESSAGES * 2
      relay.store(approvalWrap("g-older", "n".repeat(64), "d".repeat(64), at = 100))
      relay.store(*Array(wraps) { filler(it + 1, 1_000L + it) })
      relay.serveOneConnection()
      val sink = RecordingSink { ApprovalAccept.RECORDED }
      val ingress = ingress(Connections(relay.url), sink, approvalsAwaited = { true })
      ingress.runUntil { sink.seen.isNotEmpty() }
      assertEquals(0L, ingress.counts().interruptions)
      assertTrue(
        "every REQ carries the limit: ${relay.requests.filterNot { "\"limit\":${ApprovalIngress.PAGE_LIMIT}" in it }}",
        relay.requests.all { "\"limit\":${ApprovalIngress.PAGE_LIMIT}" in it },
      )
      val lead = Bip340.xonlyPubkeyHex(LEAD_SECRET)
      assertTrue(
        "every REQ asks for wraps to the lead alone: ${relay.requests}",
        relay.requests.all { "\"kinds\":[${Nip59.GIFT_WRAP_KIND}]" in it && "\"#p\":[\"$lead\"]" in it },
      )
      ingress.close()
    }

  @Test
  fun anEoseRepeatedAfterAWalkHasEndedChangesNothing() =
    FakeRelay().use { relay ->
      relay.serve { session ->
        session.nextClientText(5_000) ?: error("no REQ")
        val id = ApprovalIngress.SUBSCRIPTION_ID
        val page = "${ApprovalIngress.PAGE_SUBSCRIPTION_PREFIX}1"
        session.sendText("[\"EVENT\",\"$id\"," + filler(1, 100).serialize() + "]")
        session.sendText("[\"EOSE\",\"$id\"]")
        session.nextClientText(5_000) ?: error("no page")
        session.sendText("[\"EVENT\",\"$page\"," + filler(1, 100).serialize() + "]")
        session.sendText("[\"EOSE\",\"$page\"]")
        session.sendText("[\"EOSE\",\"$page\"]")
        session.nextClientText(10_000)
      }
      val ingress = ingress(Connections(relay.url), RecordingSink { ApprovalAccept.RECORDED }, approvalsAwaited = { true })
      ingress.runUntil { ingress.counts().malformed == 2L }
      repeat(6) { ingress.step(Duration.ofMillis(50)) }
      assertEquals(0L, ingress.counts().stalledWalks)
      assertEquals(1L, ingress.counts().pages)
      relay.assertScriptClean()
      ingress.close()
    }

  @Test
  fun aRepeatedEoseForTheSubscriptionDoesNotEndThePageInProgress() =
    FakeRelay().use { relay ->
      relay.serve { session ->
        session.nextClientText(5_000) ?: error("no REQ")
        val id = ApprovalIngress.SUBSCRIPTION_ID
        session.sendText("[\"EVENT\",\"$id\"," + filler(1, 100).serialize() + "]")
        session.sendText("[\"EOSE\",\"$id\"]")
        session.nextClientText(5_000) ?: error("no page")
        session.sendText("[\"EOSE\",\"$id\"]")
        session.nextClientText(10_000)
      }
      val ingress = ingress(Connections(relay.url), RecordingSink { ApprovalAccept.RECORDED }, approvalsAwaited = { true })
      ingress.runUntil { ingress.counts().pages == 1L }
      repeat(6) { ingress.step(Duration.ofMillis(50)) }
      assertEquals(1L, ingress.counts().pages)
      assertEquals(0L, ingress.counts().stalledWalks)
      relay.assertScriptClean()
      ingress.close()
    }

  @Test
  fun anEoseOrClosedForAPageNobodyAskedForChangesNothing() =
    FakeRelay().use { relay ->
      relay.serve { session ->
        session.nextClientText(5_000) ?: error("no REQ")
        val page = "${ApprovalIngress.PAGE_SUBSCRIPTION_PREFIX}1"
        // A relay's EOSE and CLOSED for the page before any page was asked for.
        session.sendText("[\"EOSE\",\"$page\"]")
        session.sendText("[\"CLOSED\",\"$page\",\"restricted: no\"]")
        session.sendText("[\"EOSE\",\"${ApprovalIngress.SUBSCRIPTION_ID}\"]")
        session.nextClientText(10_000)
      }
      val asked = AtomicInteger()
      val ingress =
        ingress(
          Connections(relay.url),
          RecordingSink { ApprovalAccept.RECORDED },
          approvalsAwaited = {
            asked.incrementAndGet()
            true
          },
        )
      repeat(6) { ingress.step(Duration.ofMillis(50)) }
      assertEquals(0L, ingress.counts().stalledWalks)
      assertEquals("an empty replay has nothing to walk back from", 0, asked.get())
      ingress.close()
    }

  @Test
  fun closeZeroesTheLeadKeyAndEndsTheSteps() {
    val key = SecretKeyHex.ofHexString(LEAD_SECRET)
    val ingress =
      ApprovalIngress(
        { error("no connection expected") },
        Duration.ofSeconds(1),
        RelayAuth.None,
        ReconnectingSubscription.Backoff(Duration.ofMillis(10), Duration.ofMillis(10)),
        ReconnectingSubscription.Backoff(Duration.ofMillis(10), Duration.ofMillis(10)),
        key,
        { false },
      ) {
        ApprovalAccept.RECORDED
      }
    ingress.close()
    // A zeroed holder no longer decodes: its NUL characters are not hex.
    assertThrows(IllegalArgumentException::class.java) { key.useKeyBytes { it.size } }
    assertEquals(false, ingress.step(Duration.ZERO))
  }

  @Test
  fun anApprovalOverTheRelayReleasesARealHostsGateAndItsReplayAddsNothing() =
    FakeRelay().use { relay ->
      val store = SqliteStore(tmp.newFolder().absolutePath, componentId = "lead")
      val host = leadWithAnOpenGate(store)
      val wrap = approvalOfTheOpenGate(store)
      relay.replays(wrap, wrap)
      val ingress = ingress(Connections(relay.url), host::injectApproval)
      ingress.runUntil { ingress.counts().accepted.values.sum() == 2L }
      assertEquals(1L, ingress.counts().accepted[ApprovalAccept.RELEASED])
      val rows = store.readAll()
      assertEquals("one approval row: the replay adds none", 1, rows.count { it.kind == LeadKinds.APPROVAL_RECORDED })
      assertEquals("one release", 1, rows.count { it.kind == KIND_GATE_RELEASED })
      ingress.close()
      store.close()
    }

  @Test
  fun anApprovalCrowdedOutOfTheReplayReleasesARealHostsGateAndTheWalkThenEnds() =
    StoredEventRelay(StoredEventRelay.UntilOrder.AT_OR_BEFORE, clamp = 2).use { relay ->
      val store = SqliteStore(tmp.newFolder().absolutePath, componentId = "lead")
      val host = leadWithAnOpenGate(store)
      relay.store(approvalOfTheOpenGate(store, at = 100), filler(1, 200), filler(2, 300), filler(3, 400), filler(4, 500))
      relay.store(filler(5, 50), filler(6, 40))
      relay.serveOneConnection()
      val ingress = ingress(Connections(relay.url), host::injectApproval, approvalsAwaited = host::approvalsAwaited)
      ingress.runUntil { ingress.counts().accepted[ApprovalAccept.RELEASED] == 1L }
      repeat(20) { ingress.step(Duration.ofMillis(50)) }
      assertEquals("one release", 1, store.readAll().count { it.kind == KIND_GATE_RELEASED })
      assertEquals(
        "nothing is awaited after the release, so no page goes below the approval: ${relay.requests}",
        4,
        relay.requests.size,
      )
      ingress.close()
      store.close()
    }

  /** A ticket lead with [store] as its journal, whose gate is open and whose one approver is the
   * test's, driven until it waits on that approval. */
  private fun leadWithAnOpenGate(store: SqliteStore): AgentHost<*> {
    val dir = tmp.newFolder()
    File(dir, "ticket.txt").writeText("t1\n")
    val auth =
      LeadAuth(
        AllowList(listOf(Principal("operator", "authorizer", listOf(SchemeKey("bip340", APPROVER_PUB))))),
        Bip340ApprovalVerifier,
        oneOfOne("operator"),
      )
    val host =
      ticketLead(
        store = store,
        cognition = ScriptedCognition(),
        podRunner = FakePodRunner(),
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        leadAuth = auth,
        timers = TimerService { _, _ -> },
      )
    host.driveUntilQuiescent()
    return host
  }

  /** A wrap carrying the approval of the gate [leadWithAnOpenGate] opened. */
  private fun approvalOfTheOpenGate(store: SqliteStore, at: Long = 1_700_000_000): NostrEvent {
    val gateId = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    // The nonce the gate-open minted, as the journal holds it: what a notice would carry.
    val issued =
      store.readAll().single { it.kind == LeadKinds.NONCE_ISSUED }.let { Json.parseToJsonElement(it.payloadJson).jsonObject }
    assertEquals(gateId, issued.getValue("gateId").jsonPrimitive.content)
    return approvalWrap(
      gateId,
      issued.getValue("nonce").jsonPrimitive.content,
      issued.getValue("payloadDigest").jsonPrimitive.content,
      at = at,
    )
  }

  private fun approvalWrap(
    gateId: String,
    nonce: String,
    digest: String,
    lead: RecipientKey = RecipientKey.of(Bip340.xonlyPubkeyHex(LEAD_SECRET)),
    at: Long = 1_700_000_000,
  ): NostrEvent {
    // Signed the way an approver's client signs, so the end-to-end cell runs that output through the
    // lead's classifier.
    val carrier = ApprovalSigning.sign(GateOpenNotice(gateId, digest, nonce, "the artifact"), bytes(APPROVER_SECRET), AUX)
    val encoding = encodeApproval(bytes(APPROVER_SECRET), lead, carrier, at, 1_699_999_000, AUX, AUX)
    return (encoding as GiftWrapEncoding.Wrapped).event
  }

  /** A wrap to the lead by its kind and tag alone, which does not open: it takes up a relay's window. */
  private fun filler(n: Int, at: Long) =
    NostrEvent(
      id = "%064x".format(n),
      pubkey = "00".repeat(32),
      createdAt = at,
      kind = Nip59.GIFT_WRAP_KIND,
      tags = listOf(listOf("p", Bip340.xonlyPubkeyHex(LEAD_SECRET))),
      content = "",
      sig = "00".repeat(64),
    )

  private fun rumorWrap(rumor: Rumor): NostrEvent {
    val encoding =
      Nip59.wrap(
        senderKey = bytes(APPROVER_SECRET),
        recipient = RecipientKey.of(Bip340.xonlyPubkeyHex(LEAD_SECRET)),
        rumor = rumor,
        sealCreatedAt = 1_699_999_000,
        wrapCreatedAt = 1_700_000_000,
        sealAuxRandHex = AUX,
        wrapAuxRandHex = AUX,
      )
    return (encoding as GiftWrapEncoding.Wrapped).event
  }

  private companion object {
    const val APPROVER_SECRET = "0000000000000000000000000000000000000000000000000000000000000003"
    const val LEAD_SECRET = "0000000000000000000000000000000000000000000000000000000000000005"
    const val OTHER_SECRET = "0000000000000000000000000000000000000000000000000000000000000007"
    val APPROVER_PUB: String = Bip340.xonlyPubkeyHex(APPROVER_SECRET)
    val AUX = "0".repeat(64)

    fun bytes(hex: String) = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
  }
}
