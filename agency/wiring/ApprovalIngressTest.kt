package com.geekinasuit.agency.wiring

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
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The approval ingress over a scripted relay ([FakeRelay], one connection per relay): what reaches the
 * accept boundary, what is dropped as malformed, the resubscription after the boundary throws, and one
 * run end to end into a real host, whose gate the approval releases.
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
  ) =
    ApprovalIngress(
      newConnection = connections::next,
      connectTimeout = Duration.ofSeconds(3),
      auth = RelayAuth.None,
      backoff = ReconnectingSubscription.Backoff(Duration.ofMillis(10), Duration.ofMillis(50)),
      resubscribeBackoff = resubscribeBackoff,
      leadKey = SecretKeyHex.ofHexString(LEAD_SECRET),
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
      ingress.start()
      val deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos()
      while (sink.seen.isEmpty() && System.nanoTime() < deadline) Thread.sleep(20)
      assertEquals(1, sink.seen.size)
      ingress.close()
      assertTrue(
        "the worker ended",
        Thread.getAllStackTraces().keys.none { it.name == "approval-ingress" && it.isAlive },
      )
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
      val dir = tmp.newFolder()
      File(dir, "ticket.txt").writeText("t1\n")
      val store = SqliteStore(dir.absolutePath, componentId = "lead")
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
      val gateId = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
      host.driveUntilQuiescent()
      // The nonce the gate-open minted, as the journal holds it: what a notice would carry.
      val issued =
        store.readAll().single { it.kind == LeadKinds.NONCE_ISSUED }.let { Json.parseToJsonElement(it.payloadJson).jsonObject }
      assertEquals(gateId, issued.getValue("gateId").jsonPrimitive.content)
      val wrap = approvalWrap(gateId, issued.getValue("nonce").jsonPrimitive.content, issued.getValue("payloadDigest").jsonPrimitive.content)
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

  private fun approvalWrap(
    gateId: String,
    nonce: String,
    digest: String,
    lead: RecipientKey = RecipientKey.of(Bip340.xonlyPubkeyHex(LEAD_SECRET)),
  ): NostrEvent {
    // Signed the way an approver's client signs, so the end-to-end cell runs that output through the
    // lead's classifier.
    val carrier = ApprovalSigning.sign(GateOpenNotice(gateId, digest, nonce, "the artifact"), bytes(APPROVER_SECRET), AUX)
    val encoding = encodeApproval(bytes(APPROVER_SECRET), lead, carrier, 1_700_000_000, 1_699_999_000, AUX, AUX)
    return (encoding as GiftWrapEncoding.Wrapped).event
  }

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
