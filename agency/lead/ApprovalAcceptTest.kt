package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.shared.auth.ApprovalEvidence
import com.geekinasuit.agency.shared.auth.ApprovalVerifier
import com.geekinasuit.agency.shared.auth.committedPreimage
import com.geekinasuit.agency.shared.auth.oneOfOne
import com.geekinasuit.agency.shared.journal.ChainBrokenException
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import java.sql.DriverManager
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The approval accept boundary ([AgentHost.injectApproval]), each cell on two workflows: the ticket
 * workflow, and [GateWorkflow], which is not it. Under [AUTH] only a signature equal to [GENUINE]
 * verifies, so a forgery that names the genuine key is rejected while the genuine approval verifies.
 *
 * Every cell that drops a candidate for one of its fields also shows that a candidate differing in
 * that field is journaled, so a boundary that dropped everything fails. The consumed-nonce cell drops
 * for the journal's state, not a field; the cells before it journal the same candidate on the open
 * nonce. The cells run on one thread: the lock is argued, not exercised, and the fault points stand
 * in for the loop thread's appends between check and append.
 */
class ApprovalAcceptTest {

  @get:Rule val tmp = TemporaryFolder()

  private val rigs = mutableListOf<Rig>()

  @After
  fun closeStores() {
    for (r in rigs) r.store.close()
  }

  @Test
  fun aVerifiedApprovalOfTheOpenNonceIsJournaledBeforeInjectReturns() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      assertEquals(ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
      val rows = rig.approvalRows()
      assertEquals("one approval row", 1, rows.size)
      assertEquals("under the authorization layer's origin", ORIGIN_AUTH_LAYER, rows.single().origin)
      val folded = rig.host().refold().host
      assertEquals(
        "a cold fold counts it",
        listOf("operator"),
        folded.verifiedApprovals[nonce.gateId].orEmpty().map { it.principalId },
      )
      assertEquals("and rejects nothing", emptyList<Pair<Long, String>>(), folded.unverifiedApprovals)
    }

  @Test
  fun aReturnedDriveDoesNotStopTheBoundary() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      host.driveUntilQuiescent()
      assertEquals(ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
    }

  @Test
  fun aCrashAfterTheAppendLeavesTheApprovalForTheRestartedHost() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val crash = FaultInjector { if (it == ApprovalAcceptor.FAULT_AFTER_APPEND) throw RuntimeException("crash") }
      assertThrows(RuntimeException::class.java) { rig.host(faults = crash).injectApproval(candidate(nonce)) }
      val folded = rig.host().driveUntilQuiescent().host
      assertEquals(1, folded.verifiedApprovals[nonce.gateId].orEmpty().size)
    }

  @Test
  fun aCrashBeforeTheAppendJournalsNothing() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val crash = FaultInjector { if (it == ApprovalAcceptor.FAULT_BEFORE_APPEND) throw RuntimeException("crash") }
      assertThrows(RuntimeException::class.java) { rig.host(faults = crash).injectApproval(candidate(nonce)) }
      assertEquals(0, rig.approvalRows().size)
      assertEquals("positive control", ApprovalAccept.RECORDED, rig.host().injectApproval(candidate(nonce)))
    }

  @Test
  fun aCandidateNotNamingTheOpenNonceOfAnOpenGateIsDropped() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      assertDropped(rig, ApprovalAccept.NOT_OPEN, host.injectApproval(candidate(nonce, gateId = "${nonce.gateId}-x")))
      assertDropped(rig, ApprovalAccept.NOT_OPEN, host.injectApproval(candidate(nonce, nonce = "${nonce.nonce}-x")))
      assertEquals("positive control", ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
    }

  @Test
  fun aCandidateNamingAConsumedNonceIsDropped() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      host.injectApproval(candidate(nonce, gateId = "prime-the-view"))
      rig.store.append(HostKinds.NONCE_CONSUMED, buildJsonObject { put("nonce", nonce.nonce) }, ORIGIN_SUBSTRATE)
      assertDropped(rig, ApprovalAccept.NOT_OPEN, host.injectApproval(candidate(nonce)))
    }

  @Test
  fun aCandidateNamingTheOpenNonceWithAnotherDigestIsDropped() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      assertDropped(rig, ApprovalAccept.WRONG_DIGEST, host.injectApproval(candidate(nonce, digest = "2".repeat(64))))
      assertEquals("positive control", ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
    }

  @Test
  fun aRedeliveredApprovalIsADuplicateEvenWrappedInANewCarrier() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      assertEquals(ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
      assertEquals(ApprovalAccept.DUPLICATE, host.injectApproval(candidate(nonce)))
      assertEquals(ApprovalAccept.DUPLICATE, host.injectApproval(candidate(nonce, carrier = "carrier-2")))
      assertEquals(ApprovalAccept.DUPLICATE, rig.host().injectApproval(candidate(nonce)))
      assertEquals(1, rig.approvalRows().size)
    }

  @Test
  fun aForgeryNamingTheGenuineKeyIsRejectedAndTheGenuineApprovalStillCounts() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      assertDropped(rig, ApprovalAccept.REJECTED, host.injectApproval(candidate(nonce, signature = "forged")))
      assertEquals(ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
      assertEquals(1, rig.host().refold().host.verifiedApprovals[nonce.gateId].orEmpty().size)
    }

  @Test
  fun aCandidateSignedByAKeyNotInTheAllowListIsRejected() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      assertDropped(rig, ApprovalAccept.REJECTED, host.injectApproval(candidate(nonce, publicKey = "pk-stranger")))
      assertEquals("positive control", ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
    }

  @Test
  fun aCarriersKeysThatNothingSignsNeverReachTheJournal() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val genuine = candidate(nonce)
      val padded = genuine.copy(evidence = JsonObject(genuine.evidence + ("padding" to JsonPrimitive("x".repeat(64)))))
      assertEquals(ApprovalAccept.RECORDED, rig.host().injectApproval(padded))
      val row = Json.parseToJsonElement(rig.approvalRows().single().payloadJson).jsonObject
      assertEquals("the evidence as it re-serializes", genuine.evidence, row.getValue("evidence"))
    }

  @Test
  fun aGenuineRowForTheLongestTicketRefFitsWellUnderTheBound() {
    // The ticket workflow's gate id is its kind and a ticket ref of at most 128 chars; the gate
    // workflow's is fixed. Half the bound is left for keys and signatures longer than these.
    val rig = TicketRig("r".repeat(128)).also { rigs += it }
    val nonce = rig.openGate()
    assertEquals(ApprovalAccept.RECORDED, rig.host().injectApproval(candidate(nonce, carrier = "c".repeat(64))))
    val row = rig.approvalRows().single().payloadJson
    assertTrue("${row.length} chars", row.length * 2 < ApprovalAcceptor.MAX_APPROVAL_ROW_CHARS)
  }

  @Test
  fun anOversizedRowIsDroppedAndTheGenuineApprovalStillLands() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      val padded = candidate(nonce, carrier = "c".repeat(ApprovalAcceptor.MAX_APPROVAL_ROW_CHARS))
      assertDropped(rig, ApprovalAccept.OVERSIZED, host.injectApproval(padded))
      assertEquals("the genuine approval is not its duplicate", ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
    }

  @Test
  fun aCandidateWhoseEvidenceDoesNotParseIsRejected() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      val empty = candidate(nonce).copy(evidence = JsonObject(emptyMap()))
      assertDropped(rig, ApprovalAccept.REJECTED, host.injectApproval(empty))
      assertEquals("positive control", ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
    }

  @Test
  fun aNonceIssuedAfterTheViewWasPrimedIsSeenAtTheNextInject() =
    onBothWorkflows { rig ->
      val host = rig.host()
      assertDropped(rig, ApprovalAccept.NOT_OPEN, host.injectApproval(candidate(UNISSUED)))
      val nonce = rig.openGate()
      assertEquals(ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
    }

  @Test
  fun aNonceClosedBetweenClassifyAndAppendLandsOnlyThatAcceptsRow() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val close = FaultInjector {
        if (it == ApprovalAcceptor.FAULT_BEFORE_APPEND) {
          rig.store.append(HostKinds.NONCE_CONSUMED, buildJsonObject { put("nonce", nonce.nonce) }, ORIGIN_SUBSTRATE)
        }
      }
      val before = rig.store.readAll().size
      val host = rig.host(faults = close)
      assertEquals(ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
      assertEquals(
        listOf(HostKinds.NONCE_CONSUMED, HostKinds.APPROVAL_RECORDED),
        rig.store.readAll().drop(before).map { it.kind },
      )
      assertEquals("the next accept sees it closed", ApprovalAccept.NOT_OPEN, host.injectApproval(candidate(nonce)))
    }

  @Test
  fun afterTheLoopExitsAnInjectThrowsAndAppendsNothing() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      val loop = Thread { host.runLoop() }
      loop.start()
      host.shutdown()
      loop.join(10_000)
      assertFalse("the loop exited", loop.isAlive)
      assertThrows(IllegalStateException::class.java) { host.injectApproval(candidate(nonce)) }
      assertEquals(0, rig.approvalRows().size)
      assertEquals("positive control", ApprovalAccept.RECORDED, rig.host().injectApproval(candidate(nonce)))
    }

  @Test
  fun aChainFaultInTheTailStopsTheBoundaryAndIsEscalated() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      host.injectApproval(candidate(nonce, gateId = "prime-the-view"))
      // The seq is read before the append: the store's connection keeps a read open until its next
      // write commits (#297), and the edit below must land after that.
      val seq = rig.store.chainHead().first + 1
      rig.store.append(HostKinds.STATUS_WRITTEN, buildJsonObject { put("status", "s") }, ORIGIN_SUBSTRATE)
      DriverManager.getConnection("jdbc:sqlite:${rig.dir.absolutePath}/journal.db").use { c ->
        c.createStatement().use { st -> st.executeUpdate("UPDATE journal SET payload='{\"status\":\"t\"}' WHERE seq=$seq") }
      }
      assertThrows(ChainBrokenException::class.java) { host.injectApproval(candidate(nonce)) }
      val refused = assertThrows(IllegalStateException::class.java) { host.injectApproval(candidate(nonce)) }
      assertTrue("names why", "approval boundary stopped" in refused.message!!)
      assertEquals(
        "one escalation",
        1,
        rig.rawKindsAndPayloads().count { (kind, payload) ->
          kind == HostKinds.ESCALATED && "approval boundary stopped" in payload
        },
      )
      assertEquals("no approval row", 0, rig.rawKindsAndPayloads().count { it.first == HostKinds.APPROVAL_RECORDED })
    }

  private fun assertDropped(rig: Rig, expected: ApprovalAccept, actual: ApprovalAccept) {
    assertEquals(expected, actual)
    assertEquals("$expected appends no approval row", 0, rig.approvalRows().size)
  }

  private fun onBothWorkflows(cell: (Rig) -> Unit) {
    for (rig in listOf(TicketRig(), GateRig())) {
      rigs += rig
      try {
        cell(rig)
      } catch (e: Throwable) {
        throw AssertionError("on ${rig.name}: ${e.message}", e)
      }
    }
  }

  /** One workflow's host over its own store, under [AUTH]. */
  private abstract inner class Rig(val name: String) {
    val dir: File = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")

    abstract fun host(faults: FaultInjector = FaultInjector.NONE): AgentHost<*>

    /** Drives a host until its gate is open, and returns the nonce minted for it. */
    fun openGate(): IssuedNonce = host().driveUntilQuiescent().host.issuedNonces.values.single()

    fun approvalRows(): List<JournalEntry> = store.readAll().filter { it.kind == HostKinds.APPROVAL_RECORDED }

    /** Every row's kind and payload, read past the chain check, for a journal that no longer verifies. */
    fun rawKindsAndPayloads(): List<Pair<String, String>> =
      DriverManager.getConnection("jdbc:sqlite:${dir.absolutePath}/journal.db").use { c ->
        c.createStatement().use { st ->
          st.executeQuery("SELECT kind, payload FROM journal ORDER BY seq").use { rs ->
            buildList { while (rs.next()) add(rs.getString(1) to rs.getString(2)) }
          }
        }
      }
  }

  private inner class TicketRig(ref: String = "t1") : Rig("the ticket workflow") {
    init {
      File(dir, "ticket.txt").writeText("$ref\n")
    }

    override fun host(faults: FaultInjector): AgentHost<*> =
      ticketLead(
        store = store,
        cognition = ScriptedCognition(),
        podRunner = FakePodRunner(),
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        leadAuth = AUTH,
        timers = TIMERS,
        faults = faults,
      )
  }

  private inner class GateRig : Rig("a workflow that is not the ticket workflow") {
    private val evidence = File(dir, "evidence.txt").apply { writeText("approve this\n") }

    override fun host(faults: FaultInjector): AgentHost<*> =
      AgentHost(
        store = store,
        cognition = ProposeTheGate,
        podRunner = FakePodRunner(),
        podSpec = PodSpec.fixture(),
        workflow = GateWorkflow(evidence),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        leadAuth = AUTH,
        timers = TIMERS,
        faults = faults,
      )
  }

  /** A candidate approving [n], by the allow-listed operator unless a field is overridden. The
   * evidence's own gate, digest and nonce agree with the candidate's. */
  private fun candidate(
    n: IssuedNonce,
    gateId: String = n.gateId,
    nonce: String = n.nonce,
    digest: String = n.payloadDigest,
    publicKey: String = "pk-operator",
    signature: String = GENUINE,
    carrier: String = "carrier-1",
  ) =
    ApprovalCandidate(
      gateId,
      nonce,
      digest,
      ApprovalEvidence(
          schemeId = "test",
          publicKey = publicKey,
          signature = signature,
          carrierArtifactId = carrier,
          gateId = gateId,
          payloadDigest = digest,
          nonce = nonce,
          signedPreimage = committedPreimage(publicKey, gateId, digest, nonce),
        )
        .toJson(),
    )

  private companion object {
    const val GENUINE = "sig-genuine"

    /** [ceremonyAuth]'s allow-list and quorum, with a verifier that accepts only [GENUINE]. */
    val AUTH: LeadAuth =
      LeadAuth(ceremonyAuth().allowList, ApprovalVerifier { _, _, signature, _ -> signature == GENUINE }, oneOfOne("operator"))

    /** Fires nothing; a ceremony host refuses only [TimerService.NOOP]. */
    val TIMERS = TimerService { _, _ -> }

    /** A nonce no journal here issues. */
    val UNISSUED = IssuedNonce(nonce = "n-unissued", gateId = "g-unissued", payloadDigest = "3".repeat(64), issuedSeq = 0)
  }
}
