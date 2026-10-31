package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.shared.auth.AllowList
import com.geekinasuit.agency.shared.auth.ApprovalEvidence
import com.geekinasuit.agency.shared.auth.ApprovalVerifier
import com.geekinasuit.agency.shared.auth.Principal
import com.geekinasuit.agency.shared.auth.QuorumGroup
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.SignerLeaf
import com.geekinasuit.agency.shared.auth.committedPreimage
import com.geekinasuit.agency.shared.journal.ChainBrokenException
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
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
 * nonce. A rejected attempt is journaled once per claimed key on a nonce, and the allowance cells
 * show the next attempt for that key is not. The cells run on one thread: the lock is argued,
 * not exercised, and the fault points stand in for the loop thread's appends between check and append.
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
  fun aGenuineApprovalIsAcceptedAfterItsKeysAllowanceIsUsed() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      assertEquals(ApprovalAccept.REJECTED, host.injectApproval(candidate(nonce, signature = "forged")))
      assertEquals(ApprovalAccept.REJECTED_OVER_ALLOWANCE, host.injectApproval(candidate(nonce, signature = "forged-2")))
      assertEquals("one rejected row", 1, rig.approvalRows().size)
      assertEquals(ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
      val folded = rig.host().refold().host
      assertEquals(listOf("operator"), folded.verifiedApprovals[nonce.gateId].orEmpty().map { it.principalId })
      assertEquals(1, folded.unverifiedApprovals.size)
    }

  @Test
  fun aRejectedRowNamesNoPrincipalAndCountsTowardNothing() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      assertEquals(ApprovalAccept.REJECTED, rig.host().injectApproval(candidate(nonce, signature = "forged")))
      val row = Json.parseToJsonElement(rig.approvalRows().single().payloadJson).jsonObject
      assertEquals(JsonPrimitive(LeadAuth.UNLISTED_PRINCIPAL_ID), row.getValue("principalId"))
      val claimed = row.getValue("evidence").jsonObject.getValue("publicKey")
      assertEquals("the key it claims stays in its evidence", JsonPrimitive("pk-operator"), claimed)
      val folded = rig.host().refold().host
      assertEquals(emptyList<VerifiedApproval>(), folded.verifiedApprovals[nonce.gateId].orEmpty())
      assertEquals(1, folded.unverifiedApprovals.size)
    }

  @Test
  fun eachClaimedKeyAndTheUnlistedBucketHasItsOwnAllowance() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      for (key in listOf("pk-operator", "pk-second", "pk-stranger")) {
        assertEquals(key, ApprovalAccept.REJECTED, host.injectApproval(candidate(nonce, publicKey = key, signature = "forged")))
      }
      for (key in listOf("pk-operator", "pk-second", "pk-stranger", "pk-stranger-2")) {
        val again = host.injectApproval(candidate(nonce, publicKey = key, signature = "forged-2"))
        assertEquals(key, ApprovalAccept.REJECTED_OVER_ALLOWANCE, again)
      }
      assertEquals(3, rig.approvalRows().size)
    }

  @Test
  fun aSplitNonceFloodAddsOneRowAndUsesNoListedKeysAllowance() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      val flood = (0 until 20).map { host.injectApproval(candidate(nonce, evidenceNonce = "${nonce.nonce}-$it")) }
      assertEquals(listOf(ApprovalAccept.REJECTED) + List(19) { ApprovalAccept.REJECTED_OVER_ALLOWANCE }, flood)
      val forged = host.injectApproval(candidate(nonce, signature = "forged"))
      assertEquals("the operator's own allowance is unused", ApprovalAccept.REJECTED, forged)
      assertEquals(ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
      assertEquals(3, rig.approvalRows().size)
    }

  @Test
  fun theAllowanceTallySurvivesARestart() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      assertEquals(ApprovalAccept.REJECTED, rig.host().injectApproval(candidate(nonce, signature = "forged")))
      val restarted = rig.host()
      assertEquals(ApprovalAccept.REJECTED_OVER_ALLOWANCE, restarted.injectApproval(candidate(nonce, signature = "forged-2")))
      val second = restarted.injectApproval(candidate(nonce, publicKey = "pk-second", signature = "forged"))
      assertEquals("positive control", ApprovalAccept.REJECTED, second)
      assertEquals(2, rig.approvalRows().size)
    }

  @Test
  fun aRejectedRowIsBoundAsItIsJournaled() =
    onBothWorkflows { rig ->
      // The rejected row names the sentinel, longer than "operator": a forgery sized so its row
      // would fit under the operator's id does not fit under the sentinel's.
      val nonce = rig.openGate()
      val host = rig.host()
      val grow = LeadAuth.UNLISTED_PRINCIPAL_ID.length - "operator".length
      val oneCharCarrier = rowUnderOperator(candidate(nonce, signature = FORGED_SAME_LENGTH, carrier = "c")).length
      // Under the sentinel, the row is one char over the bound.
      val target = ApprovalAcceptor.MAX_APPROVAL_ROW_CHARS + 1 - grow
      val carrier = "c".repeat(target - oneCharCarrier + 1)
      val forged = candidate(nonce, signature = FORGED_SAME_LENGTH, carrier = carrier)
      assertEquals(target, rowUnderOperator(forged).length)
      assertDropped(rig, ApprovalAccept.OVERSIZED, host.injectApproval(forged))
      assertEquals("the same size verified fits", ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce, carrier = carrier)))
    }

  @Test
  fun aCandidateSignedByAKeyNotInTheAllowListIsRejectedOnce() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      assertEquals(ApprovalAccept.REJECTED, host.injectApproval(candidate(nonce, publicKey = "pk-stranger")))
      assertEquals(ApprovalAccept.REJECTED_OVER_ALLOWANCE, host.injectApproval(candidate(nonce, publicKey = "pk-stranger")))
      assertEquals(1, rig.approvalRows().size)
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
  fun aFloodOfEvidenceThatDoesNotParseAddsOneRow() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      val flood = (0 until 20).map { host.injectApproval(candidate(nonce).copy(evidence = buildJsonObject { put("junk", it) })) }
      assertEquals(listOf(ApprovalAccept.REJECTED) + List(19) { ApprovalAccept.REJECTED_OVER_ALLOWANCE }, flood)
      val row = Json.parseToJsonElement(rig.approvalRows().single().payloadJson).jsonObject
      assertEquals("the carrier's object, signed by nothing, is not journaled", JsonObject(emptyMap()), row.getValue("evidence"))
      assertEquals("positive control", ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
    }

  @Test
  fun aNonceThatOpensAgainKeepsItsTally() =
    onBothWorkflows { rig ->
      // A newer nonce for the same gate and digest shadows the open one; consuming it opens the
      // older one again.
      val older = rig.openGate()
      val host = rig.host()
      assertEquals(ApprovalAccept.REJECTED, host.injectApproval(candidate(older, signature = "forged")))
      val newer = older.copy(nonce = "${older.nonce}-newer")
      rig.store.append(
        HostKinds.NONCE_ISSUED,
        buildJsonObject {
          put("nonce", newer.nonce)
          put("gateId", newer.gateId)
          put("payloadDigest", newer.payloadDigest)
        },
        ORIGIN_SUBSTRATE,
      )
      assertDropped(rig, ApprovalAccept.NOT_OPEN, host.injectApproval(candidate(older, signature = "forged-2")), rows = 1)
      rig.store.append(HostKinds.NONCE_CONSUMED, buildJsonObject { put("nonce", newer.nonce) }, ORIGIN_SUBSTRATE)
      assertEquals(ApprovalAccept.REJECTED_OVER_ALLOWANCE, host.injectApproval(candidate(older, signature = "forged-3")))
      assertEquals(1, rig.approvalRows().size)
    }

  @Test
  fun aPrincipalsTwoKeysEachHaveTheirOwnAllowance() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      for (key in listOf("pk-second", "pk-second-2")) {
        assertEquals(key, ApprovalAccept.REJECTED, host.injectApproval(candidate(nonce, publicKey = key, signature = "forged")))
      }
      assertEquals(2, rig.approvalRows().size)
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

  @Test
  fun twoOfThreeReleasesAtTheSecondApprovalInEitherOrder() {
    for ((first, second) in listOf("pk-operator" to "pk-second", "pk-second" to "pk-operator")) {
      onBothWorkflows { rig ->
        val nonce = rig.openGate()
        val host = rig.host()
        assertEquals(ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce, publicKey = first)))
        assertEquals("no release below the quorum", 0, rig.releaseRows().size)
        assertEquals(ApprovalAccept.RELEASED, host.injectApproval(candidate(nonce, publicKey = second)))
        val approvals = rig.approvalRows()
        assertEquals(listOf(null, JsonPrimitive(true)), approvals.map { payload(it)["completesQuorum"] })
        val release = rig.releaseRows().single()
        assertEquals(ORIGIN_AUTH_LAYER, release.origin)
        assertTrue("after the row that completed it", release.seq > approvals.last().seq)
        assertEquals(JsonPrimitive(nonce.nonce), payload(release)["nonce"])
        val folded = rig.host().refold().host
        assertTrue("the fold honors it", folded.approvedOnCurrentDigest(nonce.gateId))
        assertEquals("the nonce is spent", ApprovalAccept.NOT_OPEN, host.injectApproval(candidate(nonce, publicKey = "pk-third")))
      }
    }
  }

  @Test
  fun aCrashBetweenTheApprovalAndTheReleaseLeavesTheMarkedRowAndNoRelease() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      assertEquals(ApprovalAccept.RECORDED, rig.host().injectApproval(candidate(nonce)))
      val crash = FaultInjector { if (it == ApprovalAcceptor.FAULT_BEFORE_RELEASE) throw RuntimeException("crash") }
      assertThrows(RuntimeException::class.java) {
        rig.host(faults = crash).injectApproval(candidate(nonce, publicKey = "pk-second"))
      }
      assertEquals(JsonPrimitive(true), payload(rig.approvalRows().last())["completesQuorum"])
      assertEquals(0, rig.releaseRows().size)
      val replay = rig.host().injectApproval(candidate(nonce, publicKey = "pk-second"))
      assertEquals("the nonce is still open, and a replay releases nothing here", ApprovalAccept.DUPLICATE, replay)
      assertEquals(0, rig.releaseRows().size)
    }

  @Test
  fun aReleaseThatFailsOnALiveHostStopsTheBoundaryAndIsEscalated() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      var failed = false
      val failOnce = FaultInjector {
        if (it == ApprovalAcceptor.FAULT_BEFORE_RELEASE && !failed) {
          failed = true
          throw RuntimeException("the release append failed")
        }
      }
      val host = rig.host(faults = failOnce)
      assertEquals(ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
      assertThrows(RuntimeException::class.java) { host.injectApproval(candidate(nonce, publicKey = "pk-second")) }
      val retry = assertThrows(IllegalStateException::class.java) {
        host.injectApproval(candidate(nonce, publicKey = "pk-second"))
      }
      assertTrue("a redelivery is refused, not taken as a duplicate", "approval boundary stopped" in retry.message!!)
      assertEquals(
        "one escalation",
        1,
        rig.rawKindsAndPayloads().count { (kind, payload) ->
          kind == HostKinds.ESCALATED && "approval boundary stopped" in payload
        },
      )
      assertEquals(0, rig.releaseRows().size)
    }

  @Test
  fun aLoneApprovalThatMeetsTheQuorumReleases() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      assertEquals(ApprovalAccept.RELEASED, rig.host(auth = LOOSENED).injectApproval(candidate(nonce)))
      assertEquals(JsonPrimitive(true), payload(rig.approvalRows().single())["completesQuorum"])
      assertEquals(1, rig.releaseRows().size)
    }

  @Test
  fun aCrashBeforeTheDoorbellLeavesTheReleaseForTheRestartedHost() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      assertEquals(ApprovalAccept.RECORDED, rig.host().injectApproval(candidate(nonce)))
      val crash = FaultInjector { if (it == ApprovalAcceptor.FAULT_AFTER_RELEASE) throw RuntimeException("crash") }
      assertThrows(RuntimeException::class.java) {
        rig.host(faults = crash).injectApproval(candidate(nonce, publicKey = "pk-second"))
      }
      assertTrue(rig.host().driveUntilQuiescent().host.approvedOnCurrentDigest(nonce.gateId))
    }

  @Test
  fun theReleaseWakesAnIdleLoop() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      assertEquals(ApprovalAccept.RECORDED, rig.host().injectApproval(candidate(nonce)))
      val host = rig.host()
      val loop = Thread { host.runLoop() }
      loop.start()
      try {
        awaitIdle(loop)
        assertEquals(ApprovalAccept.RELEASED, host.injectApproval(candidate(nonce, publicKey = "pk-second")))
        // The loop may already be appending: wait for a row after the release, wherever it lands.
        val release = rig.releaseRows().single().seq
        awaitRowAfter(rig, release, "the loop never woke to the release")
      } finally {
        host.shutdown()
        loop.join(10_000)
      }
    }

  @Test
  fun aLoosenedSpecAtRestartReleasesNothingAlreadyJournaled() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      assertEquals(ApprovalAccept.RECORDED, rig.host().injectApproval(candidate(nonce)))
      val loosened = rig.host(auth = LOOSENED)
      assertFalse(loosened.refold().host.approvedOnCurrentDigest(nonce.gateId))
      assertEquals(ApprovalAccept.DUPLICATE, loosened.injectApproval(candidate(nonce)))
      assertEquals(0, rig.releaseRows().size)
      val fresh = loosened.injectApproval(candidate(nonce, publicKey = "pk-second"))
      assertEquals("positive control: a new approval under it releases", ApprovalAccept.RELEASED, fresh)
    }

  @Test
  fun revokeThenRegrantOverAnExistingReleaseRow() =
    onBothWorkflows { rig ->
      val nonce = rig.openGate()
      val host = rig.host()
      assertEquals(ApprovalAccept.RECORDED, host.injectApproval(candidate(nonce)))
      assertEquals(ApprovalAccept.RELEASED, host.injectApproval(candidate(nonce, publicKey = "pk-second")))
      val firstRelease = rig.releaseRows().single().seq

      val revoked = rig.host(auth = REVOKED)
      val underRevoke = revoked.refold().host
      assertFalse("the revoked approver's release no longer holds", underRevoke.approvedOnCurrentDigest(nonce.gateId))
      assertEquals(listOf(firstRelease), underRevoke.staleReleases.map { it.first })
      val third = revoked.injectApproval(candidate(nonce, publicKey = "pk-third"))
      assertEquals("the nonce is open again, and the third meets the revoked quorum", ApprovalAccept.RELEASED, third)
      val secondRelease = rig.releaseRows().last().seq

      val regranted = rig.host().refold().host
      assertTrue("the first release holds again", regranted.approvedOnCurrentDigest(nonce.gateId))
      val stale = regranted.staleReleases.map { it.first }
      assertEquals("the second folds stale: the gate is released once", listOf(secondRelease), stale)
    }

  private fun payload(e: JournalEntry): JsonObject = Json.parseToJsonElement(e.payloadJson).jsonObject

  /** Waits until [loop] is blocked taking its next wake from the queue: its first wake is done. */
  private fun awaitIdle(loop: Thread) {
    val deadline = System.nanoTime() + 10_000_000_000L
    while (System.nanoTime() < deadline) {
      val taking = loop.stackTrace.any { it.className.endsWith("LinkedBlockingQueue") && it.methodName == "take" }
      if (taking && loop.state == Thread.State.WAITING) return
      Thread.sleep(20)
    }
    throw AssertionError("the loop never went idle")
  }

  /** Waits until the journal holds a row after seq [seq]. */
  private fun awaitRowAfter(rig: Rig, seq: Long, what: String) {
    val deadline = System.nanoTime() + 10_000_000_000L
    while (System.nanoTime() < deadline) {
      if (rig.store.readAll().any { it.seq > seq }) return
      Thread.sleep(20)
    }
    throw AssertionError(what)
  }

  /** [actual] is [expected], and the journal still holds only the [rows] approval rows it held before. */
  private fun assertDropped(rig: Rig, expected: ApprovalAccept, actual: ApprovalAccept, rows: Int = 0) {
    assertEquals(expected, actual)
    assertEquals("$expected appends no approval row", rows, rig.approvalRows().size)
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

    abstract fun host(faults: FaultInjector = FaultInjector.NONE, auth: LeadAuth = AUTH): AgentHost<*>

    /** Drives a host until its gate is open, and returns the nonce minted for it. */
    fun openGate(): IssuedNonce = host().driveUntilQuiescent().host.issuedNonces.values.single()

    fun approvalRows(): List<JournalEntry> = store.readAll().filter { it.kind == HostKinds.APPROVAL_RECORDED }

    fun releaseRows(): List<JournalEntry> = store.readAll().filter { it.kind == KIND_GATE_RELEASED }

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

    override fun host(faults: FaultInjector, auth: LeadAuth): AgentHost<*> =
      ticketLead(
        store = store,
        cognition = ScriptedCognition(),
        podRunner = FakePodRunner(),
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        leadAuth = auth,
        timers = TIMERS,
        faults = faults,
      )
  }

  private inner class GateRig : Rig("a workflow that is not the ticket workflow") {
    private val evidence = File(dir, "evidence.txt").apply { writeText("approve this\n") }

    override fun host(faults: FaultInjector, auth: LeadAuth): AgentHost<*> =
      AgentHost(
        store = store,
        cognition = ProposeTheGate,
        podRunner = FakePodRunner(),
        podSpec = PodSpec.fixture(),
        workflow = GateWorkflow(evidence),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        leadAuth = auth,
        timers = TIMERS,
        faults = faults,
      )
  }

  /** The row [c] would be journaled as if its key resolved to the operator. */
  private fun rowUnderOperator(c: ApprovalCandidate): String =
    buildJsonObject {
        put("gateId", c.gateId)
        put("principalId", "operator")
        put("nonce", c.nonce)
        put("payloadDigest", c.payloadDigest)
        put("evidence", c.evidence)
      }
      .toString()

  /** A candidate approving [n], by the allow-listed operator unless a field is overridden. The
   * evidence's own gate and digest agree with the candidate's, and so does its nonce unless
   * [evidenceNonce] says otherwise. */
  private fun candidate(
    n: IssuedNonce,
    gateId: String = n.gateId,
    nonce: String = n.nonce,
    digest: String = n.payloadDigest,
    publicKey: String = "pk-operator",
    signature: String = GENUINE,
    carrier: String = "carrier-1",
    evidenceNonce: String = nonce,
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
          nonce = evidenceNonce,
          signedPreimage = committedPreimage(publicKey, gateId, digest, evidenceNonce),
        )
        .toJson(),
    )

  private companion object {
    const val GENUINE = "sig-genuine"

    /** A signature that does not verify, as long as [GENUINE]. */
    val FORGED_SAME_LENGTH = "f".repeat(GENUINE.length)

    val OPERATOR = Principal("operator", role = "authorizer", keys = listOf(SchemeKey("test", "pk-operator")))

    /** Holds two keys, so a cell can tell a key's allowance from its principal's. */
    val SECOND =
      Principal("second", role = "authorizer", keys = listOf(SchemeKey("test", "pk-second"), SchemeKey("test", "pk-second-2")))

    val THIRD = Principal("third", role = "authorizer", keys = listOf(SchemeKey("test", "pk-third")))

    /** [principals], a verifier that accepts only [GENUINE], and [threshold] of [quorumOf]. */
    fun authOf(principals: List<Principal>, threshold: Int, vararg quorumOf: String) =
      LeadAuth(
        AllowList(principals),
        ApprovalVerifier { _, _, signature, _ -> signature == GENUINE },
        QuorumGroup(threshold, quorumOf.map { SignerLeaf(it) }),
      )

    /** Two of the three principals release, so one approval alone does not. */
    val AUTH: LeadAuth = authOf(listOf(OPERATOR, SECOND, THIRD), 2, "operator", "second", "third")

    /** [AUTH] loosened: any one of the three releases. */
    val LOOSENED: LeadAuth = authOf(listOf(OPERATOR, SECOND, THIRD), 1, "operator", "second", "third")

    /** [AUTH] with the second principal revoked: two of the operator and the third release. */
    val REVOKED: LeadAuth = authOf(listOf(OPERATOR, THIRD), 2, "operator", "third")

    /** Fires nothing; a ceremony host refuses only [TimerService.NOOP]. */
    val TIMERS = TimerService { _, _ -> }

    /** A nonce no journal here issues. */
    val UNISSUED = IssuedNonce(nonce = "n-unissued", gateId = "g-unissued", payloadDigest = "3".repeat(64), issuedSeq = 0)
  }
}
