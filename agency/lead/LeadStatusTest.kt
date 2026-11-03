package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.ChainBrokenException
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SqliteJournalReader
import com.geekinasuit.agency.shared.journal.SqliteStore
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * A ticket lead's status as a reader beside it sees it: folded from a journal another instance
 * wrote, under the auth the reader names, with the audit rows the fold keeps no state from read
 * from the rows themselves.
 */
class LeadStatusTest {

  @get:Rule val tmp = TemporaryFolder()

  private val auth = ceremonyAuth()

  private fun status(dir: String, under: LeadAuth = auth): LeadStatus =
    SqliteJournalReader(dir, "lead").use { ticketLeadStatus(it, under) }

  private fun SqliteStore.openGate(gateId: String, digest: String, specHash: String = auth.specHash) =
    append(
      HostKinds.GATE_OPENED,
      buildJsonObject {
        put("gateId", gateId)
        put("gateKind", GateKinds.PLAN_APPROVAL)
        put("payloadDigest", digest)
        put("authSpecHash", specHash)
      },
      ORIGIN_SUBSTRATE,
    )

  private fun SqliteStore.issue(nonce: String, gateId: String, digest: String) =
    append(
      HostKinds.NONCE_ISSUED,
      buildJsonObject {
        put("nonce", nonce)
        put("gateId", gateId)
        put("payloadDigest", digest)
      },
      ORIGIN_SUBSTRATE,
    )

  private fun SqliteStore.rejected(gateId: String, nonce: String, digest: String, reason: String, origin: String = ORIGIN_AUTH_LAYER) =
    append(
      HostKinds.APPROVAL_RECORDED,
      buildJsonObject {
        put("gateId", gateId)
        put("principalId", LeadAuth.UNLISTED_PRINCIPAL_ID)
        put("nonce", nonce)
        put("payloadDigest", digest)
        put("evidence", JsonObject(emptyMap()))
        put("rejectedReason", reason)
      },
      origin,
    )

  private fun SqliteStore.ticketDone(ref: String) =
    append(LeadKinds.TICKET_DONE, buildJsonObject { put("ticketRef", ref) }, ORIGIN_SUBSTRATE)

  @Test
  fun anOpenGateShowsItsNonceItsBoundApproversAndTheRejectedAttemptsWithTheirReasons() {
    val pending = tmp.newFolder().path
    SqliteStore(pending, "lead").use { s ->
      s.openGate("plan-approval:t1", "d1")
      s.issue("n1", "plan-approval:t1", "d1")
      s.rejected("plan-approval:t1", "n1", "d1", "the signature does not verify")
    }
    val st = status(pending)
    val gate = st.gates.single()
    assertEquals("plan-approval:t1", gate.gateId)
    assertEquals("n1", gate.openNonce)
    assertFalse(gate.approvedOnCurrentDigest)
    assertEquals(auth.specHash, gate.openedUnderSpecHash)
    assertEquals(listOf(NonceStatus("n1", "plan-approval:t1", "d1", 3, consumed = false)), st.nonces)
    assertEquals(listOf(RejectedApproval(4, "plan-approval:t1", "n1", "the signature does not verify")), st.rejectedApprovals)
    assertEquals("the fold's own account of the same row", 4L, st.unverifiedApprovals.single().first)
    assertEquals(4L, st.headSeq)
    assertEquals(auth.specHash, st.foldedUnderSpecHash)
  }

  @Test
  fun aVerifiedApprovalBindsTheGateAsItStands() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { s ->
      s.openGate("plan-approval:t1", "d1")
      s.issue("n1", "plan-approval:t1", "d1")
      s.issue("n2", "plan-approval:t1", "d1")
      s.approveAndRelease("plan-approval:t1", "d1", "n1")
    }
    val st = status(dir)
    assertEquals(listOf("operator"), st.verifiedApprovals.map { it.principalId })
    assertTrue(st.gates.single().approvedOnCurrentDigest)
    assertEquals(listOf(true, false), st.nonces.map { it.consumed })
    // n2 is still usable on the released gate, but no approval names it.
    assertEquals("n2", st.gates.single().openNonce)
    assertEquals(emptySet<String>(), st.gates.single().boundApprovers)
  }

  @Test
  fun aRejectionReasonOnARowTheAuthorizationLayerDidNotWriteIsNotShownAsOne() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { s ->
      s.openGate("plan-approval:t1", "d1")
      s.issue("n1", "plan-approval:t1", "d1")
      s.rejected("plan-approval:t1", "n1", "d1", "approved, really", origin = ORIGIN_COGNITION)
    }
    val st = status(dir)
    assertEquals(emptyList<RejectedApproval>(), st.rejectedApprovals)
    assertEquals(listOf(4L to HostKinds.APPROVAL_RECORDED), st.misOriginedEntries)
  }

  @Test
  fun theScopedPartsCoverTheCurrentTicketAndTheTailsRunOn() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { s ->
      s.openGate("plan-approval:t1", "d1")
      s.issue("n1", "plan-approval:t1", "d1")
      s.rejected("plan-approval:t1", "n1", "d1", "old")
      s.append(HostKinds.ESCALATED, buildJsonObject { put("reason", "stalled") }, ORIGIN_SUBSTRATE)
      s.ticketDone("t1")
      s.openGate("plan-approval:t2", "d2")
    }
    val st = status(dir)
    assertEquals(listOf("plan-approval:t2"), st.gates.map { it.gateId })
    assertEquals(emptyList<NonceStatus>(), st.nonces)
    assertEquals(emptyList<RejectedApproval>(), st.rejectedApprovals)
    assertEquals(listOf("stalled"), st.escalations)
  }

  @Test
  fun aTicketDoneTheSubstrateDidNotWriteEndsNoScope() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { s ->
      s.openGate("plan-approval:t1", "d1", specHash = "f".repeat(64))
      s.issue("n1", "plan-approval:t1", "d1")
      s.rejected("plan-approval:t1", "n1", "d1", "the signature does not verify")
      s.append(LeadKinds.TICKET_DONE, buildJsonObject { put("ticketRef", "t1") }, ORIGIN_COGNITION)
    }
    val st = status(dir)
    assertEquals(listOf("plan-approval:t1"), st.gatesOpenedUnderAnotherSpec.map { it.gateId })
    assertEquals(listOf(4L), st.rejectedApprovals.map { it.seq })
    assertEquals(listOf(5L to LeadKinds.TICKET_DONE), st.misOriginedEntries)
  }

  @Test
  fun aGateOpenTheSubstrateDidNotWriteDoesNotChangeTheSpecAGateOpenedUnder() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { s ->
      s.openGate("plan-approval:t1", "d1", specHash = "f".repeat(64))
      s.append(
        HostKinds.GATE_OPENED,
        buildJsonObject {
          put("gateId", "plan-approval:t1")
          put("gateKind", GateKinds.PLAN_APPROVAL)
          put("payloadDigest", "d1")
          put("authSpecHash", auth.specHash)
        },
        ORIGIN_COGNITION,
      )
    }
    assertEquals(listOf("plan-approval:t1"), status(dir).gatesOpenedUnderAnotherSpec.map { it.gateId })
  }

  @Test
  fun dropRowsTheAuthorizationLayerDidNotWriteAreNotCounted() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { s ->
      s.append(
        HostKinds.APPROVAL_DROPS_SUMMARIZED,
        buildJsonObject {
          put("gateId", "plan-approval:t1")
          put("nonce", "n1")
          put("duplicates", 2)
        },
        ORIGIN_COGNITION,
      )
      s.append(HostKinds.APPROVAL_DROPS_AGGREGATED, buildJsonObject { put("notOpen", 9) }, ORIGIN_SUBSTRATE)
    }
    val st = status(dir)
    assertEquals(emptyList<DroppedOnNonce>(), st.droppedOnNonce)
    assertEquals(emptyList<DroppedNotOpen>(), st.droppedNotOpen)
  }

  @Test
  fun aGateOpenedUnderAnotherSpecIsNamed() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { s ->
      s.openGate("plan-approval:t1", "d1", specHash = "f".repeat(64))
      s.openGate("commit-approval:t1", "d2")
    }
    assertEquals(listOf("plan-approval:t1"), status(dir).gatesOpenedUnderAnotherSpec.map { it.gateId })
  }

  @Test
  fun dropRowsAreCountedAndAFieldOfTheWrongTypeCountsZero() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { s ->
      s.append(
        HostKinds.APPROVAL_DROPS_SUMMARIZED,
        buildJsonObject {
          put("gateId", "plan-approval:t1")
          put("nonce", "n1")
          put("payloadDigest", "d1")
          put("duplicates", 2)
          putJsonArray("rejectedOverAllowance") {
            addJsonObject { put("count", 3) }
            addJsonObject { put("count", 4) }
          }
          put("rejectedOverAllowanceUnlisted", 5)
          put("wrongDigest", "six")
          put("oversized", 7)
        },
        ORIGIN_AUTH_LAYER,
      )
      s.append(
        HostKinds.APPROVAL_DROPS_AGGREGATED,
        buildJsonObject {
          put("notOpen", 9)
          put("intervalStart", 1000)
        },
        ORIGIN_AUTH_LAYER,
      )
    }
    val st = status(dir)
    assertEquals(listOf(DroppedOnNonce(2, "plan-approval:t1", "n1", 2, 7, 5, 0, 7)), st.droppedOnNonce)
    assertEquals(listOf(DroppedNotOpen(3, 9, 1000)), st.droppedNotOpen)
  }

  @Test
  fun anotherComponentsJournalIsRefused() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "pod").use { it.openGate("plan-approval:t1", "d1") }
    SqliteJournalReader(dir, "lead").use { reader ->
      assertThrows(ChainBrokenException::class.java) { ticketLeadStatus(reader, auth) }
    }
  }
}
