package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.auth.QuorumGroup
import com.geekinasuit.agency.shared.auth.SignerLeaf
import com.geekinasuit.agency.shared.auth.quorumSatisfied
import com.geekinasuit.agency.shared.journal.JournalStore
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SqliteStore
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Nonce + approval fold cells (2a.4 step 1): single-use is DERIVED from the journal, so
 * every verdict here must hold identically across a process restart — the replay cells
 * re-fold through a closed-and-reopened store to prove it. The release teeth extend the
 * digest-binding precedent: issued-for-this-gate, bound-to-this-digest, never-consumed,
 * and honoring consumes.
 */
class AuthFoldTest {

  @get:Rule val tmp = TemporaryFolder()

  private fun newStoreDir(): String = tmp.newFolder().absolutePath

  private fun open(dir: String): JournalStore = SqliteStore(dir, componentId = "lead")

  private fun JournalStore.lead(): LeadState = leadFold(readAll())

  // -- append helpers ----------------------------------------------------------------------

  private fun JournalStore.gateOpened(gateId: String, digest: String) =
    append(
      LeadKinds.GATE_OPENED,
      buildJsonObject {
        put("gateId", gateId)
        put("gateKind", GateKinds.PLAN_APPROVAL)
        put("payloadDigest", digest)
      },
      ORIGIN_SUBSTRATE,
    )

  private fun JournalStore.nonceIssued(nonce: String, gateId: String, digest: String, origin: String = ORIGIN_SUBSTRATE) =
    append(
      LeadKinds.NONCE_ISSUED,
      buildJsonObject {
        put("nonce", nonce)
        put("gateId", gateId)
        put("payloadDigest", digest)
      },
      origin,
    )

  private fun JournalStore.nonceConsumed(nonce: String, reason: String) =
    append(
      LeadKinds.NONCE_CONSUMED,
      buildJsonObject {
        put("nonce", nonce)
        put("reason", reason)
      },
      ORIGIN_SUBSTRATE,
    )

  private fun JournalStore.release(gateId: String, digest: String, nonce: String? = null) =
    append(
      KIND_GATE_RELEASED,
      buildJsonObject {
        put("gateId", gateId)
        put("payloadDigest", digest)
        if (nonce != null) put("nonce", nonce)
      },
      ORIGIN_AUTH_LAYER,
    )

  private fun JournalStore.approval(
    gateId: String,
    principalId: String,
    nonce: String,
    digest: String,
    origin: String = ORIGIN_AUTH_LAYER,
  ) =
    append(
      LeadKinds.APPROVAL_RECORDED,
      buildJsonObject {
        put("gateId", gateId)
        put("principalId", principalId)
        put("nonce", nonce)
        put("payloadDigest", digest)
      },
      origin,
    )

  // -- nonce single-use --------------------------------------------------------------------

  @Test
  fun noncedReleaseHonoredOnceAndConsumed() {
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    val before = s.lead()
    assertEquals("n1", before.openNonceFor(before.openGates["g1"]!!)?.nonce)

    s.release("g1", "d1", nonce = "n1")
    val st = s.lead()
    assertTrue("g1" in st.releasedGates)
    assertFalse("g1" in st.nonceLessReleases) // ceremony release, and the state says so
    assertTrue("n1" in st.consumedNonces)
    assertNull(st.openNonceFor(st.openGates["g1"]!!))
    assertTrue(st.staleReleases.isEmpty())
  }

  @Test
  fun replayedReleaseFoldsStale() {
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.release("g1", "d1", nonce = "n1")
    val replaySeq = s.release("g1", "d1", nonce = "n1").seq
    val st = s.lead()
    assertTrue("g1" in st.releasedGates)
    assertEquals(listOf(replaySeq to "g1"), st.staleReleases)
  }

  @Test
  fun replayRejectionSurvivesRestart() {
    val dir = newStoreDir()
    val first = open(dir)
    first.gateOpened("g1", "d1")
    first.nonceIssued("n1", "g1", "d1")
    first.release("g1", "d1", nonce = "n1")
    first.close()

    // A new process re-folds the journal; the replay must be stale on derived state alone.
    // Honest scope: today this holds BY CONSTRUCTION — lead() is a pure re-fold, there is
    // no in-memory table a restart could fail to clear, so what this adds over
    // replayedReleaseFoldsStale is SQLite durability across a close/reopen. It becomes a
    // real discriminating test the moment a consumer caches LeadState or keeps a
    // spent-nonce set beside the journal — step 2's reviewer should not read this
    // checkbox as covering such a consumer.
    val second = open(dir)
    val replaySeq = second.release("g1", "d1", nonce = "n1").seq
    val st = second.lead()
    assertTrue("g1" in st.releasedGates)
    assertTrue("n1" in st.consumedNonces)
    assertEquals(listOf(replaySeq to "g1"), st.staleReleases)
    second.close()
  }

  @Test
  fun releaseOmittingTheNonceIsNotAnExemption() {
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.release("g1", "d1") // nonce-less on a gate that HAS one
    val st = s.lead()
    assertFalse("g1" in st.releasedGates)
    assertEquals(1, st.staleReleases.size)
  }

  @Test
  fun preCeremonyGateStillReleasesWithoutNonce() {
    // The stub path: a gate that never had a nonce issued keeps its pre-ceremony meaning,
    // so journals written before nonces existed fold as they always did — and the
    // disposition is marked, so derived state can tell this release from a nonced one.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.release("g1", "d1")
    val st = s.lead()
    assertTrue("g1" in st.releasedGates)
    assertTrue("g1" in st.nonceLessReleases)
  }

  @Test
  fun authorizationVoidOnPayloadChange() {
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    // Gate re-opens on a new digest; the substrate mints fresh. The old nonce is
    // deliberately NOT voided here — explicit voiding has its own cell
    // (voidedNonceCannotRelease) — so the nonce's own digest binding is the only clause
    // that can reject the second release below.
    s.gateOpened("g1", "d2")
    s.nonceIssued("n2", "g1", "d2")

    // An authorization bound to the OLD digest cannot release the re-opened gate: naming
    // the old digest fails gate binding; naming the new digest fails the nonce's own
    // digest binding (issued.payloadDigest == digest — the clause this cell observes).
    s.release("g1", "d1", nonce = "n1")
    s.release("g1", "d2", nonce = "n1")
    val st = s.lead()
    assertFalse("g1" in st.releasedGates)
    assertEquals(2, st.staleReleases.size)

    // The fresh nonce releases it.
    s.release("g1", "d2", nonce = "n2")
    assertTrue("g1" in s.lead().releasedGates)
  }

  @Test
  fun nonceBoundToAnotherGateIsStale() {
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.gateOpened("g2", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.release("g2", "d1", nonce = "n1")
    val st = s.lead()
    assertFalse("g2" in st.releasedGates)
    assertEquals(1, st.staleReleases.size)
  }

  @Test
  fun voidedNonceCannotRelease() {
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.nonceConsumed("n1", "expired")
    s.release("g1", "d1", nonce = "n1")
    val st = s.lead()
    assertFalse("g1" in st.releasedGates)
    assertEquals(1, st.staleReleases.size)
  }

  // -- nonce bookkeeping anomalies ----------------------------------------------------------

  @Test
  fun consumeOfUnknownNonceIsVisiblyDropped() {
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceConsumed("never-issued", "typo")
    val st = s.lead()
    assertTrue(st.escalations.any { "unknown nonce" in it })
    assertTrue(st.consumedNonces.isEmpty())
  }

  @Test
  fun consumeAfterReleaseIsIdempotentBookkeeping() {
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.release("g1", "d1", nonce = "n1")
    s.nonceConsumed("n1", "released") // bookkeeping after the fold already consumed
    val st = s.lead()
    assertTrue("n1" in st.consumedNonces)
    assertTrue(st.escalations.isEmpty())
  }

  @Test
  fun reIssueOfANonceValueKeepsFirstBinding() {
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.gateOpened("g2", "d2")
    s.nonceIssued("n1", "g1", "d1")
    s.nonceIssued("n1", "g2", "d2") // rebind attempt
    val st = s.lead()
    assertEquals("g1", st.issuedNonces["n1"]?.gateId)
    assertTrue(st.escalations.any { "re-issued" in it })
    // And the rebind target cannot be released with it.
    s.release("g2", "d2", nonce = "n1")
    assertFalse("g2" in s.lead().releasedGates)
  }

  @Test
  fun issueForUnknownGateIsRecordedAndFlagged() {
    val s = open(newStoreDir())
    s.nonceIssued("n1", "ghost", "d1")
    val st = s.lead()
    assertEquals("ghost", st.issuedNonces["n1"]?.gateId)
    assertTrue(st.escalations.any { "unknown gate" in it })
  }

  @Test
  fun nonceIssuedBeforeItsGateBindsItsAssertedDigestNotTheGates() {
    // The continuation of issue-before-open: the fold RECORDS a nonce for a gate it has
    // not seen, so a release can later arrive where gate lookup, gate digest, gate
    // binding, and consumption ALL pass — the nonce's own digest binding
    // (issued.payloadDigest == digest) is the single clause that rejects it. This is the
    // cell that fails if that clause is dropped from `faithful`.
    val s = open(newStoreDir())
    s.nonceIssued("n1", "g1", "dX") // minted against a digest no gate ever opened on
    s.gateOpened("g1", "d1")
    s.release("g1", "d1", nonce = "n1")
    val st = s.lead()
    assertFalse("g1" in st.releasedGates)
    assertEquals(1, st.staleReleases.size)
  }

  @Test
  fun cognitionOriginNonceKindsAreNeverHonored() {
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1", origin = ORIGIN_COGNITION)
    val st = s.lead()
    assertTrue(st.issuedNonces.isEmpty())
    // seq 1 is the chain's genesis entry; the appends here start at 2.
    assertEquals(listOf(3L to LeadKinds.NONCE_ISSUED), st.misOriginedEntries)
  }

  // -- approvals ----------------------------------------------------------------------------

  @Test
  fun approvalsAccumulateDurablyAndDeduplicate() {
    val dir = newStoreDir()
    val first = open(dir)
    first.gateOpened("g1", "d1")
    first.nonceIssued("n1", "g1", "d1")
    first.approval("g1", "council-a", "n1", "d1")
    first.approval("g1", "council-a", "n1", "d1") // re-delivery: idempotent
    first.close()

    // A k-of-n quorum fills across restarts because accumulation is journal-derived.
    val second = open(dir)
    second.approval("g1", "ops-a", "n1", "d1")
    val st = second.lead()
    assertEquals(2, st.approvals["g1"]!!.size)

    val gate = st.openGates["g1"]!!
    val approvers = st.boundApprovers(gate, "n1")
    assertEquals(setOf("council-a", "ops-a"), approvers)

    // The two halves compose: the fold's bound approver set feeds the tree evaluator.
    val policy =
      QuorumGroup(
        2,
        listOf(
          QuorumGroup(1, listOf(SignerLeaf("council-a"), SignerLeaf("council-b"))),
          QuorumGroup(1, listOf(SignerLeaf("ops-a"), SignerLeaf("ops-b"))),
        ),
      )
    assertTrue(quorumSatisfied(policy, approvers))
    assertFalse(quorumSatisfied(policy, st.boundApprovers(gate, "wrong-nonce")))
    second.close()
  }

  @Test
  fun staleBoundApprovalsAreInertAfterReopen() {
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.approval("g1", "council-a", "n1", "d1")
    s.gateOpened("g1", "d2") // re-opened on a new digest
    s.nonceIssued("n2", "g1", "d2")
    val st = s.lead()
    val gate = st.openGates["g1"]!!
    // Present in the record, excluded from the bound set under the new digest and nonce.
    assertEquals(1, st.approvals["g1"]!!.size)
    assertTrue(st.boundApprovers(gate, "n2").isEmpty())
  }

  @Test
  fun nonAuthOriginApprovalIsQuorumStuffingNotAnApproval() {
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.approval("g1", "operator", "n1", "d1", origin = ORIGIN_COGNITION)
    s.approval("g1", "operator", "n1", "d1", origin = ORIGIN_SUBSTRATE)
    val st = s.lead()
    assertTrue(st.approvals.isEmpty())
    // seq 1 is the chain's genesis entry; the appends here start at 2.
    assertEquals(
      listOf(3L to LeadKinds.APPROVAL_RECORDED, 4L to LeadKinds.APPROVAL_RECORDED),
      st.misOriginedEntries,
    )
  }

  @Test
  fun ticketDoneClearsNoncesAndApprovals() {
    val s = open(newStoreDir())
    s.append(LeadKinds.TICKET_CLAIMED, buildJsonObject { put("ticketRef", "t1") }, ORIGIN_SUBSTRATE)
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.approval("g1", "operator", "n1", "d1")
    s.release("g1", "d1", nonce = "n1")
    s.gateOpened("g2", "d2")
    s.release("g2", "d2") // pre-ceremony path, so the clear below has a marker to clear
    s.append(LeadKinds.TICKET_DONE, buildJsonObject { put("ticketRef", "t1") }, ORIGIN_SUBSTRATE)
    val st = s.lead()
    assertTrue(st.issuedNonces.isEmpty())
    assertTrue(st.consumedNonces.isEmpty())
    assertTrue(st.approvals.isEmpty())
    assertTrue(st.nonceLessReleases.isEmpty())
  }
}
