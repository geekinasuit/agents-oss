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
import kotlinx.serialization.json.JsonNull
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
    val releaseSeq = s.release("g1", "d1").seq
    val st = s.lead()
    assertTrue("g1" in st.releasedGates)
    assertEquals(releaseSeq, st.nonceLessReleases["g1"])
  }

  @Test
  fun reReleaseUnderCeremonyIsDistinguishableFromTheNonceLessMark() {
    // The marker is keyed to the seq of the release it describes: after a pre-ceremony
    // honor, a re-open + ceremony release of the same gate must neither erase the mark
    // nor let it read as covering the ceremony release.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    val preSeq = s.release("g1", "d1").seq // pre-ceremony honor
    s.gateOpened("g1", "d2") // re-opened on a new digest
    s.nonceIssued("n1", "g1", "d2")
    val ceremonySeq = s.release("g1", "d2", nonce = "n1").seq
    val st = s.lead()
    assertTrue("g1" in st.releasedGates)
    assertTrue("n1" in st.consumedNonces)
    assertEquals(preSeq, st.nonceLessReleases["g1"])
    assertTrue(ceremonySeq != preSeq)
  }

  @Test
  fun nonceLessReplayFoldsStaleAndTheMarkKeepsTheFirstSeq() {
    // The pre-ceremony honor is single-use per gate, mirroring the consumed-nonce rule:
    // a byte-identical second release folds stale — visibly — and the mark still names
    // the release that actually honored the gate, never the latest replay.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    val firstSeq = s.release("g1", "d1").seq
    val replaySeq = s.release("g1", "d1").seq
    val st = s.lead()
    assertTrue("g1" in st.releasedGates)
    assertEquals(firstSeq, st.nonceLessReleases["g1"])
    assertEquals(listOf(replaySeq to "g1"), st.staleReleases)
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
  fun inventedNonceIsStaleNotAnAuthorization() {
    // The forged-nonce clause (`issued != null`): a release naming a nonce the substrate
    // never minted must fold stale. A fold that defaulted the failed lookup to a record
    // built from the release's own claims would let any release author the authorization
    // it claims to carry — this is the cell that fails if that clause goes vacuous.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.release("g1", "d1", nonce = "never-minted")
    val st = s.lead()
    assertFalse("g1" in st.releasedGates)
    assertEquals(1, st.staleReleases.size)
    assertTrue(st.consumedNonces.isEmpty())
  }

  @Test
  fun forgedNonceAgainstAGateUnderTheCeremonyIsStale() {
    // The complement of the cell above: here the gate HAS a live nonce, so an
    // implementation keying on "some nonce exists for this gate" rather than looking up
    // the NAMED value would honor the forgery. Refusal must also mint nothing and leave
    // the real nonce untouched.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.release("g1", "d1", nonce = "n-forged") // gate + digest agree; value never minted
    val st = s.lead()
    assertFalse("g1" in st.releasedGates)
    assertEquals(1, st.staleReleases.size)
    assertTrue("n-forged" !in st.consumedNonces)
    assertTrue("n1" !in st.consumedNonces)
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
  fun nullNonceFieldOnAMintFailsClassified() {
    // JsonNull IS a JsonPrimitive whose content is the string "null": without the
    // explicit refusal, a null-valued mint would fold onward as an issued nonce named
    // the guessable four-character string "null". The nonce is REQUIRED on a mint, so a
    // null there is payload-contract drift and must fail CLASSIFIED, not fold.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.append(
      LeadKinds.NONCE_ISSUED,
      buildJsonObject {
        put("nonce", JsonNull)
        put("gateId", "g1")
        put("payloadDigest", "d1")
      },
      ORIGIN_SUBSTRATE,
    )
    val message =
      try {
        s.lead()
        throw AssertionError("expected LeadFoldException")
      } catch (expected: LeadFoldException) {
        expected.message.orEmpty()
      }
    assertTrue("'nonce'" in message)
  }

  @Test
  fun numberTypedRequiredFieldFailsClassified() {
    // Same doctrine as the null-field cell above: a numeric nonce on a mint is
    // payload-contract drift, refused classified — never coerced onward as the working
    // string "123".
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.append(
      LeadKinds.NONCE_ISSUED,
      buildJsonObject {
        put("nonce", 123)
        put("gateId", "g1")
        put("payloadDigest", "d1")
      },
      ORIGIN_SUBSTRATE,
    )
    val message =
      try {
        s.lead()
        throw AssertionError("expected LeadFoldException")
      } catch (expected: LeadFoldException) {
        expected.message.orEmpty()
      }
    assertTrue("'nonce'" in message)
    assertTrue("JSON string" in message)
  }

  @Test
  fun nullNonceFieldOnAReleaseReadsAsAbsent() {
    // The nonce is OPTIONAL on a release, so JsonNull reads as the ordinary JSON spelling
    // of absence. Under the ceremony that folds stale (a null can neither name a nonce
    // "null" nor act as an exemption); on a pre-ceremony gate it is the omission it
    // claims to be — honored and marked, exactly as if the field were left out.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.append(
      KIND_GATE_RELEASED,
      buildJsonObject {
        put("gateId", "g1")
        put("payloadDigest", "d1")
        put("nonce", JsonNull)
      },
      ORIGIN_AUTH_LAYER,
    )
    s.gateOpened("g2", "d2")
    s.append(
      KIND_GATE_RELEASED,
      buildJsonObject {
        put("gateId", "g2")
        put("payloadDigest", "d2")
        put("nonce", JsonNull)
      },
      ORIGIN_AUTH_LAYER,
    )
    val st = s.lead()
    assertFalse("g1" in st.releasedGates)
    assertEquals(1, st.staleReleases.size)
    assertTrue("g2" in st.releasedGates)
    assertTrue("g2" in st.nonceLessReleases)
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
  fun approvalForUnknownGateOrUnmintedNonceIsRecordedAndFlagged() {
    // Mirrors NONCE_ISSUED's flagged-but-kept pattern: the auth layer's assertion stands
    // in the record (a release re-verifies against live state anyway), but an approval
    // naming a gate never opened or a nonce never minted is contract drift worth seeing.
    val s = open(newStoreDir())
    s.approval("ghost", "operator", "n9", "d1")
    val st = s.lead()
    assertEquals(1, st.approvals["ghost"]!!.size)
    assertTrue(st.escalations.any { "unknown gate" in it })
    assertTrue(st.escalations.any { "unminted nonce" in it })
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
