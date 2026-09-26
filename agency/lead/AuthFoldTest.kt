package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.auth.AllowList
import com.geekinasuit.agency.shared.auth.ApprovalEvidence
import com.geekinasuit.agency.shared.auth.ApprovalVerifier
import com.geekinasuit.agency.shared.auth.Principal
import com.geekinasuit.agency.shared.auth.QuorumGroup
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.SignerLeaf
import com.geekinasuit.agency.shared.auth.committedPreimage
import com.geekinasuit.agency.shared.auth.oneOfOne
import com.geekinasuit.agency.shared.auth.quorumSatisfied
import com.geekinasuit.agency.shared.journal.JournalStore
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SqliteStore
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
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

  // -- authorization harness ----------------------------------------------------------------
  //
  // A permissive LeadAuth for the fold cells: every test principal is allow-listed under a
  // distinct key, the verifier ACCEPTS unconditionally (the real crypto adapter is step 3 —
  // these cells exercise the fold's verify-and-quorum WIRING, not secp256k1), and the quorum
  // is 1-of-N so a single verified approval clears a ceremony release. Cells that need a
  // richer tree compose one themselves over boundApprovers
  // (approvalsAccumulateDurablyAndDeduplicate); cells that need a STRICTER auth (revocation,
  // rejection) build their own LeadAuth and fold with it.

  private val principalIds = listOf("council-a", "council-b", "ops-a", "ops-b", "operator")

  private fun pubKeyFor(principalId: String): String = "pk-$principalId"

  private fun allowListOf(vararg ids: String): AllowList =
    AllowList(
      ids.map { Principal(it, role = "authorizer", keys = listOf(SchemeKey("test", pubKeyFor(it)))) }
    )

  private val acceptingVerifier = ApprovalVerifier { _, _, _, _ -> true }

  private val testAuth =
    LeadAuth(
      allowList = allowListOf(*principalIds.toTypedArray()),
      verifier = acceptingVerifier,
      quorum = QuorumGroup(1, principalIds.map { SignerLeaf(it) }),
    )

  private fun JournalStore.lead(): LeadState = leadFold(readAll(), testAuth)

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

  /** A FLAT approval with NO evidence sub-object — it cannot re-verify, so it lands in
   * unverifiedApprovals, never verifiedApprovals. Kept for cells that test the origin gate
   * (which fires before verification) or the fail-to-verify path; a cell that needs an
   * approval to COUNT uses [approvalFor]. */
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

  /** A VERIFYING approval: a real evidence sub-object whose signed preimage commits to
   * ([pubKeyFor] [principalId], gateId, digest, nonce). Under [testAuth]'s accepting verifier
   * and allow-list it re-verifies and lands in verifiedApprovals as [principalId] — the
   * approval a ceremony release's quorum is actually met by. */
  private fun JournalStore.approvalFor(
    gateId: String,
    principalId: String,
    nonce: String,
    digest: String,
  ) {
    val pk = pubKeyFor(principalId)
    append(
      LeadKinds.APPROVAL_RECORDED,
      buildJsonObject {
        put("gateId", gateId)
        put("principalId", principalId)
        put("nonce", nonce)
        put("payloadDigest", digest)
        put(
          "evidence",
          ApprovalEvidence(
              schemeId = "test",
              publicKey = pk,
              signature = "sig-$principalId",
              carrierArtifactId = "carrier-$nonce",
              gateId = gateId,
              payloadDigest = digest,
              nonce = nonce,
              signedPreimage = committedPreimage(pk, gateId, digest, nonce),
            )
            .toJson(),
        )
      },
      ORIGIN_AUTH_LAYER,
    )
  }

  /** Append an APPROVAL_RECORDED carrying a caller-built [evidence] — for the verification
   * cells that need a hand-crafted evidence object (null preimage, a flat field disagreeing
   * with the preimage, an out-of-allow-list key, a signature over other bytes). */
  private fun JournalStore.approvalWithEvidence(
    gateId: String,
    principalId: String,
    nonce: String,
    digest: String,
    evidence: ApprovalEvidence,
  ) =
    append(
      LeadKinds.APPROVAL_RECORDED,
      buildJsonObject {
        put("gateId", gateId)
        put("principalId", principalId)
        put("nonce", nonce)
        put("payloadDigest", digest)
        put("evidence", evidence.toJson())
      },
      ORIGIN_AUTH_LAYER,
    )

  /** Fold with a caller-supplied auth instead of [testAuth] — for the cells that vary the
   * allow-list, verifier, or quorum (recovery contract, quorum tree, provenance anchor). */
  private fun JournalStore.leadWith(auth: LeadAuth): LeadState = leadFold(readAll(), auth)

  private fun sha256Hex(s: String): String =
    java.security.MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") {
      "%02x".format(it)
    }

  // -- nonce single-use --------------------------------------------------------------------

  @Test
  fun noncedReleaseHonoredOnceAndConsumed() {
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    val before = s.lead()
    assertEquals("n1", before.openNonceFor(before.openGates["g1"]!!)?.nonce)

    s.approvalFor("g1", "operator", "n1", "d1") // a verified approval meets the quorum
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
    s.approvalFor("g1", "operator", "n1", "d1")
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
    first.approvalFor("g1", "operator", "n1", "d1")
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
    // A gate that HAS a nonce, released without naming it, is still refused under a ceremony
    // auth — omitting the nonce is not a way to dodge the ceremony. Under testAuth the refusal
    // is the hasApprovers guard, which fires for any nonce-less release (gate-with-nonce or not;
    // aNonceLessReleaseUnderACeremonyAuthFoldsStale is the companion no-nonce case). The per-gate
    // issuedNonces.any clause's own stale-fold is covered under DENY_ALL by
    // nullNonceFieldOnAReleaseReadsAsAbsent.
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
    // The stub path: under a no-approver (pre-ceremony) auth, a gate that never had a nonce
    // issued keeps its pre-ceremony meaning, so journals written before nonces existed fold
    // as they always did — and the disposition is marked, so derived state can tell this
    // release from a nonced one. (Under a ceremony auth this same release folds stale — see
    // aNonceLessReleaseUnderACeremonyAuthFoldsStale.)
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    val releaseSeq = s.release("g1", "d1").seq
    val st = s.leadWith(LeadAuth.DENY_ALL)
    assertTrue("g1" in st.releasedGates)
    assertEquals(releaseSeq, st.nonceLessReleases["g1"])
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
    val st = s.leadWith(LeadAuth.DENY_ALL)
    assertTrue("g1" in st.releasedGates)
    assertEquals(firstSeq, st.nonceLessReleases["g1"])
    assertEquals(listOf(replaySeq to "g1"), st.staleReleases)
  }

  @Test
  fun aReOpenedGateIsNotHonoredNonceLessASecondTimeUnderDenyAll() {
    // The nonce-less honor's single-use survives a re-open, via a DIFFERENT clause than the
    // same-digest replay (nonceLessReplayFoldsStaleAndTheMarkKeepsTheFirstSeq). A replay on d1
    // is caught by the per-(gate, digest) single-release guard; a release on a freshly-opened
    // d2 passes that guard — d2 is a new authorization surface — and is refused instead by the
    // per-gate mark, the `gateId in nonceLessReleases` clause. The second release folds stale,
    // visibly, and the mark keeps the first honoring seq. (Refused outright under a ceremony
    // auth, so this single-use guard is a DENY_ALL rule.)
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    val firstSeq = s.release("g1", "d1").seq // pre-ceremony honor
    s.gateOpened("g1", "d2") // re-opened on a new digest
    val reSeq = s.release("g1", "d2").seq // nonce-less again, on the new digest
    val st = s.leadWith(LeadAuth.DENY_ALL)
    assertTrue("g1" in st.releasedGates)
    assertEquals(firstSeq, st.nonceLessReleases["g1"])
    assertEquals(listOf(reSeq to "g1"), st.staleReleases)
  }

  @Test
  fun aNonceLessReleaseUnderACeremonyAuthFoldsStale() {
    // Under a ceremony auth (a non-empty allow-list) every release must be nonce-bound and
    // quorum-satisfied — the pre-ceremony nonce-less path is refused outright. This is the
    // invariant that lets the substrate mint nonces safely: a crash between GATE_OPENED and
    // NONCE_ISSUED leaves the gate nonce-less until the next wake mints its nonce, and never
    // releasable off the un-quorumed nonce-less path.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.release("g1", "d1") // nonce-less, no nonce ever issued for this gate
    val st = s.lead() // testAuth: non-empty allow-list
    assertFalse("g1" in st.releasedGates)
    assertEquals(1, st.staleReleases.size)
    assertTrue("g1" !in st.nonceLessReleases)
  }

  @Test
  fun aNonceLessHonorFoldsStaleWhenRefoldedUnderACeremonyAuth() {
    // The recovery contract: folded state is a function of (journal, auth). A nonce-less
    // release is the pre-ceremony path, legitimate only under a no-approver auth. The SAME
    // journal, re-folded under a ceremony auth, folds that release stale — authorization is
    // re-decided on the allow-list in force at recovery, not frozen in at write time.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.release("g1", "d1") // nonce-less
    val preCeremony = s.leadWith(LeadAuth.DENY_ALL)
    assertTrue("g1" in preCeremony.releasedGates)
    val ceremony = s.leadWith(testAuth)
    assertFalse("g1" in ceremony.releasedGates)
    assertEquals(1, ceremony.staleReleases.size)
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
    s.approvalFor("g1", "operator", "n2", "d2")
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

  @Test
  fun aReleasedGateIsNotReReleasedByAFreshNonceOnTheSameDigest() {
    // Single-release per (gate, digest): a gate already released for a payload is DECIDED,
    // and a SECOND fresh, valid, never-consumed nonce minted for the SAME gate+digest must
    // not honor it again. The nonce path had no analogue of the nonce-less path's per-gate
    // single-use guard (the `gateId in nonceLessReleases` check), so a second minted nonce
    // cleared an already-decided gate a second time — the clause this cell fails without.
    // The re-release folds stale and consumes nothing.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.approvalFor("g1", "operator", "n1", "d1")
    s.release("g1", "d1", nonce = "n1") // honored; n1 consumed
    s.nonceIssued("n2", "g1", "d1") // a second nonce for the SAME gate and digest
    val reReleaseSeq = s.release("g1", "d1", nonce = "n2").seq
    val st = s.lead()
    assertTrue("g1" in st.releasedGates)
    assertTrue("n1" in st.consumedNonces)
    assertTrue("n2" !in st.consumedNonces)
    assertEquals(listOf(reReleaseSeq to "g1"), st.staleReleases)
  }

  @Test
  fun aReOpenOnANewDigestPermitsAFreshReleaseOfAnAlreadyReleasedGate() {
    // The single-release key is the DIGEST epoch, not the gate id: a gate released for d1
    // and then re-opened on d2 is a fresh authorization surface, so a release naming d2 is
    // honored even though the gate already sits in releasedGates. This is the cell that
    // fails if the guard keys on gateId alone — it would fold the legitimate d2 release
    // stale.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.approvalFor("g1", "operator", "n1", "d1")
    s.release("g1", "d1", nonce = "n1") // honored on d1
    s.gateOpened("g1", "d2") // re-opened on a new digest
    s.nonceIssued("n2", "g1", "d2")
    s.approvalFor("g1", "operator", "n2", "d2")
    s.release("g1", "d2", nonce = "n2") // must be honored on d2
    val st = s.lead()
    assertTrue("g1" in st.releasedGates)
    assertTrue("n1" in st.consumedNonces)
    assertTrue("n2" in st.consumedNonces)
    assertTrue(st.staleReleases.isEmpty())
  }

  @Test
  fun aDigestRevisitedAcrossReopensIsStillRefused() {
    // releasedDigests is a Set per gate, not a single last-digest, precisely so a digest
    // REVISITED across re-opens (d1 → d2 → d1) is still refused. This is the ONLY shape where
    // Set-vs-single-value differs: a single-value guard would retain only d2 and would
    // re-honor the revisited d1. The cell fails if releasedDigests ever collapses to one
    // digest per gate.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.approvalFor("g1", "operator", "n1", "d1")
    s.release("g1", "d1", nonce = "n1") // honored on d1
    s.gateOpened("g1", "d2")
    s.nonceIssued("n2", "g1", "d2")
    s.approvalFor("g1", "operator", "n2", "d2")
    s.release("g1", "d2", nonce = "n2") // honored on d2
    s.gateOpened("g1", "d1") // re-opened on the ALREADY-RELEASED d1
    s.nonceIssued("n3", "g1", "d1")
    val revisitSeq = s.release("g1", "d1", nonce = "n3").seq // must fold stale
    val st = s.lead()
    assertTrue("g1" in st.releasedGates)
    assertTrue("n1" in st.consumedNonces)
    assertTrue("n2" in st.consumedNonces)
    assertTrue("n3" !in st.consumedNonces)
    assertEquals(listOf(revisitSeq to "g1"), st.staleReleases)
  }

  @Test
  fun approvedOnCurrentDigestTracksTheOpenDigestNotBareGateMembership() {
    // #28: the read-side mirror of the single-release guard, and the question every release
    // CONSUMER must ask. A gate released on d1 then re-opened on d2 (no d2 release) still sits
    // in releasedGates (epoch-blind: "released at all this ticket") but is NOT approved on its
    // CURRENT digest. Approving d2 in turn flips it back true — the helper admits a legitimate
    // re-approval exactly as foldRelease admits the legitimate re-release.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.approvalFor("g1", "operator", "n1", "d1")
    s.release("g1", "d1", nonce = "n1") // approved on d1
    assertTrue("released at all this ticket", "g1" in s.lead().releasedGates)
    assertTrue("approved on the open digest d1", s.lead().approvedOnCurrentDigest("g1"))

    s.gateOpened("g1", "d2") // re-opened on a new digest, not yet approved
    assertTrue("still in releasedGates (epoch-blind)", "g1" in s.lead().releasedGates)
    assertFalse("NOT approved on the current digest d2", s.lead().approvedOnCurrentDigest("g1"))

    s.nonceIssued("n2", "g1", "d2")
    s.approvalFor("g1", "operator", "n2", "d2")
    s.release("g1", "d2", nonce = "n2") // approved on d2
    assertTrue("approved again once d2 is released", s.lead().approvedOnCurrentDigest("g1"))
  }

  @Test
  fun approvedOnCurrentDigestIsFalseForAGateThatIsNotOpen() {
    // Fail-closed: no open gate is not approved. ScriptedCognition reads this while no plan gate
    // is open yet: a true here would have it propose the execute pod while the planner still runs.
    val s = open(newStoreDir())
    assertFalse(s.lead().approvedOnCurrentDigest("never-opened"))
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
    // of absence — never as a nonce literally named "null". Folded under a no-approver auth,
    // the two halves show it: on g1 (which HAS a nonce issued) the null-nonce release folds
    // stale via the gate-has-a-nonce clause; on g2 (no nonce) it is the omission it claims to
    // be — honored and marked, exactly as if the field were left out. (Under a ceremony auth
    // BOTH would fold stale — the nonce-less path is refused there regardless of JsonNull.)
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
    val st = s.leadWith(LeadAuth.DENY_ALL)
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
    first.approvalFor("g1", "council-a", "n1", "d1")
    first.approvalFor("g1", "council-a", "n1", "d1") // re-delivery: idempotent
    first.close()

    // A k-of-n quorum fills across restarts because accumulation is journal-derived.
    val second = open(dir)
    second.approvalFor("g1", "ops-a", "n1", "d1")
    val st = second.lead()
    assertEquals(2, st.verifiedApprovals["g1"]!!.size)

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
    s.approvalFor("g1", "council-a", "n1", "d1")
    s.gateOpened("g1", "d2") // re-opened on a new digest
    s.nonceIssued("n2", "g1", "d2")
    val st = s.lead()
    val gate = st.openGates["g1"]!!
    // Present in the record, excluded from the bound set under the new digest and nonce.
    assertEquals(1, st.verifiedApprovals["g1"]!!.size)
    assertTrue(st.boundApprovers(gate, "n2").isEmpty())
  }

  @Test
  fun nonAuthOriginApprovalIsQuorumStuffingNotAnApproval() {
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.approval("g1", "operator", "n1", "d1", origin = ORIGIN_COGNITION)
    s.approval("g1", "operator", "n1", "d1", origin = ORIGIN_SUBSTRATE)
    val st = s.lead()
    assertTrue(st.verifiedApprovals.isEmpty())
    // seq 1 is the chain's genesis entry; the appends here start at 2.
    assertEquals(
      listOf(3L to LeadKinds.APPROVAL_RECORDED, 4L to LeadKinds.APPROVAL_RECORDED),
      st.misOriginedEntries,
    )
  }

  @Test
  fun approvalForUnknownGateOrUnmintedNonceIsRecordedAndFlagged() {
    // Mirrors NONCE_ISSUED's flagged-but-kept pattern: a VERIFIED approval whose committed
    // gate was never opened / nonce never minted is kept (a release re-checks against live
    // state anyway) but the drift is flagged — verification and drift are orthogonal.
    val s = open(newStoreDir())
    s.approvalFor("ghost", "operator", "n9", "d1")
    val st = s.lead()
    assertEquals(1, st.verifiedApprovals["ghost"]!!.size)
    assertTrue(st.escalations.any { "unknown gate" in it })
    assertTrue(st.escalations.any { "unminted nonce" in it })
  }

  @Test
  fun ticketDoneClearsNoncesAndApprovals() {
    val s = open(newStoreDir())
    s.append(LeadKinds.TICKET_CLAIMED, buildJsonObject { put("ticketRef", "t1") }, ORIGIN_SUBSTRATE)
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.approvalFor("g1", "operator", "n1", "d1")
    s.release("g1", "d1", nonce = "n1")
    // The ceremony release actually HONORS here (verifying approval + met quorum), so
    // issuedNonces, consumedNonces, and verifiedApprovals are populated and then non-vacuously
    // cleared. unverifiedApprovals is not populated here — it rides the same one-shot TICKET_DONE
    // reset. The nonce-less mark is cleared under DENY_ALL (a ceremony auth can never populate
    // it) in ticketDoneClearsTheNonceLessMark.
    assertTrue("g1" in s.lead().releasedGates)
    s.append(LeadKinds.TICKET_DONE, buildJsonObject { put("ticketRef", "t1") }, ORIGIN_SUBSTRATE)
    val st = s.lead()
    assertTrue(st.issuedNonces.isEmpty())
    assertTrue(st.consumedNonces.isEmpty())
    assertTrue(st.verifiedApprovals.isEmpty())
    assertTrue(st.unverifiedApprovals.isEmpty())
  }

  @Test
  fun ticketDoneClearsTheNonceLessMark() {
    // The nonce-less mark lands in nonceLessReleases only under a pre-ceremony (DENY_ALL) auth,
    // so the TICKET_DONE clear of that map must be tested there — a ceremony fold can never put
    // a mark in it for the clear to remove. Non-vacuous: the mark is present before TICKET_DONE
    // and gone after, so dropping the nonceLessReleases line from the clear fails this.
    val s = open(newStoreDir())
    s.append(LeadKinds.TICKET_CLAIMED, buildJsonObject { put("ticketRef", "t1") }, ORIGIN_SUBSTRATE)
    s.gateOpened("g1", "d1")
    s.release("g1", "d1") // pre-ceremony nonce-less honor → marked
    assertTrue("g1" in s.leadWith(LeadAuth.DENY_ALL).nonceLessReleases)
    s.append(LeadKinds.TICKET_DONE, buildJsonObject { put("ticketRef", "t1") }, ORIGIN_SUBSTRATE)
    assertTrue(s.leadWith(LeadAuth.DENY_ALL).nonceLessReleases.isEmpty())
  }

  // -- mechanical re-verification (2b) ------------------------------------------------------

  @Test
  fun failsClosedOnAnAbsentPreimageEvenUnderAnAcceptingVerifier() {
    // The load-bearing closure: signedPreimage is nullable so legacy records parse, and the
    // fold treats a null preimage as UNVERIFIABLE — never a pass. Uses the accepting verifier
    // ([testAuth]), so the ONLY thing between this approval and a release is the
    // null-preimage check itself; were it to regress, the release would clear.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.approvalWithEvidence(
      "g1",
      "operator",
      "n1",
      "d1",
      ApprovalEvidence("test", pubKeyFor("operator"), "sig", "carrier", "g1", "d1", "n1", signedPreimage = null),
    )
    s.release("g1", "d1", nonce = "n1")
    val st = s.lead()
    assertTrue(st.verifiedApprovals.isEmpty())
    assertTrue(st.unverifiedApprovals.any { "no signed preimage" in it.second })
    assertFalse("g1" in st.releasedGates)
    assertEquals(1, st.staleReleases.size)
  }

  @Test
  fun anApprovalWithMalformedEvidenceIsUnverifiedWithoutRepeatingTheEvidence() {
    // The evidence sub-object is text its carrier chose. The reason kept for the refused approval
    // names the field and the check, not the value.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    val evidence =
      ApprovalEvidence("test", pubKeyFor("operator"), "sig", "carrier", "g1", "d1", "n1").toJson()
    val approval =
      s.append(
        LeadKinds.APPROVAL_RECORDED,
        buildJsonObject {
          put("gateId", "g1")
          put("principalId", "operator")
          put("nonce", "n1")
          put("payloadDigest", "d1")
          put("evidence", JsonObject(evidence + ("publicKey" to JsonPrimitive(90210))))
        },
        ORIGIN_AUTH_LAYER,
      )
    assertEquals(
      listOf(
        approval.seq to
          "approval at seq=${approval.seq} has malformed evidence: " +
            "approval evidence 'publicKey' must be a JSON string"
      ),
      s.lead().unverifiedApprovals,
    )
  }

  @Test
  fun splitSourceFlatKeyDisagreeingWithThePreimageIsUnverified() {
    // The split-source hole 2b closes: the preimage is authority. Here the flat evidence key
    // names council-a (allow-listed) but the preimage commits to operator — the layers
    // disagree, so the approval is unverified, naming the disagreeing layer, and neither key
    // puts an approver in the quorum.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    val preimage = committedPreimage(pubKeyFor("operator"), "g1", "d1", "n1")
    s.approvalWithEvidence(
      "g1",
      "operator",
      "n1",
      "d1",
      ApprovalEvidence("test", pubKeyFor("council-a"), "sig", "carrier", "g1", "d1", "n1", signedPreimage = preimage),
    )
    s.release("g1", "d1", nonce = "n1")
    val st = s.lead()
    assertTrue(st.verifiedApprovals.isEmpty())
    assertTrue(st.unverifiedApprovals.any { "evidence publicKey disagrees" in it.second })
    assertFalse("g1" in st.releasedGates)
  }

  @Test
  fun aSignerWhosePreimageKeyIsNotAllowListedIsUnverified() {
    // Resolution is off the PREIMAGE's key: the preimage commits to pk-ghost, which no
    // principal holds, so it resolves to nobody and is unverified — the allow-list lives with
    // us, and a carrier cannot add a signer by naming one.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    val preimage = committedPreimage("pk-ghost", "g1", "d1", "n1")
    s.approvalWithEvidence(
      "g1",
      "operator",
      "n1",
      "d1",
      ApprovalEvidence("test", "pk-ghost", "sig", "carrier", "g1", "d1", "n1", signedPreimage = preimage),
    )
    s.release("g1", "d1", nonce = "n1")
    val st = s.lead()
    assertTrue(st.verifiedApprovals.isEmpty())
    assertTrue(st.unverifiedApprovals.any { "not in the allow-list" in it.second })
    assertFalse("g1" in st.releasedGates)
  }

  @Test
  fun anUnparseablePreimageFoldsUnverifiedNotAPass() {
    // A preimage that is not the canonical committed-approval serialization: parseCommitted
    // returns null, the fold records it unverified, and no release honors. (The parse's own
    // negative surface is in ApprovalVerificationTest; this is the fold consuming that null.)
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.approvalWithEvidence(
      "g1",
      "operator",
      "n1",
      "d1",
      ApprovalEvidence("test", pubKeyFor("operator"), "sig", "carrier", "g1", "d1", "n1", signedPreimage = "not-a-canonical-array"),
    )
    s.release("g1", "d1", nonce = "n1")
    val st = s.lead()
    assertTrue(st.verifiedApprovals.isEmpty())
    assertTrue(st.unverifiedApprovals.any { "not a canonical committed approval" in it.second })
    assertFalse("g1" in st.releasedGates)
  }

  @Test
  fun aQuorumTreeGatesReleaseOverDistinctVerifiedApprovers() {
    // Release gates on the FOLD's quorum tree, evaluated over the verified-approver set: a
    // 2-group root needs an approver in each group. One approval leaves it unmet (the release
    // folds stale); a second, in the other group, meets it — order-independent, since a
    // quorum is a property of the set, not the arrival sequence.
    val auth =
      LeadAuth(
        allowList = allowListOf("council-a", "ops-a"),
        verifier = acceptingVerifier,
        quorum =
          QuorumGroup(
            2,
            listOf(
              QuorumGroup(1, listOf(SignerLeaf("council-a"))),
              QuorumGroup(1, listOf(SignerLeaf("ops-a"))),
            ),
          ),
      )
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")

    // Only one group represented: quorum unmet, the release folds stale (n1 not consumed).
    s.approvalFor("g1", "ops-a", "n1", "d1")
    s.release("g1", "d1", nonce = "n1")
    assertFalse("g1" in s.leadWith(auth).releasedGates)

    // A second, distinct approver from the other group meets the 2-of-2 root; a fresh release
    // over the same (still-unconsumed) nonce now honors.
    s.approvalFor("g1", "council-a", "n1", "d1")
    s.release("g1", "d1", nonce = "n1")
    assertTrue("g1" in s.leadWith(auth).releasedGates)
  }

  @Test
  fun foldTimeVerificationIsAFunctionOfAuthNotJournalAlone() {
    // The recovery contract 2b widens: state is a function of (journal, auth). One journal,
    // folded under two LeadAuths that differ ONLY in the allow-list. Under one that lists the
    // signer, the ceremony release reaches quorum and the gate releases; re-fold the SAME
    // journal under one that has REVOKED that principal and the same release folds stale — the
    // gate is no longer released. Authorization is re-decided at recovery, not frozen at write.
    val s = open(newStoreDir())
    s.gateOpened("g1", "d1")
    s.nonceIssued("n1", "g1", "d1")
    s.approvalFor("g1", "council-a", "n1", "d1")
    s.release("g1", "d1", nonce = "n1")

    val granting = LeadAuth(allowListOf("council-a"), acceptingVerifier, oneOfOne("council-a"))
    val revoked = LeadAuth(allowListOf("ops-a"), acceptingVerifier, oneOfOne("council-a"))

    assertTrue("g1" in s.leadWith(granting).releasedGates)
    val refolded = s.leadWith(revoked)
    assertFalse("g1" in refolded.releasedGates)
    assertEquals(1, refolded.staleReleases.size)
  }

  @Test
  fun theSignatureIsVerifiedOverTheSamePreimageTheFoldParses() {
    // Provenance anchored on an INDEPENDENT hash, not codec self-agreement: the verifier
    // accepts iff the signature equals sha256(preimage) computed here in the test. An approval
    // signed over the SAME canonical preimage the fold parses verifies and releases; one
    // signed over OTHER bytes does not.
    val shaVerifier =
      ApprovalVerifier { _, _, signature, preimage -> signature == "sha256:" + sha256Hex(preimage) }
    val auth = LeadAuth(allowListOf("operator"), shaVerifier, oneOfOne("operator"))
    val pk = pubKeyFor("operator")

    val good = open(newStoreDir())
    good.gateOpened("g1", "d1")
    good.nonceIssued("n1", "g1", "d1")
    val preimage = committedPreimage(pk, "g1", "d1", "n1")
    good.approvalWithEvidence(
      "g1",
      "operator",
      "n1",
      "d1",
      ApprovalEvidence("test", pk, "sha256:" + sha256Hex(preimage), "carrier", "g1", "d1", "n1", signedPreimage = preimage),
    )
    good.release("g1", "d1", nonce = "n1")
    assertTrue("g1" in good.leadWith(auth).releasedGates)

    val bad = open(newStoreDir())
    bad.gateOpened("g1", "d1")
    bad.nonceIssued("n1", "g1", "d1")
    bad.approvalWithEvidence(
      "g1",
      "operator",
      "n1",
      "d1",
      ApprovalEvidence("test", pk, "sha256:" + sha256Hex("not the preimage"), "carrier", "g1", "d1", "n1", signedPreimage = preimage),
    )
    bad.release("g1", "d1", nonce = "n1")
    val st = bad.leadWith(auth)
    assertFalse("g1" in st.releasedGates)
    assertTrue(st.unverifiedApprovals.any { "does not verify" in it.second })
  }
}
