package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.JsonUnquotedLiteral
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The gate-open nonce mint (2a.4 step A): the substrate mints a single-use nonce the moment
 * it journals a gate-open, but ONLY under a ceremony auth. The predicate is
 * [LeadAuth.hasApprovers] — the same one the release fold reads to refuse a nonce-less
 * release ([LeadState.foldRelease]); one predicate, read at both the write and the fold. A
 * gate-open that a crash cut short before its mint is minted at the next wake, on the same
 * terms, and so is a gate a DENY_ALL daemon opened, once the daemon restarts under a ceremony
 * auth. The honest [ScriptedCognition] walk drives a real plan-gate-open, so these cells
 * exercise the write path end to end; the journal states the daemon does not produce on its
 * own (a voided nonce, a release, a re-open on a new or blank digest, a blank recorded digest, a
 * gate under a blank id, another ticket's or a kind the lead never opens, a nonce on a digest that is
 * not the evidence, a digest, claimed ticket ref or nonce holding a lone surrogate) are hand-appended
 * on top of it. A gate under an id a stage of the current ticket waits on, that has no usable
 * nonce, that the mint issues none for, and that no release has cleared on its digest is escalated
 * as stalled, once per gate and digest: at once when its recorded kind is not the kind its id
 * names, and otherwise once evidence is recorded for its kind.
 */
class NonceMintTest {

  @get:Rule val tmp = TemporaryFolder()

  /** A timer service that fires nothing, since no cell here needs a timer to fire. A daemon under a
   * ceremony auth refuses [TimerService.NOOP], which is the service a deployment could pick up by
   * mistake, so the helper passes this one, built here. */
  private val timersNoCellFires = TimerService { _, _ -> }

  private fun daemon(
    dir: File,
    store: SqliteStore,
    auth: LeadAuth,
    cognition: CognitionStrategy = ScriptedCognition(),
    runner: PodRunner = FakePodRunner(),
    faults: FaultInjector = FaultInjector.NONE,
    sink: GateOpenSink = NoOpGateOpenSink,
  ): LeadDaemon {
    File(dir, "ticket.txt").also { if (!it.exists()) it.writeText("t1\n") }
    return LeadDaemon(
      store = store,
      cognition = cognition,
      podRunner = runner,
      podSpec = PodSpec.fixture(),
      ticketSource = FileTicketSource(File(dir, "ticket.txt")),
      workdir = dir,
      effects = EffectReceiver(dir.absolutePath),
      leadAuth = auth,
      timers = timersNoCellFires,
      faults = faults,
      gateOpenSink = sink,
    )
  }

  @Test
  fun aCeremonyDaemonMintsANonceBoundToTheOpenedGateAndItsDigest() {
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()

    val planGateId = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    val digest = f.lead.planArtifactSha
    assertNotNull("the honest walk recorded a plan-artifact digest", digest)

    // Exactly one nonce, bound to the gate that opened AND the digest it opened on. Asserting
    // BOTH bindings against distinct recorded values (planGateId vs the plan-artifact sha) is
    // what makes this non-vacuous: a mint that wrote the wrong field, or an empty nonce, fails.
    assertEquals("one nonce minted at gate-open under a ceremony auth", 1, f.lead.issuedNonces.size)
    val nonce = f.lead.issuedNonces.values.single()
    assertEquals("nonce bound to the opened gate", planGateId, nonce.gateId)
    assertEquals("nonce bound to the gate's digest", digest, nonce.payloadDigest)
    assertTrue("the minted nonce is a non-blank value", nonce.nonce.isNotBlank())

    // The notifier's accessor resolves it: bound to the gate's CURRENT digest, unconsumed.
    val open = f.lead.openGates[planGateId]
    assertNotNull("the plan gate is open", open)
    assertEquals("openNonceFor resolves the minted nonce", nonce, f.lead.openNonceFor(open!!))
    store.close()
  }

  @Test
  fun aPreCeremonyDenyAllDaemonMintsNoNonceThoughItOpensTheGate() {
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f = daemon(dir, store, LeadAuth.DENY_ALL).driveUntilQuiescent()

    val planGateId = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    // Non-vacuous: the gate DID open, so "no nonce" is a real negative and not an empty
    // pipeline that never reached the mint site at all.
    assertTrue("the plan gate opened", planGateId in f.lead.openGates)
    assertTrue("DENY_ALL mints no nonce", f.lead.issuedNonces.isEmpty())
    store.close()
  }

  @Test
  fun aCrashBetweenGateOpenAndMintIsMintedAtTheNextWakeAndStillNotBypassable() {
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val afterCrash = crashAfterGateOpened(dir, store, GateKinds.PLAN_APPROVAL)
    assertTrue("the gate opened before the crash", PLAN_GATE in afterCrash.openGates)
    assertTrue("the crash left the gate nonce-less", afterCrash.issuedNonces.isEmpty())

    // A fresh process adopts the orphaned journal, and a nonce-less release is attempted. The
    // wake mints the orphan's nonce, bound to the digest the gate opened on, and announces it,
    // while the release fold still refuses the nonce-less release under a ceremony auth.
    val d2 = daemon(dir, store, ceremonyAuth())
    d2.injectAuthRelease(PLAN_GATE, afterCrash.planArtifactSha!!)
    val f = d2.driveUntilQuiescent()
    val minted = planNonces(f.lead)
    assertEquals("the wake mints one nonce for the orphan", 1, minted.size)
    assertEquals("bound to the gate's digest", afterCrash.planArtifactSha, minted[0].payloadDigest)
    assertTrue("the minted nonce is announced", minted[0].nonce in f.lead.notifiedNonces)
    assertTrue("the orphan the mint recovers is not escalated as stalled", stalls(f.lead, PLAN_GATE).isEmpty())
    assertFalse("the gate is NOT released", PLAN_GATE in f.lead.releasedGates)
    assertTrue(
      "the nonce-less release folded stale",
      f.lead.staleReleases.any { it.second == PLAN_GATE },
    )
    // No sink is wired, so the announce was escalated too. That escalation must not silence the
    // playbook's escalation of the refused release: each is a different thing for a human to see.
    assertTrue(
      "the gate-open no sink announced is escalated",
      f.lead.escalations.any { it.startsWith("gate-open notify had no sink") },
    )
    assertEquals(
      "the refused release is escalated once",
      1,
      f.lead.escalations.count { it == "stale gate release observed (digest mismatch)" },
    )

    val again = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertEquals("a second restart mints nothing more", minted, planNonces(again.lead))
    assertEquals(
      "a second restart does not escalate the refused release again",
      1,
      again.lead.escalations.count { it == "stale gate release observed (digest mismatch)" },
    )
    store.close()
  }

  @Test
  fun aCrashBetweenTheCommitGateOpenAndItsMintIsMintedAtTheNextWake() {
    // The commit gate's evidence is the commit manifest's digest, not the plan artifact's.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f1 = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val planNonce = planNonces(f1.lead).single().nonce
    store.approveAndRelease(PLAN_GATE, f1.lead.planArtifactSha!!, planNonce)
    val afterCrash = crashAfterGateOpened(dir, store, GateKinds.COMMIT_APPROVAL)
    assertTrue("the commit gate opened before the crash", COMMIT_GATE in afterCrash.openGates)
    assertTrue(
      "the crash left the commit gate nonce-less",
      afterCrash.issuedNonces.values.none { it.gateId == COMMIT_GATE },
    )

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val minted = f.lead.issuedNonces.values.filter { it.gateId == COMMIT_GATE }
    assertEquals("the wake mints one nonce for the commit gate", 1, minted.size)
    assertEquals(
      "bound to the commit manifest's digest",
      afterCrash.commitManifestDigest,
      minted[0].payloadDigest,
    )
    assertTrue("the minted nonce is announced", minted[0].nonce in f.lead.notifiedNonces)
    assertTrue("the orphan the mint recovers is not escalated as stalled", stalls(f.lead, COMMIT_GATE).isEmpty())
    store.close()
  }

  @Test
  fun aGateWhoseNonceWasVoidedIsNotReMinted() {
    // The gate is open with no usable nonce, but it was issued one: minting another for the
    // same digest would re-authorize the payload the void withdrew.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val issued = planNonces(daemon(dir, store, ceremonyAuth()).driveUntilQuiescent().lead)
    assertEquals("the gate-open minted one nonce", 1, issued.size)
    store.append(
      LeadKinds.NONCE_CONSUMED,
      buildJsonObject {
        put("nonce", issued[0].nonce)
        put("reason", "voided")
      },
      ORIGIN_SUBSTRATE,
    )

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertTrue("the void holds", issued[0].nonce in f.lead.consumedNonces)
    assertEquals("no nonce is minted in its place", issued, planNonces(f.lead))
    store.close()
  }

  @Test
  fun aGateReleasedOnItsNonceIsNotReMinted() {
    // An approved gate stays open until its ticket is done, and its release consumed its nonce,
    // so every later wake sees it open with no usable nonce. It was issued one, so none is minted.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f1 = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val issued = planNonces(f1.lead)
    assertEquals("the gate-open minted one nonce", 1, issued.size)
    store.approveAndRelease(PLAN_GATE, f1.lead.planArtifactSha!!, issued[0].nonce)

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertTrue("the plan gate is released", f.lead.approvedOnCurrentDigest(PLAN_GATE))
    assertEquals("no nonce is minted for the released gate", issued, planNonces(f.lead))
    store.close()
  }

  @Test
  fun aDenyAllDaemonMintsNoNonceForAnOpenGateAtRestart() {
    // Under DENY_ALL every open gate is nonce-less by design: its release path is the nonce-less
    // one, and a minted nonce would need a quorum no approver can satisfy.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    daemon(dir, store, LeadAuth.DENY_ALL).driveUntilQuiescent()
    val f = daemon(dir, store, LeadAuth.DENY_ALL).driveUntilQuiescent()
    assertTrue("the plan gate is open", PLAN_GATE in f.lead.openGates)
    assertTrue("a restart under DENY_ALL mints nothing", f.lead.issuedNonces.isEmpty())
    store.close()
  }

  @Test
  fun aGateADenyAllDaemonOpenedGetsANonceOnceTheDaemonRestartsUnderACeremonyAuth() {
    // DENY_ALL opens the gate and mints nothing, so a restart under a ceremony auth finds an open
    // gate with no nonce, as a crash before the mint leaves one. The auth in force now decides:
    // the gate gets one nonce, bound to its digest, and the nonce is announced.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val pre = daemon(dir, store, LeadAuth.DENY_ALL).driveUntilQuiescent().lead
    assertTrue("the plan gate opened under DENY_ALL", PLAN_GATE in pre.openGates)
    assertTrue("DENY_ALL minted nothing", pre.issuedNonces.isEmpty())

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val minted = planNonces(f.lead)
    assertEquals("the ceremony restart mints one nonce", 1, minted.size)
    assertEquals("bound to the gate's digest", pre.planArtifactSha, minted[0].payloadDigest)
    assertTrue("the minted nonce is announced", minted[0].nonce in f.lead.notifiedNonces)
    assertTrue("the gate the mint recovers is not escalated as stalled", stalls(f.lead, PLAN_GATE).isEmpty())
    store.close()
  }

  @Test
  fun anOrphanWhoseEvidenceMovedGetsNoNonce() {
    // A gate opens only on the digest the substrate records as evidence for its kind. The mint a
    // wake owes an orphan finishes that gate-open, so it checks the same thing: a plan artifact
    // recorded since the gate opened means the gate's digest is superseded, and gets no nonce.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val afterCrash = crashAfterGateOpened(dir, store, GateKinds.PLAN_APPROVAL)
    store.planArtifactRecorded(afterCrash.planArtifactPath!!, OTHER_DIGEST)

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertEquals(
      "the gate is still open on the digest it opened on",
      afterCrash.planArtifactSha,
      f.lead.openGates[PLAN_GATE]?.payloadDigest,
    )
    assertTrue("no nonce is minted for a superseded digest", f.lead.issuedNonces.isEmpty())
    store.close()
  }

  @Test
  fun aGateReOpenedOnANewDigestGetsANonceBoundToIt() {
    // The daemon opens a gate at most once per ticket, so a gate re-opened on a new digest reaches
    // the fold only from the journal. The nonce the first open got is bound to the old digest and
    // cannot release the new one, so a nonce is minted for the new digest.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f1 = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val first = planNonces(f1.lead)
    assertEquals("the gate-open minted one nonce", 1, first.size)
    store.planArtifactRecorded(f1.lead.planArtifactPath!!, OTHER_DIGEST)
    store.append(
      LeadKinds.GATE_OPENED,
      buildJsonObject {
        put("gateId", PLAN_GATE)
        put("gateKind", GateKinds.PLAN_APPROVAL)
        put("payloadDigest", OTHER_DIGEST)
      },
      ORIGIN_SUBSTRATE,
    )

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val nonces = planNonces(f.lead)
    assertEquals("the first open's nonce, then one for the new digest", 2, nonces.size)
    assertEquals("the first is unchanged", first[0], nonces[0])
    assertEquals("the second is bound to the new digest", OTHER_DIGEST, nonces[1].payloadDigest)
    assertEquals(
      "and it is the gate's usable nonce",
      nonces[1],
      f.lead.openNonceFor(f.lead.openGates.getValue(PLAN_GATE)),
    )
    store.close()
  }

  @Test
  fun aGateOpenOnABlankDigestGetsNoNonceAndTheJournalStillFolds() {
    // A blank recorded digest is no evidence. A nonce bound to it would make every later fold of
    // the journal fail, so a gate open on one is left without a nonce.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f1 = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val first = planNonces(f1.lead)
    assertEquals("the gate-open minted one nonce", 1, first.size)
    store.planArtifactRecorded(f1.lead.planArtifactPath!!, "")
    store.append(
      LeadKinds.GATE_OPENED,
      buildJsonObject {
        put("gateId", PLAN_GATE)
        put("gateKind", GateKinds.PLAN_APPROVAL)
        put("payloadDigest", "")
      },
      ORIGIN_SUBSTRATE,
    )

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertEquals("the gate is open on the blank digest", "", f.lead.openGates[PLAN_GATE]?.payloadDigest)
    assertEquals("no nonce is minted for it", first, planNonces(f.lead))
    val escalated = stalls(f.lead, PLAN_GATE)
    assertEquals("the gate on the blank digest is escalated as stalled once", 1, escalated.size)
    assertTrue(
      "the escalation says the recorded evidence is not in the substrate's form",
      escalated[0].contains("because $MALFORMED_EVIDENCE — "),
    )
    assertEquals("the journal still folds", first, planNonces(leadFold(store.readAll(), ceremonyAuth())))
    store.close()
  }

  @Test
  fun aGateOpenProposedOnABlankRecordedDigestIsRejectedAndTheJournalStillFolds() {
    // The gate-open half of the blank rule. The honest walk proposes the recorded plan digest as
    // it is, so a blank recorded digest reaches the gate-open itself, which must refuse it rather
    // than open the gate and bind a nonce to the blank digest.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val beforeGateOpen = crashAfterPlanRecorded(dir, store)
    store.planArtifactRecorded(beforeGateOpen.planArtifactPath!!, "")

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertFalse("the plan gate stays closed", PLAN_GATE in f.lead.openGates)
    assertTrue("no nonce is minted", f.lead.issuedNonces.isEmpty())
    assertTrue(
      "the gate-open is rejected with an escalation",
      f.lead.escalations.any { it.startsWith("gate-open rejected for $PLAN_GATE") },
    )
    assertTrue("the journal still folds", leadFold(store.readAll(), ceremonyAuth()).issuedNonces.isEmpty())
    store.close()
  }

  @Test
  fun aGateOpenUnderABlankIdGetsNoNonceAndTheJournalStillFolds() {
    // The daemon never builds a blank gate id, but the fold opens a gate under one. A nonce bound
    // to a blank id would make every later fold of the journal fail, so that gate gets none.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f1 = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val first = planNonces(f1.lead)
    assertEquals("the gate-open minted one nonce", 1, first.size)
    store.append(
      LeadKinds.GATE_OPENED,
      buildJsonObject {
        put("gateId", "")
        put("gateKind", GateKinds.PLAN_APPROVAL)
        put("payloadDigest", f1.lead.planArtifactSha!!)
      },
      ORIGIN_SUBSTRATE,
    )

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertTrue("the fold opened a gate under the blank id", "" in f.lead.openGates)
    assertEquals("no nonce is minted for it", first, f.lead.issuedNonces.values.toList())
    assertEquals(
      "the journal still folds",
      first,
      leadFold(store.readAll(), ceremonyAuth()).issuedNonces.values.toList(),
    )
    store.close()
  }

  @Test
  fun aGateOpenUnderAnotherTicketsIdGetsNoNonce() {
    // The gate-open opens only the gate id it derives for the current ticket, so a gate open under
    // another ticket's id reaches the fold only from the journal. The mint finishes a gate-open, so
    // that gate gets no nonce, and no operator is asked to approve a gate nothing reads.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f1 = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val first = f1.lead.issuedNonces.values.toList()
    assertEquals("the gate-open minted one nonce", 1, first.size)
    val otherGate = gateIdFor(GateKinds.PLAN_APPROVAL, "t2")
    store.append(
      LeadKinds.GATE_OPENED,
      buildJsonObject {
        put("gateId", otherGate)
        put("gateKind", GateKinds.PLAN_APPROVAL)
        put("payloadDigest", f1.lead.planArtifactSha!!)
      },
      ORIGIN_SUBSTRATE,
    )

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertEquals("the current ticket is still t1", "t1", f.lead.currentTicket)
    assertTrue("the fold opened the other ticket's gate", otherGate in f.lead.openGates)
    assertEquals("no nonce is minted for it", first, f.lead.issuedNonces.values.toList())
    store.close()
  }

  @Test
  fun aGateReOpenedOnADigestHoldingALoneSurrogateGetsNoNonceAndTheWakeConverges() {
    // The substrate records a digest as hex, so a digest holding a lone surrogate reaches the fold
    // only from a journal that wrote the surrogate as a JSON escape. The digest is not in the form
    // the substrate records, so it is not the gate's evidence, and the gate gets no nonce.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f1 = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val first = planNonces(f1.lead)
    assertEquals("the gate-open minted one nonce", 1, first.size)
    store.append(
      LeadKinds.PLAN_ARTIFACT_RECORDED,
      buildJsonObject {
        put("path", f1.lead.planArtifactPath!!)
        put("sha256", escapedLoneSurrogateAfter("ab"))
      },
      ORIGIN_SUBSTRATE,
    )
    store.append(
      LeadKinds.GATE_OPENED,
      buildJsonObject {
        put("gateId", PLAN_GATE)
        put("gateKind", GateKinds.PLAN_APPROVAL)
        put("payloadDigest", escapedLoneSurrogateAfter("ab"))
      },
      ORIGIN_SUBSTRATE,
    )

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertEquals(
      "the gate is open on the digest with its surrogate",
      "ab$LONE_SURROGATE",
      f.lead.openGates[PLAN_GATE]?.payloadDigest,
    )
    assertEquals("no nonce is minted for it", first, planNonces(f.lead))
    val escalated = stalls(f.lead, PLAN_GATE)
    assertEquals("the gate on that digest is escalated as stalled once", 1, escalated.size)
    assertTrue(
      "the escalation says the recorded evidence is not in the substrate's form",
      escalated[0].contains("because $MALFORMED_EVIDENCE — "),
    )
    store.close()
  }

  @Test
  fun aClaimHoldingALoneSurrogateStopsEveryDriveWithNothingAppended() {
    // The claim accepts only ticket refs in an ASCII charset, so a claimed ref holding a lone
    // surrogate reaches the journal only from a writer other than the lead. The fold refuses that
    // claim, so the lead derives no gate id, nonce or announce from it: each drive stops at its
    // first fold, with nothing appended.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val announced = mutableListOf<String>()
    val sink = GateOpenSink { signal ->
      announced += signal.gateId
      AnnounceOutcome.Announced("delivered")
    }
    daemon(dir, store, ceremonyAuth(), sink = sink).driveUntilQuiescent()
    assertEquals("the honest walk announced its plan gate", listOf(PLAN_GATE), announced)
    val claim =
      store.append(
        LeadKinds.TICKET_CLAIMED,
        buildJsonObject { put("ticketRef", escapedLoneSurrogateAfter("t")) },
        ORIGIN_SUBSTRATE,
      )
    val rows = store.readAll().size

    repeat(3) { drive ->
      val e =
        assertThrows("drive ${drive + 1}: the fold refuses the claim", LeadFoldException::class.java) {
          daemon(dir, store, ceremonyAuth(), sink = sink).driveUntilQuiescent()
        }
      assertTrue("drive ${drive + 1}: the fault names the claim", e.message!!.contains("seq=${claim.seq}"))
      assertEquals(
        "drive ${drive + 1}: nothing was appended, so no gate-open, nonce or marker",
        rows,
        store.readAll().size,
      )
    }
    assertEquals("nothing further was announced", listOf(PLAN_GATE), announced)
    store.close()
  }

  @Test
  fun aNonceHoldingALoneSurrogateIsAnnouncedOnceAndEveryWakeConverges() {
    // The daemon mints a nonce as hex, so a nonce holding a lone surrogate reaches the fold only
    // from a journal that wrote the surrogate as a JSON escape. The journal stores the notify marker
    // for it in the same escaped form and reads it back as written, so the marker matches the
    // nonce: it is announced once, and no later pass or wake announces it again.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f1 = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    store.append(
      LeadKinds.NONCE_ISSUED,
      buildJsonObject {
        put("nonce", escapedLoneSurrogateAfter("n"))
        put("gateId", PLAN_GATE)
        put("payloadDigest", f1.lead.planArtifactSha!!)
      },
      ORIGIN_SUBSTRATE,
    )
    val announced = mutableListOf<String>()
    val sink = GateOpenSink { signal ->
      announced += signal.nonce
      AnnounceOutcome.Announced("delivered")
    }

    repeat(3) { daemon(dir, store, ceremonyAuth(), sink = sink).driveUntilQuiescent() }
    val nonce = "n$LONE_SURROGATE"
    assertEquals("announced once across three wakes", listOf(nonce), announced)
    val markers = store.readAll().filter { it.kind == LeadKinds.GATE_OPEN_NOTIFIED }
    assertEquals("a marker for the walk's own nonce, then one for this one", 2, markers.size)
    assertTrue(
      "its marker reads back as written",
      nonce in leadFold(store.readAll(), ceremonyAuth()).notifiedNonces,
    )
    store.close()
  }

  @Test
  fun aCommitGateOpenOnAnotherDigestIsEscalatedOnceAsStalled() {
    // The journal opens the commit gate on a digest that is not the manifest's, before the lead
    // records the manifest, and issues it no nonce. While no manifest is recorded the gate is not
    // escalated, since the manifest may yet be its digest. Once the lead records it, the mint issues
    // no nonce for a digest that is not the evidence, and the lead's own commit gate-open is
    // skipped, since that gate id is open. No release can clear the gate, and it blocks the commit,
    // so it is escalated once, across restarts, naming the manifest its digest does not match.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f1 = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val planNonce = planNonces(f1.lead).single().nonce
    store.gateOpened(COMMIT_GATE, GateKinds.COMMIT_APPROVAL, OTHER_DIGEST)
    store.approveAndRelease(PLAN_GATE, f1.lead.planArtifactSha!!, planNonce)

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val manifest = f.lead.commitManifestDigest
    assertNotNull("the lead recorded the commit manifest", manifest)
    assertEquals(
      "the commit gate is still open on the other digest",
      OTHER_DIGEST,
      f.lead.openGates[COMMIT_GATE]?.payloadDigest,
    )
    assertEquals(
      "the lead opened no commit gate of its own",
      1,
      store.readAll().count { it.kind == LeadKinds.GATE_OPENED && it.payloadJson.contains("\"$COMMIT_GATE\"") },
    )
    assertTrue("the commit gate has no nonce", f.lead.issuedNonces.values.none { it.gateId == COMMIT_GATE })
    val escalated = stalls(f.lead, COMMIT_GATE)
    assertEquals("the stalled commit gate is escalated once", 1, escalated.size)
    assertTrue(
      "the escalation names the manifest the gate's digest does not match",
      escalated[0].contains("because its digest of 64 chars is not the recorded evidence ${manifest!!.take(16)} — "),
    )
    assertTrue(
      "the escalation says no operator will be asked",
      escalated[0].contains("no operator will be asked to approve it"),
    )
    assertFalse("the escalation quotes no part of the gate's digest", escalated[0].contains(OTHER_DIGEST.take(8)))
    assertFalse("t1 is not done", "t1" in f.lead.doneTickets)

    val again = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertEquals("a restart escalates it no more", 1, stalls(again.lead, COMMIT_GATE).size)
    store.close()
  }

  @Test
  fun aCommitGateOpenOnItsManifestBeforeTheManifestIsRecordedIsMintedNotEscalated() {
    // The journal opens the commit gate before the lead records the manifest, on the digest the
    // manifest then has. The gate waits unescalated while no manifest is recorded. Once the lead
    // records it, the gate's digest is the evidence, so the mint issues it a nonce and a release
    // clears it: it was never a stall.
    val manifest = honestManifestDigest()
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f1 = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    store.gateOpened(COMMIT_GATE, GateKinds.COMMIT_APPROVAL, manifest)
    store.approveAndRelease(PLAN_GATE, f1.lead.planArtifactSha!!, planNonces(f1.lead).single().nonce)

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertEquals("this journal's manifest is the one the gate was opened on", manifest, f.lead.commitManifestDigest)
    assertEquals(
      "the lead opened no commit gate of its own",
      1,
      store.readAll().count { it.kind == LeadKinds.GATE_OPENED && it.payloadJson.contains("\"$COMMIT_GATE\"") },
    )
    assertNotNull("the commit gate has a usable nonce", f.lead.openNonceFor(f.lead.openGates.getValue(COMMIT_GATE)))
    assertTrue("the gate is not escalated as stalled", stalls(f.lead, COMMIT_GATE).isEmpty())

    val commitNonce = f.lead.issuedNonces.values.single { it.gateId == COMMIT_GATE }.nonce
    store.approveAndRelease(COMMIT_GATE, manifest, commitNonce)
    val done = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertTrue("a release cleared the gate and t1 is done", "t1" in done.lead.doneTickets)
    assertTrue(
      "no gate was escalated as stalled",
      done.lead.escalations.none { it.startsWith("gate-open stalled") },
    )
    assertTrue(
      "nor as released off its evidence: each release was on the evidence for its kind",
      done.lead.escalations.none { it.startsWith("gate released off its evidence") },
    )
    store.close()
  }

  @Test
  fun anOrphanWhoseEvidenceMovedIsEscalatedOnceAsStalled() {
    // The state anOrphanWhoseEvidenceMovedGetsNoNonce builds: the gate has no nonce and gets none, so
    // no release can clear it and nothing announces it. It blocks the execute pod, so it is escalated,
    // naming the evidence its digest does not match, once across restarts.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val afterCrash = crashAfterGateOpened(dir, store, GateKinds.PLAN_APPROVAL)
    store.planArtifactRecorded(afterCrash.planArtifactPath!!, OTHER_DIGEST)

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertTrue("no nonce is minted", f.lead.issuedNonces.isEmpty())
    val escalated = stalls(f.lead, PLAN_GATE)
    assertEquals("the stalled plan gate is escalated once", 1, escalated.size)
    assertTrue(
      "the escalation gives the gate's digest by its length and names the evidence it does not match",
      escalated[0].contains("because its digest of 64 chars is not the recorded evidence ${OTHER_DIGEST.take(16)} — "),
    )
    assertFalse(
      "the escalation quotes no part of the gate's digest",
      escalated[0].contains(afterCrash.planArtifactSha!!.take(8)),
    )

    val again = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertEquals("a restart escalates it no more", 1, stalls(again.lead, PLAN_GATE).size)
    store.close()
  }

  @Test
  fun aGateWhoseNonceWasVoidedIsEscalatedOnceAsStalled() {
    // The mint issues no second nonce on a digest that had one, so a gate whose nonce was voided has
    // none a release can name. It is escalated once, across restarts.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val issued = planNonces(daemon(dir, store, ceremonyAuth()).driveUntilQuiescent().lead).single()
    store.append(
      LeadKinds.NONCE_CONSUMED,
      buildJsonObject {
        put("nonce", issued.nonce)
        put("reason", "voided")
      },
      ORIGIN_SUBSTRATE,
    )

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val escalated = stalls(f.lead, PLAN_GATE)
    assertEquals("the gate is escalated once", 1, escalated.size)
    assertTrue(
      "the escalation names the nonce its digest already had",
      escalated[0].contains("a nonce was already issued on its digest"),
    )

    val again = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertEquals("a restart escalates it no more", 1, stalls(again.lead, PLAN_GATE).size)
    store.close()
  }

  @Test
  fun aStalledGateReOpenedOnAnotherDigestIsEscalatedOnceMore() {
    // One escalation per gate and digest: the gate re-opened on a second digest that is not the
    // evidence either is a stall of its own, escalated once in its turn.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val afterCrash = crashAfterGateOpened(dir, store, GateKinds.PLAN_APPROVAL)
    store.planArtifactRecorded(afterCrash.planArtifactPath!!, OTHER_DIGEST)
    val first = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertEquals("the first digest is escalated once", 1, stalls(first.lead, PLAN_GATE).size)
    store.gateOpened(PLAN_GATE, GateKinds.PLAN_APPROVAL, THIRD_DIGEST)

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertEquals("the second digest is escalated once more", 2, stalls(f.lead, PLAN_GATE).size)
    val again = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertEquals("a restart escalates neither again", 2, stalls(again.lead, PLAN_GATE).size)
    store.close()
  }

  @Test
  fun aGateWithAUsableNonceOrReleasedOnItsDigestIsNotEscalatedAsStalled() {
    // The honest walk leaves the plan gate open with its nonce, then, once the plan is approved,
    // the plan gate released and the commit gate open with its nonce. A gate opens in cognition's
    // turn, after that wake's mechanical pass, so each state is driven again from a restart, whose
    // pass sees the gates open. A release can clear each gate or has, so none is a stall.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val f1 = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertNotNull(
      "the plan gate has a usable nonce",
      f1.lead.openNonceFor(f1.lead.openGates.getValue(PLAN_GATE)),
    )
    assertTrue("it is not escalated as stalled", stalls(f1.lead, PLAN_GATE).isEmpty())
    store.approveAndRelease(PLAN_GATE, f1.lead.planArtifactSha!!, planNonces(f1.lead).single().nonce)

    daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertTrue("the plan gate is released", f.lead.approvedOnCurrentDigest(PLAN_GATE))
    assertNotNull(
      "the commit gate has a usable nonce",
      f.lead.openNonceFor(f.lead.openGates.getValue(COMMIT_GATE)),
    )
    assertTrue(
      "no gate is escalated as stalled",
      f.lead.escalations.none { it.startsWith("gate-open stalled") },
    )
    store.close()
  }

  @Test
  fun aDenyAllDaemonEscalatesNoGateAsStalled() {
    // Under DENY_ALL a gate that never had a nonce is released without one, so a gate whose evidence
    // moved can still be cleared, and it is not a stall.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f1 = daemon(dir, store, LeadAuth.DENY_ALL).driveUntilQuiescent()
    store.planArtifactRecorded(f1.lead.planArtifactPath!!, OTHER_DIGEST)

    val f = daemon(dir, store, LeadAuth.DENY_ALL).driveUntilQuiescent()
    assertEquals(
      "the plan gate is open on a digest that is not the evidence",
      f1.lead.planArtifactSha,
      f.lead.openGates[PLAN_GATE]?.payloadDigest,
    )
    assertTrue(
      "no gate is escalated as stalled",
      f.lead.escalations.none { it.startsWith("gate-open stalled") },
    )
    store.close()
  }

  @Test
  fun aGateNoStageOfTheCurrentTicketWaitsOnIsNotEscalatedAsStalled() {
    // Only a gate of a kind the lead opens, under the id the gate-open derives for the current
    // ticket, blocks a stage. Another ticket's gate and a gate of a kind the lead never opens get no
    // nonce, and neither is escalated as stalled.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f1 = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    val otherTicketsGate = gateIdFor(GateKinds.PLAN_APPROVAL, "t2")
    val unknownKindsGate = gateIdFor("review", "t1")
    store.gateOpened(otherTicketsGate, GateKinds.PLAN_APPROVAL, OTHER_DIGEST)
    store.gateOpened(unknownKindsGate, "review", f1.lead.planArtifactSha!!)

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertTrue(
      "both gates are open",
      otherTicketsGate in f.lead.openGates && unknownKindsGate in f.lead.openGates,
    )
    assertTrue(
      "neither gets a nonce",
      f.lead.issuedNonces.values.none { it.gateId == otherTicketsGate || it.gateId == unknownKindsGate },
    )
    assertTrue(
      "no gate is escalated as stalled",
      f.lead.escalations.none { it.startsWith("gate-open stalled") },
    )
    store.close()
  }

  @Test
  fun aGateOfAKindTheLeadNeverOpensUnderThePlanGatesIdIsEscalatedOnceAsStalled() =
    assertAGateOfAnotherKindUnderThePlanGatesIdIsEscalatedOnce("review")

  @Test
  fun aCommitGateUnderThePlanGatesIdIsEscalatedOnceAsStalled() =
    assertAGateOfAnotherKindUnderThePlanGatesIdIsEscalatedOnce(GateKinds.COMMIT_APPROVAL)

  /**
   * The journal opens a [gateKind] gate under the plan gate's id, on the recorded plan's digest,
   * after a crash right after the plan is recorded. The plan stage waits on the gate under that id,
   * whatever kind it records, and the lead's own plan gate-open is skipped, since that id is open.
   * The mint issues the gate no nonce, since its kind does not name its id, so no release can clear
   * it: it is escalated once, across restarts, giving the recorded kind by its length.
   */
  private fun assertAGateOfAnotherKindUnderThePlanGatesIdIsEscalatedOnce(gateKind: String) {
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val beforeGateOpen = crashAfterPlanRecorded(dir, store)
    store.gateOpened(PLAN_GATE, gateKind, beforeGateOpen.planArtifactSha!!)

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertEquals(
      "the gate under the plan gate's id records the other kind",
      gateKind,
      f.lead.openGates[PLAN_GATE]?.gateKind,
    )
    assertEquals(
      "the lead opened no plan gate of its own",
      1,
      store.readAll().count { it.kind == LeadKinds.GATE_OPENED },
    )
    assertTrue("no nonce is minted", f.lead.issuedNonces.isEmpty())
    val escalated = stalls(f.lead, PLAN_GATE)
    assertEquals("the gate is escalated once", 1, escalated.size)
    assertTrue(
      "the escalation gives the recorded kind by its length",
      escalated[0].contains("because its recorded kind of ${gateKind.length} chars is not the kind its id names — "),
    )
    assertFalse("the escalation does not quote the recorded kind", escalated[0].contains(gateKind))

    val again = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertEquals("a restart escalates it no more", 1, stalls(again.lead, PLAN_GATE).size)
    store.close()
  }

  @Test
  fun aGateWithANonceOnADigestThatIsNotTheEvidenceIsEscalatedAsUnresolvedNotAsStalled() {
    // A nonce issued on a digest that is not the evidence reaches the fold only from a journal the
    // lead did not write. Its announce reads the recorded evidence, whose digest does not match the
    // nonce's, so the announce is escalated as unresolved. A release can still name the nonce, so the
    // gate is not a stall.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    store.gateOpened(PLAN_GATE, GateKinds.PLAN_APPROVAL, OTHER_DIGEST)
    store.append(
      LeadKinds.NONCE_ISSUED,
      buildJsonObject {
        put("nonce", "ab".repeat(16))
        put("gateId", PLAN_GATE)
        put("payloadDigest", OTHER_DIGEST)
      },
      ORIGIN_SUBSTRATE,
    )

    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    assertTrue(
      "the announce is escalated as unresolved",
      f.lead.escalations.any {
        it.startsWith("gate-open notify unresolved for $PLAN_GATE") && it.contains("digest-mismatch")
      },
    )
    assertTrue("the gate is not escalated as stalled", stalls(f.lead, PLAN_GATE).isEmpty())
    store.close()
  }

  /**
   * Runs a ceremony daemon until an injected crash lands between a [gateKind] gate's GATE_OPENED
   * and its NONCE_ISSUED, two sequential appends, and returns the state the journal folds to then.
   */
  private fun crashAfterGateOpened(dir: File, store: SqliteStore, gateKind: String): LeadState {
    val crash =
      FaultInjector {
        if (it == "after-gate-opened-$gateKind") {
          throw RuntimeException("crash after gate-opened, before mint")
        }
      }
    val d1 = daemon(dir, store, ceremonyAuth(), faults = crash)
    var threw = false
    try {
      d1.driveUntilQuiescent()
    } catch (e: RuntimeException) {
      threw = true
    }
    assertTrue("the injected crash fired at the post-gate-open seam", threw)
    return d1.refold().lead
  }

  /**
   * Runs a ceremony daemon until an injected crash lands right after the plan is recorded, before
   * the plan gate opens, and returns the state the journal folds to then.
   */
  private fun crashAfterPlanRecorded(dir: File, store: SqliteStore): LeadState {
    val crash =
      FaultInjector {
        if (it == "after-plan-recorded") throw RuntimeException("crash after the plan is recorded")
      }
    val d1 = daemon(dir, store, ceremonyAuth(), faults = crash)
    var threw = false
    try {
      d1.driveUntilQuiescent()
    } catch (e: RuntimeException) {
      threw = true
    }
    assertTrue("the injected crash fired after the plan was recorded", threw)
    val beforeGateOpen = d1.refold().lead
    assertFalse("the plan gate has not opened", PLAN_GATE in beforeGateOpen.openGates)
    return beforeGateOpen
  }

  /** The commit manifest digest the honest walk records for t1, from a journal of its own: the
   * fake pod writes the same manifest on every run. */
  private fun honestManifestDigest(): String {
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f1 = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()
    store.approveAndRelease(PLAN_GATE, f1.lead.planArtifactSha!!, planNonces(f1.lead).single().nonce)
    val manifest = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent().lead.commitManifestDigest
    store.close()
    return checkNotNull(manifest) { "the honest walk recorded no manifest" }
  }

  /** The nonces issued for the plan gate, in issue order. */
  private fun planNonces(lead: LeadState): List<IssuedNonce> =
    lead.issuedNonces.values.filter { it.gateId == PLAN_GATE }.sortedBy { it.issuedSeq }

  /** The escalations that report [gateId] as stalled: open with no nonce a release can name. */
  private fun stalls(lead: LeadState, gateId: String): List<String> =
    lead.escalations.filter { it.startsWith("gate-open stalled for $gateId:") }

  private fun SqliteStore.gateOpened(gateId: String, gateKind: String, digest: String) =
    append(
      LeadKinds.GATE_OPENED,
      buildJsonObject {
        put("gateId", gateId)
        put("gateKind", gateKind)
        put("payloadDigest", digest)
      },
      ORIGIN_SUBSTRATE,
    )

  /** A JSON string of [prefix] then a lone surrogate, spelled as the escape a JSON writer may use
   * for one. It is appended as raw JSON text, so the cell holds the form a journal the lead did not
   * write can have, whatever this store does with a lone surrogate it is given. The fold reads it
   * back as the surrogate. */
  @OptIn(ExperimentalSerializationApi::class)
  private fun escapedLoneSurrogateAfter(prefix: String) =
    JsonUnquotedLiteral("\"" + prefix + LONE_SURROGATE_ESCAPE + "\"")

  private fun SqliteStore.planArtifactRecorded(path: String, digest: String) =
    append(
      LeadKinds.PLAN_ARTIFACT_RECORDED,
      buildJsonObject {
        put("path", path)
        put("sha256", digest)
      },
      ORIGIN_SUBSTRATE,
    )

  private companion object {
    val PLAN_GATE = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    val COMMIT_GATE = gateIdFor(GateKinds.COMMIT_APPROVAL, "t1")
    val OTHER_DIGEST = "0".repeat(64)
    val THIRD_DIGEST = "1".repeat(64)

    /** The mint's refusal for a gate whose kind has evidence recorded in a form the substrate never
     * records one in. */
    const val MALFORMED_EVIDENCE = "the evidence recorded for its kind is not in the form the substrate records"

    /** A high surrogate with no low surrogate after it: not valid Unicode text on its own. */
    val LONE_SURROGATE = Char(0xD800).toString()

    /** The JSON escape for [LONE_SURROGATE]. */
    val LONE_SURROGATE_ESCAPE = "\\" + "ud800"
  }
}
