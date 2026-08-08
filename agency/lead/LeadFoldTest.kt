package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalStore
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SqliteStore
import com.geekinasuit.agency.shared.journal.fold
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Lead fold unit tests: the state machine derives correctly from
 * entries, and the gate teeth are real — wrong-origin releases are never honored (and
 * stay visible in the SHARED fold's rejection list), auth-origin releases with the wrong
 * digest stay pending and visible as stale, and only a faithful release advances state.
 */
class LeadFoldTest {

  @get:Rule val tmp = TemporaryFolder()

  private fun newStore(): JournalStore =
    SqliteStore(tmp.newFolder().absolutePath, componentId = "lead")

  private fun JournalStore.lead(): LeadState = leadFold(readAll())

  // -- small append helpers --------------------------------------------------------------

  private fun JournalStore.claim(t: String) =
    append(LeadKinds.TICKET_CLAIMED, buildJsonObject { put("ticketRef", t) }, ORIGIN_SUBSTRATE)

  private fun JournalStore.planRequested() =
    append(LeadKinds.PLAN_REQUESTED, buildJsonObject {}, ORIGIN_SUBSTRATE)

  private fun JournalStore.podSpawned(podId: String, taskRef: String) =
    append(
      LeadKinds.POD_SPAWNED,
      buildJsonObject {
        put("podId", podId)
        put("sessionId", "sess-$podId")
        put("taskRef", taskRef)
        put("artifactPath", "/tmp/$podId-artifact")
      },
      ORIGIN_SUBSTRATE,
    )

  private fun JournalStore.podResult(podId: String, digest: String) =
    append(
      LeadKinds.POD_RESULT_RECORDED,
      buildJsonObject {
        put("podId", podId)
        put("artifactPath", "/tmp/$podId-artifact")
        put("resultDigest", digest)
        put("costUsd", 0.0)
      },
      ORIGIN_SUBSTRATE,
    )

  private fun JournalStore.planRecorded(sha: String) =
    append(
      LeadKinds.PLAN_ARTIFACT_RECORDED,
      buildJsonObject {
        put("path", "/tmp/plan.md")
        put("sha256", sha)
      },
      ORIGIN_SUBSTRATE,
    )

  private fun JournalStore.gateOpened(gateId: String, gateKind: String, digest: String) =
    append(
      LeadKinds.GATE_OPENED,
      buildJsonObject {
        put("gateId", gateId)
        put("gateKind", gateKind)
        put("payloadDigest", digest)
      },
      ORIGIN_SUBSTRATE,
    )

  private fun JournalStore.release(gateId: String, digest: String, origin: String) =
    append(
      KIND_GATE_RELEASED,
      buildJsonObject {
        put("gateId", gateId)
        put("payloadDigest", digest)
      },
      origin,
    )

  // -- cells -----------------------------------------------------------------------------

  @Test
  fun fullTicketWalkAdvancesPhasesStepwise() {
    val s = newStore()
    assertEquals(TicketPhase.IDLE, s.lead().phase)

    s.claim("t1")
    assertEquals(TicketPhase.CLAIMED, s.lead().phase)
    assertEquals("t1", s.lead().currentTicket)

    s.planRequested()
    assertEquals(TicketPhase.PLAN_REQUESTED, s.lead().phase)

    s.podSpawned("p1", "plan:t1")
    assertEquals(TicketPhase.PLANNING, s.lead().phase)

    s.podResult("p1", "aa11")
    s.planRecorded("aa11")
    assertEquals(TicketPhase.PLAN_RECORDED, s.lead().phase)
    assertEquals("aa11", s.lead().planArtifactSha)

    val planGate = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    s.gateOpened(planGate, GateKinds.PLAN_APPROVAL, "aa11")
    assertEquals(TicketPhase.PLAN_GATED, s.lead().phase)
    assertEquals(listOf(planGate), s.lead().pendingGates.map { it.gateId })

    s.release(planGate, "aa11", ORIGIN_AUTH_LAYER)
    assertEquals(TicketPhase.PLAN_APPROVED, s.lead().phase)
    assertTrue(s.lead().pendingGates.isEmpty())

    s.podSpawned("p2", "execute:t1")
    assertEquals(TicketPhase.EXECUTING, s.lead().phase)

    s.podResult("p2", "bb22")
    assertEquals(TicketPhase.EXECUTED, s.lead().phase)

    s.append(
      LeadKinds.COMMIT_PROPOSED,
      buildJsonObject {
        put("manifestPath", "/tmp/p2-artifact")
        put("manifestDigest", "bb22")
      },
      ORIGIN_SUBSTRATE,
    )
    assertEquals(TicketPhase.COMMIT_PROPOSED, s.lead().phase)

    val commitGate = gateIdFor(GateKinds.COMMIT_APPROVAL, "t1")
    s.gateOpened(commitGate, GateKinds.COMMIT_APPROVAL, "bb22")
    assertEquals(TicketPhase.COMMIT_GATED, s.lead().phase)

    s.release(commitGate, "bb22", ORIGIN_AUTH_LAYER)
    assertEquals(TicketPhase.COMMIT_APPROVED, s.lead().phase)

    s.append(LeadKinds.TICKET_DONE, buildJsonObject { put("ticketRef", "t1") }, ORIGIN_SUBSTRATE)
    val done = s.lead()
    assertEquals(TicketPhase.IDLE, done.phase)
    assertNull(done.currentTicket)
    assertNull(done.planArtifactSha)
    assertNull(done.commitManifestDigest)
    assertEquals(listOf("t1"), done.doneTickets)
    s.close()
  }

  @Test
  fun wrongOriginReleaseIsNeverHonoredAndStaysVisible() {
    val s = newStore()
    s.claim("t1")
    val gate = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    s.gateOpened(gate, GateKinds.PLAN_APPROVAL, "aa11")

    // Forged provenance, correct digest — the red path both folds must hold the line on.
    s.release(gate, "aa11", ORIGIN_COGNITION)
    s.release(gate, "aa11", ORIGIN_SUBSTRATE)

    val lead = s.lead()
    assertTrue(lead.releasedGates.isEmpty())
    assertEquals(listOf(gate), lead.pendingGates.map { it.gateId })
    assertEquals(TicketPhase.PLAN_GATED, lead.phase) // never advanced

    val shared = fold(s.readAll())
    assertEquals(2, shared.rejectedGateReleases.size) // visible, never silently dropped
    assertTrue(shared.gateReleases.isEmpty())
    s.close()
  }

  @Test
  fun staleDigestReleaseStaysPendingAndVisibleUntilFaithfulRelease() {
    val s = newStore()
    s.claim("t1")
    val gate = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    s.gateOpened(gate, GateKinds.PLAN_APPROVAL, "aa11")

    // Authorization origin, but not the digest the gate was opened on.
    s.release(gate, "ffff", ORIGIN_AUTH_LAYER)
    var lead = s.lead()
    assertTrue(lead.releasedGates.isEmpty())
    assertEquals(1, lead.staleReleases.size)
    assertEquals(TicketPhase.PLAN_GATED, lead.phase)

    // The shared fold HONORS it (provenance is its only check) — the digest binding is
    // the lead fold's stricter rule layered on top; the gate still does not open.
    assertEquals(listOf(gate), fold(s.readAll()).gateReleases)

    s.release(gate, "aa11", ORIGIN_AUTH_LAYER)
    lead = s.lead()
    assertEquals(setOf(gate), lead.releasedGates)
    assertEquals(TicketPhase.PLAN_APPROVED, lead.phase)
    s.close()
  }

  @Test
  fun releaseForUnknownGateIsStaleNotHonored() {
    val s = newStore()
    s.claim("t1")
    s.release("no-such-gate", "aa11", ORIGIN_AUTH_LAYER)
    val lead = s.lead()
    assertTrue(lead.releasedGates.isEmpty())
    assertEquals(1, lead.staleReleases.size)
    s.close()
  }

  @Test
  fun podLifecycleTracksActiveResultAndAbandoned() {
    val s = newStore()
    s.claim("t1")
    s.podSpawned("p1", "plan:t1")
    assertEquals(1, s.lead().activePods.size)
    assertEquals("sess-p1", s.lead().pods["p1"]!!.sessionId) // journaled at spawn

    s.append(
      LeadKinds.POD_ABANDONED,
      buildJsonObject {
        put("podId", "p1")
        put("reason", "lead-restart")
      },
      ORIGIN_SUBSTRATE,
    )
    assertTrue(s.lead().activePods.isEmpty())
    assertEquals("lead-restart", s.lead().pods["p1"]!!.abandonedReason)

    s.podSpawned("p2", "plan:t1")
    s.podResult("p2", "cc33")
    val lead = s.lead()
    assertTrue(lead.activePods.isEmpty())
    assertEquals("cc33", lead.podFor("plan:t1")!!.resultDigest) // latest spawn wins
    s.close()
  }

  @Test
  fun podResultWithoutCostFoldsAsUnmeasuredNotZero() {
    val s = newStore()
    s.claim("t1")
    s.podSpawned("p1", "plan:t1")
    // A completion journaled with NO costUsd field (null-not-zero: the daemon omits
    // the field when the transport surfaced no measurement). The fold must read it back
    // as null — never crash on the absence, never fabricate a measured 0.0.
    s.append(
      LeadKinds.POD_RESULT_RECORDED,
      buildJsonObject {
        put("podId", "p1")
        put("artifactPath", "/tmp/p1-artifact")
        put("resultDigest", "aa11")
      },
      ORIGIN_SUBSTRATE,
    )
    val pod = s.lead().pods["p1"]!!
    assertEquals("aa11", pod.resultDigest)
    assertNull("absent cost is unmeasured (null), not zero", pod.costUsd)
    s.close()
  }

  @Test
  fun podResultFoldsBoundPathAndItsAbsenceStaysNullNeverInvented() {
    val s = newStore()
    s.claim("t1")
    s.podSpawned("p1", "plan:t1")
    // Bind-once: the result row names the LEAD-owned bound copy consumers
    // read. The fold carries it verbatim…
    s.append(
      LeadKinds.POD_RESULT_RECORDED,
      buildJsonObject {
        put("podId", "p1")
        put("artifactPath", "/tmp/p1-artifact")
        put("boundPath", "/lead/artifacts-bound/p1")
        put("resultDigest", "aa11")
      },
      ORIGIN_SUBSTRATE,
    )
    assertEquals("/lead/artifacts-bound/p1", s.lead().pods["p1"]!!.boundPath)

    // …and a pre-bind-once row (no boundPath) folds as NULL — missing evidence the
    // consumer abandons on, never a license to fall back to the pod's own artifactPath.
    s.podSpawned("p2", "plan:t1")
    s.append(
      LeadKinds.POD_RESULT_RECORDED,
      buildJsonObject {
        put("podId", "p2")
        put("artifactPath", "/tmp/p2-artifact")
        put("resultDigest", "bb22")
      },
      ORIGIN_SUBSTRATE,
    )
    assertNull(s.lead().pods["p2"]!!.boundPath)
    s.close()
  }

  @Test
  fun podResultWithNonFiniteCostFailsTheFoldClassified() {
    val s = newStore()
    s.claim("t1")
    s.podSpawned("p1", "plan:t1")
    // A PRESENT costUsd must be a finite, non-negative number (the write side journals
    // only such values): "NaN" would pass toDouble silently, so the
    // fold's explicit check must catch it as payload-contract drift, classified with the
    // seq + kind named, never fold it into state.
    s.append(
      LeadKinds.POD_RESULT_RECORDED,
      buildJsonObject {
        put("podId", "p1")
        put("artifactPath", "/tmp/p1-artifact")
        put("resultDigest", "aa11")
        put("costUsd", "NaN")
      },
      ORIGIN_SUBSTRATE,
    )
    try {
      s.lead()
      throw AssertionError("a NaN costUsd must fail the fold classified")
    } catch (expected: LeadFoldException) {
      assertTrue(expected.message!!.contains(LeadKinds.POD_RESULT_RECORDED))
      assertTrue(expected.message!!.contains("non-finite or negative"))
    }
    s.close()
  }

  @Test
  fun resultForUnknownPodIsDroppedVisibly() {
    val s = newStore()
    s.claim("t1")
    s.podResult("ghost", "dd44")
    val lead = s.lead()
    assertTrue(lead.pods.isEmpty()) // still dropped: no spawn record to attach to
    // …but never silently (AGENCY-021): the drop is the backstop for
    // the pod-completion accept-exemption, so it surfaces like every other anomaly.
    assertTrue(lead.escalations.any { it.contains("unknown pod 'ghost'") })
    s.close()
  }

  @Test
  fun statusTailKeepsLastTwenty() {
    val s = newStore()
    for (i in 1..25) {
      s.append(LeadKinds.STATUS_WRITTEN, buildJsonObject { put("status", "s$i") }, ORIGIN_SUBSTRATE)
    }
    val tail = s.lead().statusTail
    assertEquals(20, tail.size)
    assertEquals("s6", tail.first())
    assertEquals("s25", tail.last())
    s.close()
  }

  @Test
  fun substrateKindWithNonSubstrateOriginIsNeverHonoredAndStaysVisible() {
    val s = newStore()
    s.claim("t1")
    // A GATE_OPENED forged with cognition origin must NOT open a gate — provenance teeth are
    // symmetric with the release check. It lands visibly instead.
    s.append(
      LeadKinds.GATE_OPENED,
      buildJsonObject {
        put("gateId", gateIdFor(GateKinds.PLAN_APPROVAL, "t1"))
        put("gateKind", GateKinds.PLAN_APPROVAL)
        put("payloadDigest", "aa11")
      },
      ORIGIN_COGNITION,
    )
    val lead = s.lead()
    assertTrue("no gate may open from a non-substrate origin", lead.openGates.isEmpty())
    assertEquals(TicketPhase.CLAIMED, lead.phase) // never advanced to PLAN_GATED
    assertEquals(1, lead.misOriginedEntries.size)
    assertEquals(LeadKinds.GATE_OPENED, lead.misOriginedEntries.single().second)
    s.close()
  }

  @Test
  fun malformedCognitionAccruesSpendAndStaysApartFromEscalations() {
    val s = newStore()
    s.append(
      LeadKinds.COGNITION_MALFORMED,
      buildJsonObject {
        put("strategy", "ollama")
        put("reason", "unknown proposal type 'deploy'")
        put("attempt", 1)
        put("costUsd", "0.04")
      },
      ORIGIN_SUBSTRATE,
    )
    val lead = s.lead()
    // Countable as its own class of event: a model degrading by emitting near-misses is only
    // measurable if those turns do not blend into the escalations a working model asks for.
    assertEquals(1, lead.malformedCognition.size)
    assertTrue(lead.malformedCognition.single().second.contains("unknown proposal type"))
    assertTrue(lead.escalations.isEmpty())
    // The turn was billed even though it decided nothing — the cap must see that spend.
    assertEquals(0.04, lead.cognitionSpendUsd, 1e-9)
    s.close()
  }

  @Test
  fun malformedCognitionForgedWithCognitionOriginIsNeverHonored() {
    val s = newStore()
    // The row is the SUBSTRATE's observation about the model. A cognition-origin one is a
    // confused deputy — a strategy grading its own output — so it lands visibly instead,
    // and in particular cannot inflate spend to trip the budget cap.
    s.append(
      LeadKinds.COGNITION_MALFORMED,
      buildJsonObject {
        put("reason", "self-reported")
        put("costUsd", "99.0")
      },
      ORIGIN_COGNITION,
    )
    val lead = s.lead()
    assertTrue(lead.malformedCognition.isEmpty())
    assertEquals(0.0, lead.cognitionSpendUsd, 1e-9)
    assertEquals(LeadKinds.COGNITION_MALFORMED, lead.misOriginedEntries.single().second)
    s.close()
  }

  @Test
  fun ticketDoneClearsGateAndPodStateToPreventCrossTicketResidue() {
    val s = newStore()
    s.claim("t1")
    val gate = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    s.gateOpened(gate, GateKinds.PLAN_APPROVAL, "aa11")
    s.release(gate, "aa11", ORIGIN_AUTH_LAYER)
    s.podSpawned("p1", "plan:t1")
    s.podResult("p1", "aa11")
    var lead = s.lead()
    assertTrue(lead.openGates.isNotEmpty() && lead.releasedGates.isNotEmpty() && lead.pods.isNotEmpty())

    // TICKET_DONE clears all ticket-scoped state: no cross-ticket
    // residue, no unbounded growth; only the durable doneTickets record persists.
    s.append(LeadKinds.TICKET_DONE, buildJsonObject { put("ticketRef", "t1") }, ORIGIN_SUBSTRATE)
    lead = s.lead()
    assertTrue("gates cleared", lead.openGates.isEmpty())
    assertTrue("releases cleared", lead.releasedGates.isEmpty())
    assertTrue("pods cleared", lead.pods.isEmpty())
    assertEquals(listOf("t1"), lead.doneTickets)
    s.close()
  }

  @Test
  fun escalationsTailIsBoundedAgainstUnboundedGrowth() {
    val s = newStore()
    for (i in 1..150) {
      s.append(LeadKinds.ESCALATED, buildJsonObject { put("reason", "e$i") }, ORIGIN_SUBSTRATE)
    }
    val esc = s.lead().escalations
    assertEquals(100, esc.size) // ANOMALY_TAIL
    assertEquals("e51", esc.first())
    assertEquals("e150", esc.last())
    s.close()
  }

  @Test
  fun spawnIntentIsPendingUntilSpawnedThenClears() {
    val s = newStore()
    s.claim("t1")
    s.append(
      LeadKinds.POD_SPAWN_INTENDED,
      buildJsonObject {
        put("taskRef", "plan:t1")
        put("artifactPath", "/tmp/plan-t1")
      },
      ORIGIN_SUBSTRATE,
    )
    assertEquals(setOf("plan:t1"), s.lead().pendingSpawnIntents.keys) // intent recorded
    s.podSpawned("p1", "plan:t1")
    assertTrue("POD_SPAWNED fulfills the intent", s.lead().pendingSpawnIntents.isEmpty())
    s.close()
  }

  @Test
  fun spawnIntentAbandonedClearsAndSurfacesAnEscalation() {
    val s = newStore()
    s.claim("t1")
    s.append(
      LeadKinds.POD_SPAWN_INTENDED,
      buildJsonObject {
        put("taskRef", "plan:t1")
        put("artifactPath", "/tmp/plan-t1")
      },
      ORIGIN_SUBSTRATE,
    )
    s.append(
      LeadKinds.POD_SPAWN_ABANDONED,
      buildJsonObject {
        put("taskRef", "plan:t1")
        put("reason", "spawn intent orphaned at restart")
      },
      ORIGIN_SUBSTRATE,
    )
    val lead = s.lead()
    assertTrue("intent cleared", lead.pendingSpawnIntents.isEmpty())
    assertTrue(
      "the orphan is a visible escalation",
      lead.escalations.any { it.contains("orphaned for plan:t1") },
    )
    s.close()
  }
}
