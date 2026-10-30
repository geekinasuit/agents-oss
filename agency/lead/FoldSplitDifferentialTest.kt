package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The host/workflow split of the lead fold must not change what any journal folds to. This folds a
 * generated corpus ([corpus], FoldCorpus.kt) with [legacyLeadFold] (the fold as it stood before the
 * split, frozen in LegacyLeadFold.kt) and with the split fold ([splitFold]), under every auth in
 * [AUTHS], and asserts that each journal folds to the same [LegacyLeadState] under both, or fails
 * under both with the same exception type and message.
 *
 * The corpus is seeded, so a failure reproduces. [theCorpusReachesTheStatesThatMatter] checks the
 * corpus is not trivially agreeing: it must reach approved phases, honored ceremony releases, fold
 * failures, a capped misorigin tail and an orphaned spawn described by its task ref.
 */
class FoldSplitDifferentialTest {

  @Test
  fun everyGeneratedJournalFoldsTheSameUnderTheSplitFold() {
    // Every prefix, not just the whole journal: a step where the two folds disagree can be masked
    // by a later entry, such as a scope end that clears what differed.
    for ((i, journal) in corpus().withIndex()) {
      for ((authName, auth) in AUTHS) {
        for (n in 0..journal.size) assertSameFold("journal $i, first $n entries, under $authName", journal.take(n), auth)
      }
    }
  }

  @Test
  fun aForgedClaimAfterTheMisoriginTailIsFullIsStillRefused() {
    // The tail caps at 100 entries, so after it is full a forged row no longer grows it. The
    // workflow must still not advance on a forged claim.
    val forged = (1L..120L).map { entry(it, LeadKinds.STATUS_WRITTEN, ORIGIN_COGNITION, obj("status" to "x")) }
    val claim = entry(121, LeadKinds.TICKET_CLAIMED, ORIGIN_COGNITION, obj("ticketRef" to "T1"))
    for ((authName, auth) in AUTHS) {
      assertSameFold("forged claim under $authName", forged + claim, auth)
      val s = splitFold(forged + claim, auth)
      assertEquals(null, s.currentTicket)
      assertEquals(TicketPhase.IDLE, s.phase)
    }
  }

  @Test
  fun everyKindFailsTheSameWhicheverOfItsFieldsAreBroken() {
    // Which field a fold reads first decides the failure message (it names the field), so a
    // change in read order is a behaviour change. The corpus breaks random fields and may never
    // hit a given pair. Here, after a legal walk to the commit gate's release, each kind gets every
    // subset of its fields broken, in each of five ways. Missing, null and a number fail the strict
    // reader. An object also fails the lenient one, which accepts any scalar. A string that is not
    // a number fails the contract checks, such as the cost's.
    val walk = legalWalk("T1").dropLast(1)
    for ((kind, valid) in validPayloads()) {
      val names = valid.keys.toList()
      for (mask in 1 until (1 shl names.size)) {
        val broken = names.filterIndexed { i, _ -> mask and (1 shl i) != 0 }.toSet()
        for (mode in listOf("missing", "null", "number", "object", "string")) {
          val payload =
            JsonObject(
              valid.entries
                .filter { (k, _) -> k !in broken || mode != "missing" }
                .associate { (k, v) ->
                  k to
                    when {
                      k !in broken -> v
                      mode == "null" -> JsonNull
                      mode == "object" -> JsonObject(emptyMap())
                      mode == "string" -> JsonPrimitive("not-a-number")
                      else -> JsonPrimitive(7)
                    }
                }
            )
          val journal = (walk + Triple(kind, naturalOrigin(kind), payload.toString())).mapIndexed { i, (k, o, p) ->
            entry(i + 1L, k, o, p)
          }
          for ((authName, auth) in AUTHS) assertSameFold("$kind with $broken $mode under $authName", journal, auth)
        }
      }
    }
  }

  @Test
  fun anApprovalOnAnotherDigestDoesNotCountTowardTheRelease() {
    // The quorum counts only approvals bound to the digest the gate is open on. Here the one
    // approval names the right gate and nonce but another digest, so the release folds stale. The
    // corpus does not reach this case on its own.
    val plan = gateIdFor(GateKinds.PLAN_APPROVAL, "T1")
    val walk = legalWalk("T1").take(9) // through the plan gate's open and its nonce on D1
    val journal =
      (walk + approval(plan, D2, "n1") + release(plan, D1, "n1")).mapIndexed { i, (k, o, p) ->
        entry(i + 1L, k, o, p)
      }
    for ((authName, auth) in AUTHS) assertSameFold("approval on another digest under $authName", journal, auth)
    val s = splitFold(journal, ceremonyAuth())
    assertTrue("the plan gate is not released", plan !in s.releasedGates)
    assertEquals(TicketPhase.PLAN_GATED, s.phase)
  }

  @Test
  fun theLegalWalkReachesDoneUnderTheCeremony() {
    val walk = legalWalk("T1").mapIndexed { i, (k, o, p) -> entry(i + 1L, k, o, p) }
    assertSameFold("legal walk", walk, ceremonyAuth())
    val beforeDone = splitFold(walk.dropLast(1), ceremonyAuth())
    assertEquals(TicketPhase.COMMIT_APPROVED, beforeDone.phase)
    assertEquals(listOf("T1"), splitFold(walk, ceremonyAuth()).doneTickets)
  }

  @Test
  fun theCorpusReachesTheStatesThatMatter() {
    var commitApproved = 0
    var planApproved = 0
    var ceremonyReleases = 0
    var failures = 0
    var cappedMisorigin = 0
    var orphanDescribedByRef = 0
    var done = 0
    for (journal in corpus()) {
      for ((authName, auth) in AUTHS) {
        val s =
          try {
            splitFold(journal, auth)
          } catch (_: LeadFoldException) {
            failures++
            continue
          }
        if (s.phase == TicketPhase.COMMIT_APPROVED) commitApproved++
        if (s.phase == TicketPhase.PLAN_APPROVED) planApproved++
        if (authName == "ceremony" && s.releasedGates.isNotEmpty()) ceremonyReleases++
        if (s.misOriginedEntries.size == 100) cappedMisorigin++
        if (s.escalations.any { it.contains("orphaned at seq=") && it.contains("for plan:T") }) orphanDescribedByRef++
        if (s.doneTickets.isNotEmpty()) done++
      }
    }
    val counts =
      "commitApproved=$commitApproved planApproved=$planApproved ceremonyReleases=$ceremonyReleases " +
        "failures=$failures cappedMisorigin=$cappedMisorigin orphanDescribedByRef=$orphanDescribedByRef done=$done"
    assertTrue(counts, commitApproved > 0)
    assertTrue(counts, planApproved > 0)
    assertTrue(counts, ceremonyReleases > 0)
    assertTrue(counts, failures > 0)
    assertTrue(counts, cappedMisorigin > 0)
    assertTrue(counts, orphanDescribedByRef > 0)
    assertTrue(counts, done > 0)
  }

  private fun assertSameFold(label: String, journal: List<JournalEntry>, auth: LeadAuth) {
    val legacy = runCatching { legacyLeadFold(journal, auth) }
    val split = runCatching { splitFold(journal, auth) }
    when {
      legacy.isSuccess && split.isSuccess -> assertEquals(label, legacy.getOrThrow(), split.getOrThrow())
      legacy.isFailure && split.isFailure -> {
        val a = legacy.exceptionOrNull()!!
        val b = split.exceptionOrNull()!!
        assertEquals("$label: exception type", a::class, b::class)
        assertEquals("$label: exception message", a.message, b.message)
      }
      else ->
        fail(
          "$label: legacy ${if (legacy.isSuccess) "folded" else "failed (${legacy.exceptionOrNull()})"}, " +
            "split ${if (split.isSuccess) "folded" else "failed (${split.exceptionOrNull()})"}"
        )
    }
  }

  /** The split fold's two halves, the host's records and the ticket lead's state, in the pre-split
   * shape the oracle folds to. */
  private fun splitFold(journal: List<JournalEntry>, auth: LeadAuth): LegacyLeadState {
    val (h, w) = foldHostAndLead(journal, auth, TicketWorkflowFold)
    return LegacyLeadState(
      runsStarted = h.runsStarted,
      currentTicket = w.currentTicket,
      phase = w.phase,
      planArtifactPath = w.planArtifactPath,
      planArtifactSha = w.planArtifactSha,
      commitManifestPath = w.commitManifestPath,
      commitManifestDigest = w.commitManifestDigest,
      openGates = h.openGates,
      releasedGates = h.releasedGates,
      releasedDigests = h.releasedDigests,
      nonceLessReleases = h.nonceLessReleases,
      staleReleases = h.staleReleases,
      issuedNonces = h.issuedNonces,
      consumedNonces = h.consumedNonces,
      notifiedNonces = h.notifiedNonces,
      failedAnnounces = h.failedAnnounces,
      notReadAnnounces = h.notReadAnnounces,
      verifiedApprovals = h.verifiedApprovals,
      unverifiedApprovals = h.unverifiedApprovals,
      pods = h.pods,
      pendingSpawnIntents = h.pendingSpawnIntents,
      misOriginedEntries = h.misOriginedEntries,
      statusTail = h.statusTail,
      escalations = h.escalations,
      escalatedStalls = h.escalatedStalls,
      declinedEffects = h.declinedEffects,
      malformedCognition = h.malformedCognition,
      doneTickets = w.doneTickets,
      cognitionSpendUsd = h.cognitionSpendUsd,
    )
  }
}
