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
import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import kotlin.random.Random
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The host/workflow split of the lead fold must not change what any journal folds to. This folds a
 * generated corpus with [legacyLeadFold] (the fold as it stood before the split, frozen in
 * LegacyLeadFold.kt) and with [leadFold], under both [LeadAuth.DENY_ALL] and [ceremonyAuth], and
 * asserts that each journal folds to the same [LeadState] under both, or fails under both with the
 * same exception type and message.
 *
 * The corpus is seeded, so a failure reproduces. Half the journals start from a legal ticket walk
 * (claim to done, both gates released under the ceremony) and splice random entries into it; the
 * rest are random sequences over the same small id space, so gates, nonces, approvals and pods
 * collide often enough for releases to be honored. A fraction of entries carry a forged origin or
 * a corrupted payload. [theCorpusReachesTheStatesThatMatter] checks the corpus is not trivially
 * agreeing: it must reach approved phases, honored ceremony releases, fold failures, a capped
 * misorigin tail and an orphaned spawn described by its task ref.
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
      val s = leadFold(forged + claim, auth)
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
    val s = leadFold(journal, ceremonyAuth())
    assertTrue("the plan gate is not released", plan !in s.releasedGates)
    assertEquals(TicketPhase.PLAN_GATED, s.phase)
  }

  @Test
  fun theLegalWalkReachesDoneUnderTheCeremony() {
    val walk = legalWalk("T1").mapIndexed { i, (k, o, p) -> entry(i + 1L, k, o, p) }
    assertSameFold("legal walk", walk, ceremonyAuth())
    val beforeDone = leadFold(walk.dropLast(1), ceremonyAuth())
    assertEquals(TicketPhase.COMMIT_APPROVED, beforeDone.phase)
    assertEquals(listOf("T1"), leadFold(walk, ceremonyAuth()).doneTickets)
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
            leadFold(journal, auth)
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
    val split = runCatching { leadFold(journal, auth) }
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

  private companion object {
    /** [ceremonyAuth]'s principal plus a second one, who never approves in this corpus. */
    val TWO_PRINCIPALS =
      AllowList(
        listOf(
          Principal("operator", role = "authorizer", keys = listOf(SchemeKey("test", "pk-operator"))),
          Principal("second", role = "authorizer", keys = listOf(SchemeKey("test", "pk-second"))),
        )
      )
    val ACCEPTING = ApprovalVerifier { _, _, _, _ -> true }

    /** Every auth shape the fold treats differently: no approvers; the one-of-one ceremony; a
     * ceremony whose verifier rejects every signature; one of two principals, which the operator's
     * approval satisfies; and two of two, which it never does. */
    val AUTHS: List<Pair<String, LeadAuth>> =
      listOf(
        "deny-all" to LeadAuth.DENY_ALL,
        "ceremony" to ceremonyAuth(),
        "rejecting" to LeadAuth(ceremonyAuth().allowList, ApprovalVerifier { _, _, _, _ -> false }, oneOfOne("operator")),
        "one-of-two" to
          LeadAuth(TWO_PRINCIPALS, ACCEPTING, QuorumGroup(1, listOf(SignerLeaf("operator"), SignerLeaf("second")))),
        "two-of-two" to
          LeadAuth(TWO_PRINCIPALS, ACCEPTING, QuorumGroup(2, listOf(SignerLeaf("operator"), SignerLeaf("second")))),
      )

    const val SEED = 20261018L
    const val JOURNALS = 1500

    val D1 = "1".repeat(64)
    val D2 = "2".repeat(64)
    val TICKETS = listOf("T1", "T2", "bad:ref")
    val GATE_KINDS = listOf(GateKinds.PLAN_APPROVAL, GateKinds.COMMIT_APPROVAL, "other-kind")
    val DIGESTS = listOf(D1, D2, "not-a-digest")
    val NONCES = listOf("n1", "n2", "n3")
    val PODS = listOf("p1", "p2", "p3")
    val TASK_REFS = listOf("plan:T1", "execute:T1", "plan:T2", "execute:T2", "misc")
    val KINDS =
      listOf(
        LeadKinds.RUN_STARTED,
        LeadKinds.TICKET_CLAIMED,
        LeadKinds.PLAN_REQUESTED,
        LeadKinds.PLAN_ARTIFACT_RECORDED,
        LeadKinds.COMMIT_PROPOSED,
        LeadKinds.STATUS_WRITTEN,
        LeadKinds.TICKET_DONE,
        LeadKinds.ESCALATED,
        LeadKinds.GATE_OPENED,
        LeadKinds.GATE_OPEN_NOTIFIED,
        LeadKinds.POD_SPAWNED,
        LeadKinds.POD_RESULT_RECORDED,
        LeadKinds.POD_ABANDONED,
        LeadKinds.POD_SPAWN_INTENDED,
        LeadKinds.POD_SPAWN_ABANDONED,
        LeadKinds.POD_EVENT,
        LeadKinds.COGNITION_PROPOSED,
        LeadKinds.COGNITION_MALFORMED,
        LeadKinds.NONCE_ISSUED,
        LeadKinds.NONCE_CONSUMED,
        LeadKinds.APPROVAL_RECORDED,
        KIND_GATE_RELEASED,
        "some-shared-kind",
      )

    fun corpus(): List<List<JournalEntry>> {
      val r = Random(SEED)
      return (0 until JOURNALS).map { i ->
        // Corruption on a fifth of the journals only: a journal that fails folds no further, so
        // corrupting every journal would leave little of the corpus reaching late states.
        val corrupting = i % 5 == 3
        val spec =
          if (i % 2 == 0) {
            val walk = legalWalk(r.pick(listOf("T1", "T2")), orphanPlanPod = r.nextInt(4) == 0)
            splice(r, walk.take(r.nextInt(1, walk.size + 1)), corrupting)
          } else List(r.nextInt(0, 60)) { randomEntry(r, corrupting) }
        val withForgeries =
          if (i % 50 == 1) List(110) { Triple(LeadKinds.ESCALATED, ORIGIN_COGNITION, obj("reason" to "forged")) } + spec
          else spec
        withForgeries.mapIndexed { seq, (k, o, p) -> entry(seq + 1L, k, o, p) }
      }
    }

    /** Inserts, drops and duplicates a few random entries in [walk]. */
    fun splice(
      r: Random,
      walk: List<Triple<String, String, String>>,
      corrupting: Boolean,
    ): List<Triple<String, String, String>> {
      val out = walk.toMutableList()
      repeat(r.nextInt(0, 6)) {
        when (r.nextInt(3)) {
          0 -> out.add(r.nextInt(out.size + 1), randomEntry(r, corrupting))
          1 -> if (out.isNotEmpty()) out.removeAt(r.nextInt(out.size))
          else -> if (out.isNotEmpty()) out.add(r.nextInt(out.size + 1), out[r.nextInt(out.size)])
        }
      }
      return out
    }

    /** One ticket's legal walk under [ceremonyAuth]: claim, plan pod, plan gate released, execute
     * pod, commit gate released, done. Each element is (kind, origin, payload JSON). With
     * [orphanPlanPod], the plan pod's first spawn intent is orphaned at a restart and abandoned
     * before it is intended again. */
    fun legalWalk(t: String, orphanPlanPod: Boolean = false): List<Triple<String, String, String>> {
      val plan = gateIdFor(GateKinds.PLAN_APPROVAL, t)
      val commit = gateIdFor(GateKinds.COMMIT_APPROVAL, t)
      fun sub(kind: String, vararg f: Pair<String, Any?>) = Triple(kind, ORIGIN_SUBSTRATE, obj(*f))
      val orphan =
        if (orphanPlanPod)
          listOf(
            sub(LeadKinds.POD_SPAWN_INTENDED, "taskRef" to "plan:$t"),
            sub(LeadKinds.RUN_STARTED),
            sub(LeadKinds.POD_SPAWN_ABANDONED, "taskRef" to "plan:$t", "reason" to ORPHANED_SPAWN_REASON),
          )
        else emptyList()
      return listOf(
        sub(LeadKinds.RUN_STARTED),
        sub(LeadKinds.TICKET_CLAIMED, "ticketRef" to t),
        sub(LeadKinds.PLAN_REQUESTED),
      ) + orphan + listOf(
        sub(LeadKinds.POD_SPAWN_INTENDED, "taskRef" to "plan:$t"),
        sub(LeadKinds.POD_SPAWNED, "podId" to "p1", "sessionId" to "s1", "taskRef" to "plan:$t", "artifactPath" to "a"),
        sub(LeadKinds.POD_RESULT_RECORDED, "podId" to "p1", "resultDigest" to D1, "boundPath" to "b"),
        sub(LeadKinds.PLAN_ARTIFACT_RECORDED, "path" to "b", "sha256" to D1),
        sub(LeadKinds.GATE_OPENED, "gateId" to plan, "gateKind" to GateKinds.PLAN_APPROVAL, "payloadDigest" to D1),
        sub(LeadKinds.NONCE_ISSUED, "nonce" to "n1", "gateId" to plan, "payloadDigest" to D1),
        approval(plan, D1, "n1"),
        release(plan, D1, "n1"),
        sub(LeadKinds.POD_SPAWN_INTENDED, "taskRef" to "execute:$t"),
        sub(LeadKinds.POD_SPAWNED, "podId" to "p2", "sessionId" to "s2", "taskRef" to "execute:$t", "artifactPath" to "a"),
        sub(LeadKinds.POD_RESULT_RECORDED, "podId" to "p2", "resultDigest" to D2, "costUsd" to "0.25"),
        sub(LeadKinds.COMMIT_PROPOSED, "manifestPath" to "m", "manifestDigest" to D2),
        sub(LeadKinds.GATE_OPENED, "gateId" to commit, "gateKind" to GateKinds.COMMIT_APPROVAL, "payloadDigest" to D2),
        sub(LeadKinds.NONCE_ISSUED, "nonce" to "n2", "gateId" to commit, "payloadDigest" to D2),
        approval(commit, D2, "n2"),
        release(commit, D2, "n2"),
        sub(LeadKinds.TICKET_DONE, "ticketRef" to t),
      )
    }

    fun naturalOrigin(kind: String): String =
      when (kind) {
        LeadKinds.APPROVAL_RECORDED,
        KIND_GATE_RELEASED -> ORIGIN_AUTH_LAYER
        LeadKinds.COGNITION_PROPOSED -> ORIGIN_COGNITION
        else -> ORIGIN_SUBSTRATE
      }

    /** For each kind with payload fields, a payload with every field it can carry, each valid
     * against [legalWalk]`("T1")` up to the commit gate's release. */
    fun validPayloads(): List<Pair<String, JsonObject>> {
      val plan = gateIdFor(GateKinds.PLAN_APPROVAL, "T1")
      fun o(vararg f: Pair<String, Any?>) = JsonObject(f.associate { (k, v) -> k to jsonValue(v) })
      val approval = kotlinx.serialization.json.Json.parseToJsonElement(approval(plan, D1, "n1").third) as JsonObject
      return listOf(
        LeadKinds.TICKET_CLAIMED to o("ticketRef" to "T2"),
        LeadKinds.TICKET_DONE to o("ticketRef" to "T1"),
        LeadKinds.PLAN_ARTIFACT_RECORDED to o("path" to "b", "sha256" to D1),
        LeadKinds.COMMIT_PROPOSED to o("manifestPath" to "m", "manifestDigest" to D2),
        LeadKinds.STATUS_WRITTEN to o("status" to "s"),
        LeadKinds.ESCALATED to
          o("reason" to "why", "stalledGateId" to plan, "stalledDigest" to D1, "declinedEffectDigest" to D1),
        LeadKinds.GATE_OPENED to o("gateId" to plan, "gateKind" to GateKinds.PLAN_APPROVAL, "payloadDigest" to D2),
        LeadKinds.GATE_OPEN_NOTIFIED to o("nonce" to "n1", "retry" to true, "notRead" to true),
        LeadKinds.POD_SPAWNED to o("podId" to "p3", "sessionId" to "s", "taskRef" to "plan:T1", "artifactPath" to "a"),
        LeadKinds.POD_RESULT_RECORDED to o("podId" to "p1", "resultDigest" to D1, "boundPath" to "b", "costUsd" to "0.5"),
        LeadKinds.POD_ABANDONED to o("podId" to "p1", "reason" to "gone"),
        LeadKinds.POD_SPAWN_INTENDED to o("taskRef" to "plan:T1"),
        LeadKinds.POD_SPAWN_ABANDONED to o("taskRef" to "plan:T1", "reason" to ORPHANED_SPAWN_REASON),
        LeadKinds.COGNITION_PROPOSED to o("costUsd" to "0.1"),
        LeadKinds.COGNITION_MALFORMED to o("reason" to MalformedReasons.NOT_JSON, "costUsd" to "0.1"),
        LeadKinds.NONCE_ISSUED to o("nonce" to "n3", "gateId" to plan, "payloadDigest" to D1),
        LeadKinds.NONCE_CONSUMED to o("nonce" to "n1"),
        LeadKinds.APPROVAL_RECORDED to approval,
        KIND_GATE_RELEASED to o("gateId" to plan, "payloadDigest" to D1, "nonce" to "n1"),
      )
    }

    fun randomEntry(r: Random, corrupting: Boolean): Triple<String, String, String> {
      val kind = r.pick(KINDS)
      val natural = naturalOrigin(kind)
      val origin = if (r.nextInt(10) == 0) r.pick(listOf(ORIGIN_SUBSTRATE, ORIGIN_AUTH_LAYER, ORIGIN_COGNITION, "pod")) else natural
      val gate = gateIdFor(r.pick(GATE_KINDS), r.pick(TICKETS))
      val fields: List<Pair<String, Any?>> =
        when (kind) {
          LeadKinds.TICKET_CLAIMED,
          LeadKinds.TICKET_DONE -> listOf("ticketRef" to r.pick(TICKETS))
          LeadKinds.PLAN_ARTIFACT_RECORDED -> listOf("path" to "b", "sha256" to r.pick(DIGESTS))
          LeadKinds.COMMIT_PROPOSED -> listOf("manifestPath" to "m", "manifestDigest" to r.pick(DIGESTS))
          LeadKinds.STATUS_WRITTEN -> listOf("status" to "s")
          LeadKinds.ESCALATED ->
            listOf("reason" to "why") +
              (if (r.nextBoolean()) listOf("stalledGateId" to gate, "stalledDigest" to r.pick(DIGESTS)) else emptyList()) +
              (if (r.nextInt(4) == 0) listOf("declinedEffectDigest" to D1) else emptyList())
          LeadKinds.GATE_OPENED -> {
            val gk = r.pick(GATE_KINDS)
            listOf("gateId" to gateIdFor(gk, r.pick(TICKETS)), "gateKind" to gk, "payloadDigest" to r.pick(DIGESTS))
          }
          LeadKinds.GATE_OPEN_NOTIFIED ->
            listOf("nonce" to r.pick(NONCES)) +
              (if (r.nextBoolean()) listOf("retry" to r.pick(listOf(true, "true", false))) else emptyList()) +
              (if (r.nextBoolean()) listOf("notRead" to true) else emptyList())
          LeadKinds.POD_SPAWNED ->
            listOf("podId" to r.pick(PODS), "sessionId" to "s", "taskRef" to r.pick(TASK_REFS), "artifactPath" to "a")
          LeadKinds.POD_RESULT_RECORDED ->
            listOf("podId" to r.pick(PODS), "resultDigest" to r.pick(DIGESTS)) +
              (if (r.nextBoolean()) listOf("boundPath" to "b") else emptyList()) +
              (if (r.nextBoolean()) listOf("costUsd" to r.pick(listOf<Any>("0.5", "-1", "NaN", "abc", 0.25))) else emptyList())
          LeadKinds.POD_ABANDONED -> listOf("podId" to r.pick(PODS), "reason" to "gone")
          LeadKinds.POD_SPAWN_INTENDED -> listOf("taskRef" to r.pick(TASK_REFS))
          LeadKinds.POD_SPAWN_ABANDONED ->
            listOf("taskRef" to r.pick(TASK_REFS), "reason" to r.pick(listOf(ORPHANED_SPAWN_REASON, "other")))
          LeadKinds.COGNITION_PROPOSED -> listOf("costUsd" to r.pick(listOf<Any>("0.1", "NaN", "-2", 0.3)))
          LeadKinds.COGNITION_MALFORMED ->
            listOf("reason" to r.pick(listOf(MalformedReasons.NOT_JSON, "something else")), "costUsd" to "0.1")
          LeadKinds.NONCE_ISSUED ->
            listOf("nonce" to r.pick(NONCES + ""), "gateId" to gate, "payloadDigest" to r.pick(DIGESTS))
          LeadKinds.NONCE_CONSUMED -> listOf("nonce" to r.pick(NONCES))
          LeadKinds.APPROVAL_RECORDED -> return approval(gate, r.pick(DIGESTS), r.pick(NONCES), origin, r)
          KIND_GATE_RELEASED ->
            listOf("gateId" to gate, "payloadDigest" to r.pick(DIGESTS)) +
              (if (r.nextInt(4) != 0) listOf("nonce" to r.pick(NONCES + listOf(null))) else emptyList())
          else -> emptyList()
        }
      return Triple(kind, origin, if (corrupting) corrupt(r, fields) else obj(*fields.toTypedArray()))
    }

    /** Usually the fields as given; sometimes some of them (each with even odds) dropped, nulled or
     * made a number, or a payload that is not JSON at all. */
    fun corrupt(r: Random, fields: List<Pair<String, Any?>>): String {
      if (r.nextInt(25) == 0) return "not json {"
      if (fields.isEmpty() || r.nextInt(20) != 0) return obj(*fields.toTypedArray())
      val broken = fields.indices.filter { r.nextBoolean() }.ifEmpty { listOf(r.nextInt(fields.size)) }.toSet()
      val changed =
        fields.mapIndexedNotNull { j, f ->
          if (j !in broken) f
          else
            when (r.nextInt(3)) {
              0 -> null
              1 -> f.first to null
              else -> f.first to 7
            }
        }
      return obj(*changed.toTypedArray())
    }

    fun approval(gateId: String, digest: String, nonce: String): Triple<String, String, String> =
      approval(gateId, digest, nonce, ORIGIN_AUTH_LAYER, null)

    /** An approval by [ceremonyAuth]'s principal. With [r], sometimes one flat copy disagrees with
     * the preimage, so it folds unverified. */
    fun approval(gateId: String, digest: String, nonce: String, origin: String, r: Random?): Triple<String, String, String> {
      val publicKey = "pk-operator"
      val flatGate = if (r != null && r.nextInt(6) == 0) "$gateId-x" else gateId
      val payload = buildJsonObject {
        put("gateId", flatGate)
        put("principalId", "operator")
        put("nonce", nonce)
        put("payloadDigest", digest)
        put(
          "evidence",
          ApprovalEvidence(
              schemeId = "test",
              publicKey = publicKey,
              signature = "sig-operator",
              carrierArtifactId = "carrier-$nonce",
              gateId = gateId,
              payloadDigest = digest,
              nonce = nonce,
              signedPreimage = committedPreimage(publicKey, gateId, digest, nonce),
            )
            .toJson(),
        )
      }
      return Triple(LeadKinds.APPROVAL_RECORDED, origin, payload.toString())
    }

    fun release(gateId: String, digest: String, nonce: String): Triple<String, String, String> =
      Triple(KIND_GATE_RELEASED, ORIGIN_AUTH_LAYER, obj("gateId" to gateId, "payloadDigest" to digest, "nonce" to nonce))

    fun obj(vararg fields: Pair<String, Any?>): String =
      JsonObject(fields.associate { (k, v) -> k to jsonValue(v) }).toString()

    fun jsonValue(v: Any?): JsonElement =
      when (v) {
        null -> JsonNull
        is String -> JsonPrimitive(v)
        is Number -> JsonPrimitive(v)
        is Boolean -> JsonPrimitive(v)
        else -> error("unsupported payload value $v")
      }

    fun entry(seq: Long, kind: String, origin: String, payloadJson: String): JournalEntry =
      JournalEntry(
        seq = seq,
        schemaVersion = 3,
        kind = kind,
        chainContext = "agency/lead/main/v3",
        origin = origin,
        keyEpoch = 0,
        salt = "",
        payloadCommitment = "",
        payloadJson = payloadJson,
        idempotencyKey = null,
        prevHash = "",
        hash = "",
        sig = null,
      )

    fun <T> Random.pick(xs: List<T>): T = xs[nextInt(xs.size)]
  }
}
