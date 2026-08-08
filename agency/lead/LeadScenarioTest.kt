package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.EffectReceiver
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Lead durability scenarios: the fixture binary is
 * killed by deterministic fault injection at every named instruction boundary ON THE DRIVE
 * PATH — adopt, the mechanical pipeline, and cognition-proposal execution — then a fresh
 * process adopts by re-folding, and the walk always converges to the same terminal state
 * with the commit effect fired exactly once. Red-path cells prove the gate teeth:
 * forged-origin and stale-digest releases leave the gate pending and VISIBLE, and the
 * positive-control cell proves the harness can observe the double-fire it claims to prevent.
 * Assertions read folded state + effect logs, never timing.
 *
 * One named boundary is deliberately NOT in this matrix: `after-gate-released`
 * lives on the in-process AuthRelease ACCEPT path ([LeadDaemon.injectAuthRelease] journals the
 * release, then rings the doorbell — journal-then-ack, AGENCY-021), and this fixture applies
 * releases at the STORE level (`AuthStub.appendRelease`, matching the sequential model where the
 * daemon is not running between advances) — so a release never arrives here through the accept
 * surface. The accept-then-crash window that boundary marks is covered in-process by
 * WakeLoopTest's restart cells (an accepted release survives a death before its wake), and the
 * boundary becomes fixture-kill-relevant when a real ceremony delivers authenticated releases
 * into a live loop.
 */
class LeadScenarioTest {

  @get:Rule val tmp = TemporaryFolder()

  private val fixture: String by lazy {
    val srcdir = System.getenv("TEST_SRCDIR") ?: error("TEST_SRCDIR not set (not under bazel test)")
    val f = File(srcdir, "_main/agency/lead/lead_fixture")
    check(f.exists()) { "lead_fixture not found in runfiles at $f" }
    f.absolutePath
  }

  private fun newDir(): String {
    val dir = tmp.newFolder()
    File(dir, "ticket.txt").writeText("t1\n")
    return dir.absolutePath
  }

  private fun run(dir: String, vararg args: String): Pair<Int, String> {
    val cmd = mutableListOf(fixture)
    cmd += args
    cmd += listOf("--dir", dir)
    if (args.firstOrNull() == "advance") cmd += listOf("--ticket-file", "$dir/ticket.txt")
    val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
    val out = p.inputStream.readBytes().toString(Charsets.UTF_8)
    val code = p.waitFor()
    if (code !in setOf(0, 42)) {
      throw AssertionError("fixture ${args.toList()} exited $code:\n$out")
    }
    return code to out
  }

  private fun advance(dir: String, vararg extra: String): Pair<Int, String> =
    run(dir, "advance", *extra)

  private fun replay(dir: String): String = run(dir, "replay").second

  private fun commitEffectCount(dir: String): Int =
    EffectReceiver(dir).lineCountFor("apply-commit:t1")

  /** Drive a (possibly mid-flight) journal to ticket completion, approving each gate as
   * it comes up. The recovery path after every fault cell funnels through this. */
  private fun finishPipeline(dir: String, dedup: Boolean = true) {
    val noDedup = if (dedup) emptyArray() else arrayOf("--no-dedup")
    repeat(4) {
      val out = advance(dir, *noDedup).second
      when {
        out.contains("done=[t1]") -> return
        out.contains("pending=[${gateIdFor(GateKinds.PLAN_APPROVAL, "t1")}]") ->
          run(dir, "release", "--gate-kind", GateKinds.PLAN_APPROVAL)
        out.contains("pending=[${gateIdFor(GateKinds.COMMIT_APPROVAL, "t1")}]") ->
          run(dir, "release", "--gate-kind", GateKinds.COMMIT_APPROVAL)
      }
    }
    val out = advance(dir, *noDedup).second
    assertTrue("pipeline did not converge: $out", out.contains("done=[t1]"))
  }

  private fun assertTerminal(dir: String, expectedEffectCount: Int = 1) {
    val r = replay(dir)
    assertTrue("not terminal: $r", r.contains("phase=IDLE"))
    assertTrue("not terminal: $r", r.contains("doneTickets=[t1]"))
    assertTrue("effects pending: $r", r.contains("pendingEffects=[]"))
    assertEquals(expectedEffectCount, commitEffectCount(dir))
  }

  @Test
  fun happyPathWalksTheWholePipeline() {
    val dir = newDir()
    val (c1, out1) = advance(dir)
    assertEquals(0, c1)
    assertTrue(out1, out1.contains("phase=PLAN_GATED"))
    run(dir, "release", "--gate-kind", GateKinds.PLAN_APPROVAL)
    val (_, out2) = advance(dir)
    assertTrue(out2, out2.contains("phase=COMMIT_GATED"))
    run(dir, "release", "--gate-kind", GateKinds.COMMIT_APPROVAL)
    val (_, out3) = advance(dir)
    assertTrue(out3, out3.contains("done=[t1]"))
    assertTerminal(dir)
  }

  @Test
  fun killMatrixStageOneBoundariesAllConverge() {
    val boundaries =
      listOf(
        "after-claim",
        "after-plan-requested",
        "after-spawn-intended", // intent journaled, pod not yet launched
        "between-spawn-and-journal",
        "after-pod-spawned",
        "after-pod-result",
        "after-plan-recorded",
        "after-gate-opened-plan-approval",
      )
    for (b in boundaries) {
      val dir = newDir()
      val (code, out) = advance(dir, "--fault", b)
      assertEquals("boundary $b did not fault: $out", 42, code)
      finishPipeline(dir)
      assertTerminal(dir)
    }
  }

  @Test
  fun killMatrixCommitBoundariesConvergeExactlyOnce() {
    // "after-spawn-intended" is in the stage-one matrix too, on purpose: the shared spawn
    // boundary fires on the FIRST spawn it reaches, so here — plan pod already done and its
    // gate released — it kills the EXECUTE pod's spawn intent. That orphan recovers through a
    // different predicate than the plan orphan (Cognition.kt's planApproved-and-no-active-
    // execute-pod arm), which needs the released plan gate to survive the re-fold: the one
    // place intent-before-side-effect and clear-ticket-state-on-done actually meet.
    for (b in listOf("after-spawn-intended", "after-commit-proposed",
                     "after-gate-opened-commit-approval", "after-commit-intent",
                     "after-commit-effect", "after-ticket-done")) {
      val dir = newDir()
      advance(dir)
      run(dir, "release", "--gate-kind", GateKinds.PLAN_APPROVAL)
      val out = advance(dir, "--fault", b)
      // Boundaries in the post-plan-approval drive fault here; later ones fault after the
      // commit release below.
      if (out.first != 42) {
        run(dir, "release", "--gate-kind", GateKinds.COMMIT_APPROVAL)
        val (code2, out2) = advance(dir, "--fault", b)
        assertEquals("boundary $b never faulted: ${out.second}\n$out2", 42, code2)
      }
      finishPipeline(dir)
      assertTerminal(dir)
    }
  }

  @Test
  fun killMidAdoptConverges() {
    val dir = newDir()
    advance(dir) // real content in the journal first
    val (code, _) = advance(dir, "--fault", "mid-adopt")
    assertEquals(42, code)
    finishPipeline(dir)
    assertTerminal(dir)
  }

  @Test
  fun positiveControlWithoutDedupObservesTheDoubleFire() {
    val dir = newDir()
    advance(dir, "--no-dedup")
    run(dir, "release", "--gate-kind", GateKinds.PLAN_APPROVAL)
    advance(dir, "--no-dedup")
    run(dir, "release", "--gate-kind", GateKinds.COMMIT_APPROVAL)
    val (code, _) = advance(dir, "--no-dedup", "--fault", "after-commit-effect")
    assertEquals(42, code)
    // A check that cannot see the failure is not evidence: with dedup off, the crash
    // window really does double-fire, and this harness observes it.
    finishPipeline(dir, dedup = false)
    assertTerminal(dir, expectedEffectCount = 2)
  }

  @Test
  fun forgedOriginReleasesLeaveGatePendingAndVisible() {
    val dir = newDir()
    advance(dir)
    run(dir, "release", "--gate-kind", GateKinds.PLAN_APPROVAL, "--forge-origin", "cognition")
    advance(dir)
    var r = replay(dir)
    assertTrue(r, r.contains("pending=[${gateIdFor(GateKinds.PLAN_APPROVAL, "t1")}]"))
    assertTrue(r, r.contains("rejected=1"))

    run(dir, "release", "--gate-kind", GateKinds.PLAN_APPROVAL, "--forge-origin", "substrate")
    advance(dir)
    r = replay(dir)
    assertTrue(r, r.contains("pending=[${gateIdFor(GateKinds.PLAN_APPROVAL, "t1")}]"))
    assertTrue(r, r.contains("rejected=2"))

    // The faithful release still works after the forgeries — and the record keeps them.
    finishPipeline(dir)
    assertTerminal(dir)
    assertTrue(replay(dir).contains("rejected=2"))
  }

  @Test
  fun staleDigestReleaseStaysPendingEscalatesThenFaithfulReleaseProceeds() {
    val dir = newDir()
    advance(dir)
    run(dir, "release", "--gate-kind", GateKinds.PLAN_APPROVAL, "--stale-digest")
    advance(dir)
    val r = replay(dir)
    assertTrue(r, r.contains("pending=[${gateIdFor(GateKinds.PLAN_APPROVAL, "t1")}]"))
    assertTrue(r, r.contains("stale=1"))
    assertTrue(r, r.contains("escalations=1")) // scripted cognition raised it for a human

    finishPipeline(dir)
    assertTerminal(dir)
  }

  @Test
  fun tamperingPodDigestIsRecomputedEscalatedAndThePipelineStillCompletes() {
    val dir = newDir()
    // Every pod reports a wrong digest; the daemon recomputes from the artifact, escalates
    // the mismatch, and binds gates to the recomputed digest — so approving each gate
    // still drives the ticket to completion on real content.
    advance(dir, "--tamper-artifact")
    var r = replay(dir)
    assertTrue("mismatch escalated: $r", r.contains("escalations=1") || r.contains("escalations=2"))
    assertTrue(r, r.contains("phase=PLAN_GATED"))
    run(dir, "release", "--gate-kind", GateKinds.PLAN_APPROVAL)
    advance(dir, "--tamper-artifact")
    run(dir, "release", "--gate-kind", GateKinds.COMMIT_APPROVAL)
    advance(dir, "--tamper-artifact")
    assertTerminal(dir)
    r = replay(dir)
    assertTrue("both mismatches recorded: $r", r.contains("escalations=2"))
  }

  @Test
  fun heldPodIsAbandonedOnAdoptAndReSpawned() {
    val dir = newDir()
    val (_, out) = advance(dir, "--hold-pods")
    assertTrue(out, out.contains("phase=PLANNING"))
    assertTrue(replay(dir).contains("activePods=1"))
    // Fresh process (completions were parked in-memory and died with it): adopt abandons
    // the orphan visibly, cognition re-proposes, and the pipeline proceeds.
    val (_, out2) = advance(dir)
    assertTrue(out2, out2.contains("phase=PLAN_GATED"))
    finishPipeline(dir)
    assertTerminal(dir)
  }

  @Test
  fun unwritableBoundStoreFailsClosedCapsReproposalsThenConvergesOnceCleared() {
    val dir = newDir()
    // Bind-once red path: the lead's OWN bound-artifact store is obstructed (a plain
    // file where artifacts-bound/ must go), so every completion's bound write fails. Fail
    // closed means NO result row (no digest without a durable consumable object) — the pod
    // is abandoned, the evidence-based playbook re-proposes, and the lead-tier attempt cap
    // is what makes this advance TERMINATE: without it the spawn→fail→abandon→re-propose
    // cycle would spin driveUntilQuiescent forever, so exit 0 here is the cap's evidence.
    val (code, out) = advance(dir, "--unwritable-bound")
    assertEquals("a failing bound store must not crash or spin the loop: $out", 0, code)
    assertTrue("no plan evidence may be recorded on failed bound writes: $out", out.contains("phase=PLANNING"))
    val r = replay(dir)
    assertTrue("bound-write failures + the cap refusal are escalated: $r", Regex("escalations=[1-9]").containsMatchIn(r))
    assertTrue("every attempt's pod was abandoned: $r", r.contains("activePods=0"))
    // The operator clears the fault; a FRESH process (restart = the cap's reset act)
    // re-proposes and the ticket completes on real content.
    assertTrue(File(dir, "artifacts-bound").delete())
    val (_, out2) = advance(dir)
    assertTrue("recovered once the bound store is writable: $out2", out2.contains("phase=PLAN_GATED"))
    finishPipeline(dir)
    assertTerminal(dir)
  }

  @Test
  fun spawnIntentOrphanedByKillIsAbandonedVisiblyAndReSpawned() {
    val dir = newDir()
    // Kill AFTER the spawn intent is journaled but BEFORE the pod is launched. A fresh
    // re-fold must NOT report "nothing happened": adopt records the orphaned intent
    // visibly (an escalation) and the playbook re-proposes.
    val (code, _) = advance(dir, "--fault", "after-spawn-intended")
    assertEquals(42, code)
    val (_, out2) = advance(dir)
    assertTrue("recovered after the orphaned intent: $out2", out2.contains("phase=PLAN_GATED"))
    val r = replay(dir)
    // replay surfaces only the escalation COUNT; the exact orphan text ("… orphaned for
    // plan:t1") is asserted at the fold level (LeadFoldTest). Assert nonzero here, not an
    // exact 1, so an added escalation on this path can't turn a real pass into a false fail.
    assertTrue(
      "the orphaned spawn intent must surface as a visible escalation: $r",
      Regex("escalations=[1-9]").containsMatchIn(r),
    )
    finishPipeline(dir)
    assertTerminal(dir)
  }
}
