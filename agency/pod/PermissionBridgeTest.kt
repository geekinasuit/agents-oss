package com.geekinasuit.agency.pod

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * Direct battery for [PermissionBridge]'s fail-closed ask path (AGENCY-028): an
 * ask whose [PodEvent.PermissionAsked] fact the sink REFUSES is a DENIED ask — the
 * decider is never consulted, a best-effort "denied-unjournaled" decision fact records
 * why, [PermissionDecision.RejectOnce] is what crosses the wire, and every refused
 * report is counted for the runner's health drain.
 *
 * The bridge is a plain class, so these cells need no agent process — and only cells at
 * THIS layer can observe which answer crosses the wire and that the decider was skipped.
 * The engine battery's fixture agent completes its turns whatever the answer is (its
 * file work is sequenced before its scripted behavior, so crash/stall cells can leave
 * evidence), which makes an unjournaled deny and an unjournaled allow indistinguishable
 * from up there. The healthy ask/decision flow stays pinned where it lives today, in the
 * engine battery's journal cells.
 */
class PermissionBridgeTest {

  private fun ask() =
    PermissionAsk(
      sessionId = "sess-1",
      toolCallId = "tc-0",
      title = "write artifact",
      toolKind = "EXECUTE",
      optionKinds = listOf("ALLOW_ONCE", "REJECT_ONCE"),
    )

  /** Consulting the decider at all is the defect these cells exist to catch: a decision
   * granted against an unjournalable ask would be an invisible approval — the exact thing
   * the journal-durability rule forbids. */
  private val neverConsulted: (PermissionAsk) -> PermissionDecision = {
    throw AssertionError("decider consulted for an unjournalable ask")
  }

  @Test
  fun anUnjournalableAskIsDeniedWithoutConsultingTheDecider() {
    // The sink refuses exactly the ask fact and accepts everything else, so the record
    // still carries WHY the reject crossed the wire.
    val accepted = mutableListOf<PodEvent>()
    val bridge =
      PermissionBridge(10_000, neverConsulted) { e ->
        if (e is PodEvent.PermissionAsked) throw IllegalStateException("journal refused this append")
        accepted += e
      }

    val answer = bridge.deciderFor("pod-1").decide(ask())

    assertEquals(PermissionDecision.RejectOnce, answer)
    val decided = accepted.filterIsInstance<PodEvent.PermissionDecided>().single()
    assertEquals("denied-unjournaled", decided.decision)
    // Attributable to the ask it denies — a decision fact the fold cannot tie back to
    // its ask would be a hole of its own.
    assertEquals("pod-1", decided.podId)
    assertEquals("sess-1", decided.sessionId)
    assertEquals("tc-0", decided.toolCallId)
    assertFalse("a denial made without the decider is never stamped late", decided.lateAfterDeadline)
    assertEquals("the refused ask fact is a counted hole", 1, bridge.reportFailures())
  }

  @Test
  fun aSinkRefusingTheDecisionFactTooCountsBothHolesAndStillRejects() {
    // The best-effort decision fact can be refused as well; both holes are counted the
    // same way and the wire answer is still the reject.
    val bridge =
      PermissionBridge(10_000, neverConsulted) {
        throw IllegalStateException("journal refused this append")
      }

    val answer = bridge.deciderFor("pod-1").decide(ask())

    assertEquals(PermissionDecision.RejectOnce, answer)
    assertEquals("both refused facts are counted holes", 2, bridge.reportFailures())
  }
}
