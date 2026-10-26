package com.geekinasuit.agency.lead

import java.lang.reflect.Modifier
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The string every lead-chain kind is journaled under. A journal written by one binary is folded by
 * the next, so a kind's string is a wire format. The journal goldens show only the kinds their walks
 * reach; this pins every one, on its side and through [LeadKinds].
 */
class KindWireStringsTest {

  private val hostKinds =
    listOf(
      HostKinds.RUN_STARTED to "run-started",
      HostKinds.STATUS_WRITTEN to "status-written",
      HostKinds.ESCALATED to "escalated",
      HostKinds.GATE_OPENED to "gate-opened",
      HostKinds.GATE_OPEN_NOTIFIED to "gate-open-notified",
      HostKinds.POD_SPAWNED to "pod-spawned",
      HostKinds.POD_RESULT_RECORDED to "pod-result-recorded",
      HostKinds.POD_ABANDONED to "pod-abandoned",
      HostKinds.POD_SPAWN_INTENDED to "pod-spawn-intended",
      HostKinds.POD_SPAWN_ABANDONED to "pod-spawn-abandoned",
      HostKinds.POD_EVENT to "pod-event",
      HostKinds.COGNITION_PROPOSED to "cognition-proposed",
      HostKinds.COGNITION_MALFORMED to "cognition-malformed",
      HostKinds.NONCE_ISSUED to "nonce-issued",
      HostKinds.NONCE_CONSUMED to "nonce-consumed",
      HostKinds.APPROVAL_RECORDED to "approval-recorded",
    )

  private val ticketKinds =
    listOf(
      TicketKinds.TICKET_CLAIMED to "ticket-claimed",
      TicketKinds.PLAN_REQUESTED to "plan-requested",
      TicketKinds.PLAN_ARTIFACT_RECORDED to "plan-artifact-recorded",
      TicketKinds.COMMIT_PROPOSED to "commit-proposed",
      TicketKinds.TICKET_DONE to "ticket-done",
    )

  /** The string constants [type] declares, so a kind added there without a pin here fails. */
  private fun declared(type: Class<*>): Set<String> =
    type.declaredFields
      .filter { Modifier.isStatic(it.modifiers) && it.type == String::class.java }
      .map { it.get(null) as String }
      .toSet()

  @Test
  fun everyHostKindKeepsItsWireString() {
    for ((actual, wire) in hostKinds) assertEquals(wire, wire, actual)
    assertEquals("the host kinds pinned here are exactly those declared", hostKinds.map { it.second }.toSet(), declared(HostKinds::class.java))
  }

  @Test
  fun everyTicketKindKeepsItsWireString() {
    for ((actual, wire) in ticketKinds) assertEquals(wire, wire, actual)
    assertEquals("the ticket kinds pinned here are exactly those declared", ticketKinds.map { it.second }.toSet(), declared(TicketKinds::class.java))
  }

  @Test
  fun leadKindsNamesTheSameStrings() {
    val pairs =
      listOf(
        LeadKinds.RUN_STARTED to "run-started",
        LeadKinds.TICKET_CLAIMED to "ticket-claimed",
        LeadKinds.PLAN_REQUESTED to "plan-requested",
        LeadKinds.PLAN_ARTIFACT_RECORDED to "plan-artifact-recorded",
        LeadKinds.COMMIT_PROPOSED to "commit-proposed",
        LeadKinds.STATUS_WRITTEN to "status-written",
        LeadKinds.TICKET_DONE to "ticket-done",
        LeadKinds.ESCALATED to "escalated",
        LeadKinds.GATE_OPENED to "gate-opened",
        LeadKinds.GATE_OPEN_NOTIFIED to "gate-open-notified",
        LeadKinds.POD_SPAWNED to "pod-spawned",
        LeadKinds.POD_RESULT_RECORDED to "pod-result-recorded",
        LeadKinds.POD_ABANDONED to "pod-abandoned",
        LeadKinds.POD_SPAWN_INTENDED to "pod-spawn-intended",
        LeadKinds.POD_SPAWN_ABANDONED to "pod-spawn-abandoned",
        LeadKinds.POD_EVENT to "pod-event",
        LeadKinds.COGNITION_PROPOSED to "cognition-proposed",
        LeadKinds.COGNITION_MALFORMED to "cognition-malformed",
        LeadKinds.NONCE_ISSUED to "nonce-issued",
        LeadKinds.NONCE_CONSUMED to "nonce-consumed",
        LeadKinds.APPROVAL_RECORDED to "approval-recorded",
      )
    for ((actual, wire) in pairs) assertEquals(wire, wire, actual)
    assertEquals("LeadKinds names exactly the host's and the ticket workflow's kinds", pairs.map { it.second }.toSet(), declared(LeadKinds::class.java))
  }
}
