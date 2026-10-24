package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalState
import java.lang.reflect.Modifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The lead's kinds split between the host and the ticket workflow: each lead kind is folded by
 * exactly one of them, and [requireKindPartition] refuses a workflow that would break that.
 */
class KindPartitionTest {

  /** Every kind [LeadKinds] declares, read from its constants, so a kind added there without being
   * given to the host or the workflow fails [everyLeadKindBelongsToExactlyOneSide]. */
  private val declaredLeadKinds: Set<String> =
    LeadKinds::class
      .java
      .declaredFields
      .filter { Modifier.isStatic(it.modifiers) && it.type == String::class.java }
      .map { it.get(null) as String }
      .toSet()

  private val ticketWorkflow = TicketWorkflow { null }

  @Test
  fun everyLeadKindBelongsToExactlyOneSide() {
    assertTrue("LeadKinds declares no kinds; the reflection read nothing", declaredLeadKinds.isNotEmpty())
    for (kind in declaredLeadKinds) {
      val sides = listOfNotNull(
        "host".takeIf { kind in HOST_KINDS },
        "workflow".takeIf { kind in ticketWorkflow.substrateKinds },
      )
      assertEquals("lead kind $kind is folded by: $sides", 1, sides.size)
    }
  }

  @Test
  fun theTicketWorkflowPartitionsWithTheHost() {
    requireKindPartition(HOST_KINDS, ticketWorkflow)
  }

  @Test
  fun aWorkflowClaimingAHostKindIsRefused() {
    val e =
      assertThrows(IllegalArgumentException::class.java) {
        requireKindPartition(HOST_KINDS, FakeWorkflow(kinds = setOf("w-kind", LeadKinds.GATE_OPENED)))
      }
    assertTrue(e.message!!, e.message!!.contains(LeadKinds.GATE_OPENED))
  }

  @Test
  fun aScopeEndKindTheWorkflowDoesNotOwnIsRefused() {
    // A scope-end kind the host folds would skip the host's own arm for it; one nobody folds would
    // end a scope no workflow fold sees end. Either way it is not among the workflow's own kinds.
    for (scopeEnd in listOf(LeadKinds.RUN_STARTED, "unowned-kind")) {
      val e =
        assertThrows(IllegalArgumentException::class.java) {
          requireKindPartition(HOST_KINDS, FakeWorkflow(kinds = setOf("w-kind"), scopeEnds = setOf(scopeEnd)))
        }
      assertTrue(e.message!!, e.message!!.contains(scopeEnd))
    }
  }

  @Test
  fun aWorkflowOfItsOwnKindsIsAccepted() {
    requireKindPartition(HOST_KINDS, FakeWorkflow(kinds = setOf("w-kind", "w-done"), scopeEnds = setOf("w-done")))
  }

  private class FakeWorkflow(kinds: Set<String>, scopeEnds: Set<String> = emptySet()) : Workflow {
    override val substrateKinds = kinds
    override val scopeEndKinds = scopeEnds
    override val gateKinds = emptySet<String>()

    override fun scopeKey(lead: LeadState): String? = null

    override fun currentScopeKey(lead: LeadState): String? = null

    override fun gateId(gateKind: String, scopeKey: String) = "$gateKind:$scopeKey"

    override fun admitGateOpen(gateKind: String, payloadDigest: String, gateId: String, lead: LeadState) =
      GateOpenDecision.Refuse("fake")

    override fun gateArtifactPath(gateKind: String, lead: LeadState): String? = null

    override fun admitPodSpawn(taskRef: String, lead: LeadState, turn: ProposalTurn, host: HostServices) = false

    override fun redriveMessage(key: String, lead: LeadState): String? = null

    override fun redriveDeclineReason(key: String): String? = null

    override fun mechanicalStep(lead: LeadState, shared: JournalState, host: HostServices) = false
  }
}
