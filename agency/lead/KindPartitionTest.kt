package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
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
        "workflow".takeIf { kind in ticketWorkflow.fold.substrateKinds },
      )
      assertEquals("lead kind $kind is folded by: $sides", 1, sides.size)
    }
  }

  @Test
  fun theTicketWorkflowPartitionsWithTheHost() {
    requireKindPartition(HOST_KINDS, ticketWorkflow.fold)
  }

  @Test
  fun aWorkflowClaimingAHostKindIsRefused() {
    val e =
      assertThrows(IllegalArgumentException::class.java) {
        requireKindPartition(HOST_KINDS, FakeFold(kinds = setOf("w-kind", LeadKinds.GATE_OPENED)))
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
          requireKindPartition(HOST_KINDS, FakeFold(kinds = setOf("w-kind"), scopeEnds = setOf(scopeEnd)))
        }
      assertTrue(e.message!!, e.message!!.contains(scopeEnd))
    }
  }

  @Test
  fun aWorkflowOfItsOwnKindsIsAccepted() {
    requireKindPartition(HOST_KINDS, FakeFold(kinds = setOf("w-kind", "w-done"), scopeEnds = setOf("w-done")))
  }

  @Test
  fun theHostFoldsWithTheKindsItChecked() {
    // A set whose `contains` disagrees with its elements: it lists only its own kind, so the
    // partition check passes, but claims a host kind on lookup. Folding with the live set would let
    // the workflow's provenance rule reject a legitimately cognition-authored host entry.
    val lying =
      object : AbstractSet<String>() {
        private val listed = setOf("w-kind")
        override val size = listed.size

        override fun iterator() = listed.iterator()

        override fun contains(element: String) = element == HostKinds.COGNITION_PROPOSED || element in listed
      }
    val turn =
      JournalEntry(
        seq = 1,
        schemaVersion = 3,
        kind = HostKinds.COGNITION_PROPOSED,
        chainContext = "agency/lead/main/v3",
        origin = ORIGIN_COGNITION,
        keyEpoch = 0,
        salt = "",
        payloadCommitment = "",
        payloadJson = """{"costUsd":"0.5"}""",
        idempotencyKey = null,
        prevHash = "",
        hash = "",
        sig = null,
      )
    val lead = foldLeadJournal(listOf(turn), LeadAuth.DENY_ALL, FakeFold(kinds = lying))
    assertEquals("the turn is not rejected", emptyList<Pair<Long, String>>(), lead.misOriginedEntries)
    assertEquals("the turn's spend is folded", 0.5, lead.cognitionSpendUsd, 0.0)
  }

  @Test
  fun theHostEndsTheScopeOnTheKindsItChecked() {
    // A scope-end set that lists only the workflow's own kind, so the partition check passes, but
    // claims a host kind on lookup. Folding with the live set would let the workflow end the scope
    // (clearing the host's scoped records) on a host entry.
    val lying =
      object : AbstractSet<String>() {
        private val listed = setOf("w-done")
        override val size = listed.size

        override fun iterator() = listed.iterator()

        override fun contains(element: String) = element == HostKinds.COGNITION_PROPOSED || element in listed
      }
    val turn =
      JournalEntry(
        seq = 1,
        schemaVersion = 3,
        kind = HostKinds.COGNITION_PROPOSED,
        chainContext = "agency/lead/main/v3",
        origin = ORIGIN_COGNITION,
        keyEpoch = 0,
        salt = "",
        payloadCommitment = "",
        payloadJson = """{"costUsd":"0.5"}""",
        idempotencyKey = null,
        prevHash = "",
        hash = "",
        sig = null,
      )
    val lead = foldLeadJournal(listOf(turn), LeadAuth.DENY_ALL, FakeFold(kinds = setOf("w-done"), scopeEnds = lying))
    assertEquals("the turn's spend is folded, not cleared as a scope end", 0.5, lead.cognitionSpendUsd, 0.0)
  }

  private class FakeFold(kinds: Set<String>, scopeEnds: Set<String> = emptySet()) : WorkflowFold<LeadState, Unit> {
    override val substrateKinds = kinds
    override val scopeEndKinds = scopeEnds
    override val start = Unit

    override fun expectedTaskRefs(w: Unit) = emptySet<String>()

    override fun step(w: Unit, e: JournalEntry, outcome: HostOutcome) = Unit

    override fun assemble(host: HostState, w: Unit) =
      LeadState(misOriginedEntries = host.misOriginedEntries, cognitionSpendUsd = host.cognitionSpendUsd)
  }
}
