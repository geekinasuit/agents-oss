package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.ChainBrokenException
import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SqliteStore
import com.geekinasuit.agency.shared.journal.entryHashV3
import com.geekinasuit.agency.shared.journal.newSaltHex
import com.geekinasuit.agency.shared.journal.payloadCommitment
import java.sql.DriverManager
import kotlin.random.Random
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * [IncrementalLeadView] must equal a cold [foldHostAndLead] over [SqliteStore.readAll] after every
 * advance. Corpus journals ([corpus]) are re-chained into real stores, so each advance goes through
 * the verified tail read, and appended in random batches, empty and single-entry ones included. A
 * journal that fails to fold must fail the view's advance with the same exception, leave its state
 * as it was, and leave it unusable.
 */
class IncrementalLeadViewTest {

  @get:Rule val tmp = TemporaryFolder()

  @Test
  fun theViewEqualsAColdFoldAfterEveryAdvance() {
    val r = Random(SEED)
    var advances = 0
    var multiEntryBatches = 0
    var failures = 0
    for ((i, journal) in corpus().withIndex()) {
      SqliteStore(tmp.newFolder().absolutePath, componentId = "lead").use { store ->
        val views = AUTHS.map { (name, auth) -> Triple(name, auth, IncrementalLeadView(store, auth, TicketWorkflowFold)) }
        val live = views.toMutableList()
        var next = 0
        while (live.isNotEmpty()) {
          val batch = r.nextInt(0, 5)
          if (batch > 1) multiEntryBatches++
          repeat(batch) { if (next < journal.size) appendChained(store, journal[next++]) }
          val iterator = live.iterator()
          while (iterator.hasNext()) {
            val (name, auth, view) = iterator.next()
            val label = "journal $i through entry $next under $name"
            if (!assertSameAdvance(label, view, auth, store)) {
              failures++
              iterator.remove()
            }
            advances++
          }
          if (next >= journal.size) break
        }
      }
    }
    val counts = "advances=$advances multiEntryBatches=$multiEntryBatches failures=$failures"
    assertTrue(counts, advances > 1000)
    assertTrue(counts, multiEntryBatches > 100)
    assertTrue(counts, failures > 0)
  }

  @Test
  fun aChainFaultInTheTailFailsTheAdvanceAndLeavesTheViewUnusable() {
    val dir = tmp.newFolder().absolutePath
    SqliteStore(dir, componentId = "lead").use { store ->
      val view = IncrementalLeadView(store, LeadAuth.DENY_ALL, TicketWorkflowFold)
      store.append(LeadKinds.RUN_STARTED, buildJsonObject {}, origin = ORIGIN_SUBSTRATE)
      view.advance()
      store.append(LeadKinds.STATUS_WRITTEN, buildJsonObject { put("status", "s") }, origin = ORIGIN_SUBSTRATE)
      DriverManager.getConnection("jdbc:sqlite:$dir/journal.db").use { c ->
        c.createStatement().use { st -> st.executeUpdate("UPDATE journal SET payload='{\"status\":\"t\"}' WHERE seq=3") }
      }
      val x = assertThrows(ChainBrokenException::class.java) { view.advance() }
      assertFailed("chain fault", view, x)
    }
  }

  @Test
  fun anInPlaceChangeToAnEntryAlreadyFoldedIsUnseenByTheViewAndRefusedByAColdFold() {
    val dir = tmp.newFolder().absolutePath
    SqliteStore(dir, componentId = "lead").use { store ->
      val view = IncrementalLeadView(store, LeadAuth.DENY_ALL, TicketWorkflowFold)
      store.append(LeadKinds.RUN_STARTED, buildJsonObject {}, origin = ORIGIN_SUBSTRATE)
      store.append(LeadKinds.STATUS_WRITTEN, buildJsonObject { put("status", "s") }, origin = ORIGIN_SUBSTRATE)
      view.advance()
      store.append(LeadKinds.STATUS_WRITTEN, buildJsonObject { put("status", "u") }, origin = ORIGIN_SUBSTRATE)
      DriverManager.getConnection("jdbc:sqlite:$dir/journal.db").use { c ->
        c.createStatement().use { st -> st.executeUpdate("UPDATE journal SET payload='{\"status\":\"t\"}' WHERE seq=3") }
      }
      // The view does not re-verify what it has folded; a full read, which the host loop takes on
      // every wake, refuses the journal. This cell keeps the gap documented, not blessed.
      view.advance()
      assertEquals(listOf("s", "u"), view.host.statusTail)
      assertThrows(ChainBrokenException::class.java) { store.readAll() }
    }
  }

  @Test
  fun aWorkflowWhoseAssembleThrowsFailsTheAdvanceAsItFailsAColdFold() {
    SqliteStore(tmp.newFolder().absolutePath, componentId = "lead").use { store ->
      val view = IncrementalLeadView(store, LeadAuth.DENY_ALL, AssembleFailsPastOne)
      store.append(LeadKinds.RUN_STARTED, buildJsonObject {}, origin = ORIGIN_SUBSTRATE)
      view.advance()
      assertEquals("positive control: one entry assembles", 1, view.lead)
      store.append(LeadKinds.RUN_STARTED, buildJsonObject {}, origin = ORIGIN_SUBSTRATE)
      val cold = assertThrows(IllegalStateException::class.java) {
        foldHostAndLead(store.readAll(), LeadAuth.DENY_ALL, AssembleFailsPastOne)
      }
      val warm = assertThrows(IllegalStateException::class.java) { view.advance() }
      assertEquals(cold.message, warm.message)
      assertFailed("assemble failure", view, warm)
    }
  }

  /** A workflow that counts run-started rows and cannot assemble a lead's state past one. */
  private object AssembleFailsPastOne : WorkflowFold<Int, Int> {
    override val substrateKinds = emptySet<String>()
    override val scopeEndKinds = emptySet<String>()
    override val start = 0

    override fun expectedTaskRefs(w: Int) = emptySet<String>()

    override fun step(w: Int, e: JournalEntry, outcome: HostOutcome) = if (e.kind == LeadKinds.RUN_STARTED) w + 1 else w

    override fun assemble(host: HostState, w: Int): Int {
      check(w <= 1) { "cannot assemble past one run, at $w" }
      return w
    }
  }

  /** [view] has failed with [cause]: its advance and both reads refuse, naming [cause]. */
  private fun assertFailed(label: String, view: IncrementalLeadView<*, *>, cause: Throwable) {
    assertSame("$label: advance", cause, assertThrows(IllegalStateException::class.java) { view.advance() }.cause)
    assertSame("$label: host", cause, assertThrows(IllegalStateException::class.java) { view.host }.cause)
    assertSame("$label: lead", cause, assertThrows(IllegalStateException::class.java) { view.lead }.cause)
  }

  /** Advances [view] and folds [store] cold under [auth]; returns false once both have failed. */
  private fun assertSameAdvance(
    label: String,
    view: IncrementalLeadView<LeadState, *>,
    auth: LeadAuth,
    store: SqliteStore,
  ): Boolean {
    val cold = runCatching { foldHostAndLead(store.readAll(), auth, TicketWorkflowFold) }
    val warm = runCatching {
      view.advance()
      view.host to view.lead
    }
    when {
      cold.isSuccess && warm.isSuccess -> assertEquals(label, cold.getOrThrow(), warm.getOrThrow())
      cold.isFailure && warm.isFailure -> {
        val a = cold.exceptionOrNull()!!
        val b = warm.exceptionOrNull()!!
        assertEquals("$label: exception type", a::class, b::class)
        assertEquals("$label: exception message", a.message, b.message)
        assertFailed(label, view, b)
        return false
      }
      else ->
        fail(
          "$label: cold ${if (cold.isSuccess) "folded" else "failed (${cold.exceptionOrNull()})"}, " +
            "view ${if (warm.isSuccess) "folded" else "failed (${warm.exceptionOrNull()})"}"
        )
    }
    return true
  }

  /** Appends [e]'s kind, origin and payload as the next hash-chained entry of [store]. Raw, so a
   * payload that is not JSON, which [SqliteStore.append] refuses, still reaches the fold. */
  private fun appendChained(store: SqliteStore, e: JournalEntry) {
    val (lastSeq, lastHash) = store.chainHead()
    val seq = lastSeq + 1
    val salt = newSaltHex()
    val commitment = payloadCommitment(salt, e.payloadJson)
    val hash =
      entryHashV3(seq, 3, e.kind, store.chainContext, e.origin, 0, salt, commitment, e.payloadJson, null, lastHash)
    store.appendRaw(
      JournalEntry(seq, 3, e.kind, store.chainContext, e.origin, 0, salt, commitment, e.payloadJson, null, lastHash, hash, null)
    )
  }
}
