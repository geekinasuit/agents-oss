package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.ChainCursor
import com.geekinasuit.agency.shared.journal.JournalStore

/**
 * The host's records and the workflow's state over [store]'s journal, kept current by folding only
 * the entries appended since the last [advance]: a verified tail read ([JournalStore.readAfter]) from
 * a retained cursor, each entry through the same step a cold fold takes ([LeadFoldStepper]). While
 * the journal only grows, [host] and [lead] after every [advance] equal [foldHostAndLead] over
 * [JournalStore.readAll].
 *
 * Entries already folded are not verified again: [JournalStore.readAfter] checks only the cursor's
 * stored hash and epoch. So an in-place change to an entry the view has folded, one that leaves the
 * cursor's stored hash alone, goes unseen here while a cold fold of [JournalStore.readAll] refuses
 * the journal. Verifying the whole chain stays the job of a full read; the host loop does one on
 * every wake.
 *
 * The first [advance] reads from genesis. A failed [advance] leaves the view failed, whatever the
 * cause (a chain fault in the tail, a fold failure on one of its entries, a failure assembling the
 * lead's state, or a store error): every later [advance], [host] and [lead] throws
 * [IllegalStateException] with the first failure as its cause. To try again, build a new view, which
 * reads from genesis. The lead's state is assembled inside [advance], so a workflow whose assemble
 * throws fails the advance, as it fails a cold fold. Before the first [advance], [lead] is assembled
 * from the empty state when the view is built, and a failure there is thrown by the constructor.
 *
 * Not thread-safe: the caller serializes calls.
 */
internal class IncrementalLeadView<S, W>(
  private val store: JournalStore,
  auth: LeadAuth,
  fold: WorkflowFold<S, W>,
) {
  private val stepper = LeadFoldStepper(auth, fold)
  private var cursor = ChainCursor.START
  private var state = stepper.start
  private var assembled = stepper.assemble(state)
  private var failure: Exception? = null

  /** The host's records as of the last [advance]. */
  val host: HostState
    get() = current().host

  /** The lead's state as of the last [advance]. */
  val lead: S
    get() {
      current()
      return assembled
    }

  /** Folds the entries appended since the last call. */
  fun advance() {
    current()
    try {
      val tail = store.readAfter(cursor)
      var next = state
      for (e in tail.entries) next = stepper.step(next, e)
      val nextLead = stepper.assemble(next)
      state = next
      assembled = nextLead
      cursor = tail.cursor
    } catch (x: Exception) {
      failure = x
      throw x
    }
  }

  private fun current(): LeadFoldState<W> {
    failure?.let { throw IllegalStateException("the view failed an earlier advance", it) }
    return state
  }
}
