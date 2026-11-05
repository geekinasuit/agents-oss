package com.geekinasuit.agency.nostr

/**
 * Decides how a client walks back through a relay's stored events, one page at a time, with NIP-01's
 * `until`. A relay answers a REQ with the newest events it allows, so the events past that cap are
 * reached only by asking again from below what came back. Feed each stored event of a page to [saw],
 * and call [pageEnded] at that page's EOSE. The first page is the replay of the REQ with no `until`.
 *
 * The next `until` is one above the lowest `created_at` seen on the page, taken over the whole page
 * because a relay's order is not trusted. One above, not the lowest itself: a relay that reads `until`
 * as "before", where NIP-01 says "at or before", would otherwise skip the rest of that second. So a
 * page repeats what it starts from. A walk ends on a page that gets no lower than the page before it,
 * and it ends so whatever cap the relay puts on a page.
 *
 * A page that gets no lower and holds [limit] events may have stopped short, so it reports
 * [Decision.Stalled], and there may be more below it. [limit] events stamped in one second, or across
 * two adjacent ones, stall a walk: `until` has one-second steps, so nothing asks for the rest of that
 * second. Any key the relay stores events for can make such a run. A relay that ignores `until` stalls
 * a walk too. A relay that caps a page below [limit] makes a stall look like [Decision.Done]. A page
 * after the first that is empty also stalls: under either reading of `until` it should repeat the
 * lowest event, so the relay has stopped answering as it did.
 *
 * The pager trusts what it is fed to be the page. A low stamp fed by mistake moves the walk past
 * everything between, so feed it only events that came under that page's own REQ, before its EOSE.
 *
 * `created_at` is whatever each author wrote. A negative one ends the walk: NIP-01 has no `until` below
 * zero to ask with.
 *
 * Not thread-safe.
 */
class UntilPager(private val limit: Int) {
  /** What [pageEnded] says to do next. */
  sealed interface Decision {
    /** Ask for a page with this `until`. */
    data class Next(val until: Long) : Decision

    /** The walk reached the end of what the relay gives. */
    data object Done : Decision

    /** The walk can get no lower, and there may be more below. */
    data object Stalled : Decision
  }

  private var reached: Long? = null
  private var pageLowest: Long? = null
  private var pageSize = 0

  init {
    require(limit >= 1) { "a page must hold at least one event, was $limit" }
  }

  /** Count one stored event of the page in progress. */
  fun saw(createdAt: Long) {
    pageLowest = minOf(pageLowest ?: createdAt, createdAt)
    pageSize++
  }

  /** The page in progress is complete. Say what comes next, and start a new page. */
  fun pageEnded(): Decision {
    val lowest = pageLowest
    val size = pageSize
    val previous = reached
    pageLowest = null
    pageSize = 0
    return when {
      lowest == null -> if (previous == null) Decision.Done else Decision.Stalled
      previous != null && lowest >= previous -> if (size >= limit) Decision.Stalled else Decision.Done
      lowest < 0 -> Decision.Done
      else -> {
        reached = lowest
        Decision.Next(if (lowest == Long.MAX_VALUE) lowest else lowest + 1)
      }
    }
  }
}
