package com.geekinasuit.agency.nostr

import com.geekinasuit.agency.nostr.UntilPager.Decision
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** [UntilPager]'s decisions, page by page. The walks against a relay are in `ApprovalIngressTest`. */
class UntilPagerTest {
  private fun UntilPager.page(vararg createdAt: Long): Decision {
    createdAt.forEach { saw(it) }
    return pageEnded()
  }

  @Test
  fun `an empty first page ends the walk`() {
    assertEquals(Decision.Done, UntilPager(3).page())
  }

  @Test
  fun `the next page starts one above the page's lowest, wherever on the page that came`() {
    assertEquals(Decision.Next(101), UntilPager(3).page(300, 100, 200))
  }

  @Test
  fun `a walk goes down page by page while each page gets lower`() {
    val pager = UntilPager(3)
    assertEquals(Decision.Next(201), pager.page(400, 300, 200))
    assertEquals(Decision.Next(101), pager.page(201, 200, 100))
  }

  @Test
  fun `a short page that gets no lower ends the walk`() {
    val pager = UntilPager(3)
    assertEquals(Decision.Next(201), pager.page(400, 300, 200))
    assertEquals("the repeat of the page's own lowest", Decision.Done, pager.page(200))
  }

  @Test
  fun `an empty page after the first stalls, since it should have repeated the lowest event`() {
    val pager = UntilPager(3)
    assertEquals(Decision.Next(201), pager.page(400, 300, 200))
    assertEquals(Decision.Stalled, pager.page())
  }

  @Test
  fun `a page below the limit that gets lower goes on, so a relay's lower cap does not end the walk`() {
    val pager = UntilPager(500)
    assertEquals(Decision.Next(301), pager.page(400, 300))
    assertEquals(Decision.Next(201), pager.page(301, 200))
  }

  @Test
  fun `a full page that gets no lower stalls`() {
    val pager = UntilPager(3)
    assertEquals(Decision.Next(101), pager.page(100, 100, 100))
    assertEquals(Decision.Stalled, pager.page(100, 100, 100))
  }

  @Test
  fun `a full page stamped higher than the walk has reached stalls, as a relay that ignores until sends`() {
    val pager = UntilPager(3)
    assertEquals(Decision.Next(201), pager.page(400, 300, 200))
    assertEquals(Decision.Stalled, pager.page(400, 300, 200))
  }

  @Test
  fun `a page's size and lowest do not carry into the next page`() {
    val pager = UntilPager(3)
    assertEquals(Decision.Next(101), pager.page(300, 200, 100))
    assertEquals("one event, not four", Decision.Done, pager.page(100))
  }

  @Test
  fun `a negative created_at ends the walk`() {
    assertEquals(Decision.Done, UntilPager(3).page(100, -1))
  }

  @Test
  fun `the lowest created_at there can be still gets a next page`() {
    assertEquals(Decision.Next(1), UntilPager(3).page(0))
  }

  @Test
  fun `the highest created_at does not overflow the next until`() {
    assertEquals(Decision.Next(Long.MAX_VALUE), UntilPager(3).page(Long.MAX_VALUE))
  }

  @Test
  fun `a limit below one is refused`() {
    assertThrows(IllegalArgumentException::class.java) { UntilPager(0) }
  }
}
