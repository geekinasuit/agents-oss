package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.harness.ClaudeHarness
import com.geekinasuit.agency.shared.journal.JournalState
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Hermetic coverage of [ClaudeCognition]'s answers about whether its turn was presented the wake's
 * context, which decide whether the daemon retires the wake's mail (#255). The harness runs a
 * stand-in `claude` executable, a shell script written per cell, through the harness's own
 * `claudeBin` seam. No real model is called.
 */
class ClaudeCognitionTest {

  @get:Rule val tmp = TemporaryFolder()

  /** A stand-in `claude` that records it was run, then prints [stdout] and exits [exit]. */
  private class FakeClaude(dir: File, stdout: String, exit: Int) {
    val ran = File(dir, "ran")
    val bin =
      File(dir, "fake-claude").apply {
        writeText(
          "#!/bin/sh\n" +
            ": > '${ran.absolutePath}'\n" +
            "cat <<'ENVELOPE'\n$stdout\nENVELOPE\n" +
            "exit $exit\n"
        )
        setExecutable(true)
      }
  }

  private fun cognition(fake: FakeClaude, workDir: File, maxTotalUsd: Double = 5.0) =
    ClaudeCognition(
      harness = ClaudeHarness(fake.bin.absolutePath),
      workDir = workDir,
      maxTotalUsd = maxTotalUsd,
      timeoutSec = 30,
    )

  private fun wake(lead: LeadState) =
    WakeContext(
      reason = WakeReason.MailArrived("please review"),
      lead = lead,
      shared = JournalState(),
      undeliveredMail = listOf(1L to "please review"),
    )

  @Test
  fun atTheSpendCapTheEscalationRunsNoTurnAndPresentsNothing() {
    val dir = tmp.newFolder()
    val fake = FakeClaude(dir, SUCCESS_ENVELOPE, exit = 0)
    val out = cognition(fake, dir, maxTotalUsd = 1.0).decide(wake(LeadState(cognitionSpendUsd = 1.5)))

    assertFalse("no harness call is made at the cap", fake.ran.exists())
    assertTrue(
      (out.proposals.single() as Proposal.ProposeEscalate).reason.startsWith("cognition budget exhausted")
    )
    assertEquals(ContextPresentation.NOT_PRESENTED, out.presentation)
  }

  @Test
  fun atTheSpendCapALaterIdleRunsNoTurnAndPresentsNothing() {
    val dir = tmp.newFolder()
    val fake = FakeClaude(dir, SUCCESS_ENVELOPE, exit = 0)
    val lead =
      LeadState(
        cognitionSpendUsd = 1.5,
        escalations = listOf("cognition budget exhausted: already raised"),
      )
    val out = cognition(fake, dir, maxTotalUsd = 1.0).decide(wake(lead))

    assertFalse("no harness call is made at the cap", fake.ran.exists())
    assertTrue("the escalation is not raised twice", out.proposals.isEmpty())
    assertEquals(ContextPresentation.NOT_PRESENTED, out.presentation)
  }

  @Test
  fun aFailedTurnPresentsNothing() {
    val dir = tmp.newFolder()
    val fake = FakeClaude(dir, "not an envelope", exit = 1)
    val out = cognition(fake, dir).decide(wake(LeadState()))

    assertTrue("the harness was run", fake.ran.exists())
    assertNull("a failed turn is not a malformed one", out.malformed)
    assertTrue(
      (out.proposals.single() as Proposal.ProposeEscalate).reason.startsWith("cognition turn failed")
    )
    assertEquals(ContextPresentation.NOT_PRESENTED, out.presentation)
  }

  @Test
  fun aTurnThatExitsCleanButReportsAnErrorPresentsNothing() {
    // The CLI can report is_error while the process exits 0 (ClaudeHarness.neutralResult), so a
    // bare exit check is not the failure test. The result is prose, as an error's is.
    val dir = tmp.newFolder()
    val fake = FakeClaude(dir, ERROR_ENVELOPE, exit = 0)
    val out = cognition(fake, dir).decide(wake(LeadState()))

    assertTrue("the harness was run", fake.ran.exists())
    assertEquals(ContextPresentation.NOT_PRESENTED, out.presentation)
    assertNull("a failed turn is not a malformed one", out.malformed)
    assertTrue(
      (out.proposals.single() as Proposal.ProposeEscalate).reason.startsWith("cognition turn failed")
    )
  }

  @Test
  fun aSuccessfulParsedTurnWasPresentedTheContext() {
    val dir = tmp.newFolder()
    val fake = FakeClaude(dir, SUCCESS_ENVELOPE, exit = 0)
    val out = cognition(fake, dir).decide(wake(LeadState()))

    assertTrue("the harness was run", fake.ran.exists())
    assertNull(out.malformed)
    assertTrue("the reply was an idle", out.proposals.isEmpty())
    assertEquals("s-1", out.meta["sessionId"])
    assertEquals(ContextPresentation.PRESENTED, out.presentation)
  }

  private companion object {
    /** A `claude -p --output-format json` result envelope whose result is an idle decision. */
    val SUCCESS_ENVELOPE =
      """{"type":"result","subtype":"success","is_error":false,""" +
        """"result":"{\"proposals\": [], \"reasoning\": \"waiting\"}",""" +
        """"session_id":"s-1","num_turns":1,"total_cost_usd":0.01}"""

    /** An error envelope, in the shape [ClaudeHarness.parseTurn] reads: is_error true. */
    val ERROR_ENVELOPE =
      """{"type":"result","subtype":"error_max_budget_usd","is_error":true,""" +
        """"result":"budget exceeded before the turn finished",""" +
        """"session_id":"s-2","num_turns":1,"total_cost_usd":0.02}"""
  }
}
