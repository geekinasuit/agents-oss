package com.geekinasuit.agency.shared.harness

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Hermetic tests for the harness runtime. The live claude paths (execute/turn against
 * a real `claude` binary) are NOT exercised here — they cost money and need a logged-in
 * CLI. These tests drive the model-agnostic
 * runtime against `/bin/sh` fakes plus the pure claude-argv/JSON-parse seams, pinning
 * the live-proven behaviours without spend.
 */
class HarnessTest {
  private val workRoot: File =
      File(System.getenv("TEST_TMPDIR") ?: System.getProperty("java.io.tmpdir"))

  // ── subprocess runtime (Subprocess.kt) ─────────────────────────────────────

  // Probe: the test sandbox permits spawning /bin/sh — every cell below depends on it.
  @Test
  fun sandbox_can_spawn_bin_sh() {
    val r = Subprocess.run(listOf("/bin/sh", "-c", "echo hello"), workRoot, cleanEnv = false)
    assertEquals("exit (stdout='${r.stdout}' stderr='${r.stderr}')", 0, r.exit)
    assertEquals("hello", r.stdout.trim())
  }

  @Test
  fun procResult_captures_streams_exit_timing() {
    val r = Subprocess.run(listOf("/bin/sh", "-c", "echo out; echo err 1>&2; exit 3"), workRoot, cleanEnv = false)
    assertEquals(3, r.exit)
    assertEquals("out", r.stdout.trim())
    assertEquals("err", r.stderr.trim())
    assertFalse(r.timedOut)
    assertTrue("wallMs >= 0 (was ${r.wallMs})", r.wallMs >= 0)
  }

  @Test
  fun timeout_yields_124_and_timedOut() {
    val r = Subprocess.run(listOf("/bin/sh", "-c", "sleep 30"), workRoot, timeoutSec = 1, cleanEnv = false)
    assertTrue("should have timed out", r.timedOut)
    assertEquals(124, r.exit)
  }

  @Test
  fun killTree_terminates_descendants() {
    val dir = Subprocess.tempDir("harness-kill")
    val marker = File(dir, "child-marker")
    // Parent shell backgrounds a child that would create the marker after 3s, then waits on it.
    val proc =
        Subprocess.start(
            listOf(
                "/bin/sh",
                "-c",
                "( sleep 3; touch '${marker.absolutePath}' ) & echo started; wait"),
            dir,
            cleanEnv = false)
    Thread.sleep(500) // let the backgrounded descendant actually spawn before we snapshot+kill
    val latencyMs = proc.killTreeNow()
    assertTrue("kill latency should be non-negative (was $latencyMs)", latencyMs >= 0)
    // killTreeNow blocks until the snapshot is dead; wait past the 3s delay to be certain the
    // descendant never ran its touch.
    Thread.sleep(3500)
    assertFalse(
        "descendant survived tree-kill and wrote ${marker.absolutePath}", marker.exists())
  }

  @Test
  fun cleanEnv_scrubs_ambient_keeps_allowlist_and_explicit() {
    val scrubbed =
        System.getenv().entries.firstOrNull {
          it.key !in Subprocess.POD_ENV_ALLOWLIST && it.value.isNotEmpty()
        }?.key ?: error("test needs a non-empty, non-allowlisted ambient env var")
    val kept =
        Subprocess.POD_ENV_ALLOWLIST.firstOrNull { System.getenv(it) != null }
            ?: error("test needs an allowlisted ambient env var present")
    val script = "printf 'scrub=[%s] keep=[%s] expl=[%s]' \"\$$scrubbed\" \"\$$kept\" \"\$EXPL\""

    val clean =
        Subprocess.run(
            listOf("/bin/sh", "-c", script),
            workRoot,
            env = mapOf("EXPL" to "yes"),
            cleanEnv = true)
    assertEquals(0, clean.exit)
    assertTrue("ambient '$scrubbed' scrubbed under cleanEnv: '${clean.stdout}'", clean.stdout.contains("scrub=[]"))
    assertFalse("allowlisted '$kept' survives cleanEnv: '${clean.stdout}'", clean.stdout.contains("keep=[]"))
    assertTrue("explicit env passes through: '${clean.stdout}'", clean.stdout.contains("expl=[yes]"))

    val dirty = Subprocess.run(listOf("/bin/sh", "-c", script), workRoot, cleanEnv = false)
    assertFalse("ambient '$scrubbed' inherited without cleanEnv: '${dirty.stdout}'", dirty.stdout.contains("scrub=[]"))
  }

  // ── claude adapter pure seams (ClaudeHarness.kt) ────────────────────────────

  @Test
  fun turnCmd_builds_full_argv_in_order() {
    val cmd =
        ClaudeHarness("claude")
            .turnCmd(
                prompt = "hello",
                model = "m1",
                resume = "sid-1",
                forkSession = true,
                appendSystemPrompt = "be terse")
    assertEquals(
        listOf(
            "claude", "-p", "--output-format", "json", "--model", "m1",
            "--resume", "sid-1", "--fork-session", "--append-system-prompt", "be terse", "hello"),
        cmd)
  }

  @Test
  fun turnCmd_minimal_defaults_model_and_prompt_last() {
    val cmd = ClaudeHarness("claude").turnCmd(prompt = "hi")
    assertEquals(
        listOf("claude", "-p", "--output-format", "json", "--model", ClaudeHarness.MODEL, "hi"),
        cmd)
  }

  @Test
  fun parseTurn_reads_claude_envelope() {
    val fixture =
        """{"result":"the answer","session_id":"11111111-2222-3333-4444-555555555555","subtype":"success","num_turns":2,"total_cost_usd":0.0123,"is_error":false}"""
    val t =
        ClaudeHarness.parseTurn(
            ProcResult(stdout = fixture, stderr = "", exit = 0, timedOut = false, wallMs = 10))
    assertEquals("the answer", t.resultText)
    assertEquals("11111111-2222-3333-4444-555555555555", t.sessionId)
    assertTrue("session id matches UUID_RE", ClaudeHarness.UUID_RE.matches(t.sessionId))
    assertEquals("success", t.subtype)
    assertEquals(2, t.numTurns)
    assertEquals(0.0123, t.costUsd, 1e-9)
    assertFalse(t.isError)
    assertTrue("ok = exit0 && !isError", t.ok)
  }

  @Test
  fun parseTurn_handles_nonjson_gracefully() {
    val t =
        ClaudeHarness.parseTurn(
            ProcResult(stdout = "not json at all", stderr = "", exit = 1, timedOut = false, wallMs = 5))
    assertEquals(null, t.json)
    assertEquals("", t.resultText)
    assertEquals(-1, t.numTurns)
    assertTrue("isError defaults true on unparseable output", t.isError)
    assertFalse("not ok on exit1 + parse fail", t.ok)
    assertEquals("not json at all", t.raw)
  }

  // ── neutral mapping seam (ClaudeHarness.neutralResult) ──────────────────────
  // The one seam every neutral-path consumer depends on; driven through the real
  // parseTurn so the map exercises the same envelope claude actually emits.

  @Test
  fun neutralResult_flags_is_error_even_on_exit_zero() {
    // claude can report is_error while the process exits 0 — a bare exit code would
    // read this as success.
    val fixture =
        """{"result":"partial answer","session_id":"11111111-2222-3333-4444-555555555555","subtype":"error_during_execution","num_turns":1,"total_cost_usd":0.02,"is_error":true}"""
    val t =
        ClaudeHarness.parseTurn(
            ProcResult(stdout = fixture, stderr = "", exit = 0, timedOut = false, wallMs = 10))
    val r = ClaudeHarness.neutralResult(t)
    assertEquals("exit code alone would look like success", 0, r.exitCode)
    assertFalse("is_error must surface through the neutral seam despite exit 0", r.ok)
    assertEquals("partial answer", r.text)
    assertEquals(1, r.toolCalls)
  }

  @Test
  fun neutralResult_maps_parse_failure_to_diagnostic_not_sentinel() {
    val garbage = "boom: not json"
    val t =
        ClaudeHarness.parseTurn(
            ProcResult(stdout = garbage, stderr = "", exit = 0, timedOut = false, wallMs = 5))
    val r = ClaudeHarness.neutralResult(t)
    assertFalse("unparseable output is a failure even on exit 0", r.ok)
    assertEquals("text carries raw output as diagnostic (no sentinel prefix)", garbage, r.text)
    assertEquals("num_turns absent → toolCalls null, not -1", null, r.toolCalls)
  }

  @Test
  fun neutralResult_maps_clean_success() {
    val fixture =
        """{"result":"done","session_id":"11111111-2222-3333-4444-555555555555","subtype":"success","num_turns":4,"total_cost_usd":0.01,"is_error":false}"""
    val t =
        ClaudeHarness.parseTurn(
            ProcResult(stdout = fixture, stderr = "", exit = 0, timedOut = false, wallMs = 8))
    val r = ClaudeHarness.neutralResult(t)
    assertTrue("clean turn is ok", r.ok)
    assertEquals("done", r.text)
    assertEquals(4, r.toolCalls)
    assertEquals(0, r.exitCode)
  }

  @Test
  fun provenanceStamp_carries_harness_fields() {
    val stamp = ClaudeHarness.provenanceStamp("v1.2.3", "claude-haiku", "sid-9")
    assertEquals("claude-code", stamp.getString("harness"))
    assertEquals("v1.2.3", stamp.getString("harnessVersion"))
    assertEquals("claude-haiku", stamp.getString("model"))
    assertEquals("sid-9", stamp.getString("sessionId"))
  }
}
