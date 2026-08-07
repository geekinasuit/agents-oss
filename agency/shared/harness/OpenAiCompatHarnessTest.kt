package com.geekinasuit.agency.shared.harness

import java.io.File
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Hermetic coverage of the OpenAI-compatible transport: profile validation, the exact
 * request put on the wire, and every way a response can fail to be usable. A
 * [FakeOpenAiEndpoint] on an ephemeral loopback port stands in for the provider — no
 * Ollama, no network, deterministic in CI.
 *
 * The success fixture is a reply captured verbatim from a live `qwen3-coder:30b`; see
 * [FakeOpenAiEndpoint.CAPTURED_OLLAMA_RESPONSE] for why it is kept as captured bytes.
 */
class OpenAiCompatHarnessTest {

  private var endpoint: FakeOpenAiEndpoint? = null

  @After
  fun tearDown() {
    endpoint?.close()
  }

  private fun harnessFor(
    body: String,
    status: Int = 200,
    delayMs: Long = 0,
  ): Pair<OpenAiCompatHarness, FakeOpenAiEndpoint> {
    val ep = FakeOpenAiEndpoint(body, status, delayMs)
    endpoint = ep
    return OpenAiCompatHarness(OpenAiCompatProfile.ollama(MODEL, ep.baseUrl)) to ep
  }

  // ---- profile: the configuration assertions the egress claim actually rests on ----

  @Test
  fun theOllamaProfileIsLoopbackAndSendsNoCredential() {
    val p = OpenAiCompatProfile.ollama(MODEL)
    assertEquals(OpenAiAuthMode.NONE, p.authMode)
    assertTrue("the default Ollama endpoint must be loopback", p.isLoopback)
    assertEquals("http://localhost:11434", p.baseUrl)
  }

  @Test
  fun aRemoteEndpointIsNotLoopback() {
    val p = OpenAiCompatProfile("remote", "https://api.example.com", MODEL, OpenAiAuthMode.NONE)
    assertFalse(p.isLoopback)
  }

  @Test
  fun aKeyedProfileIsRefusedAtConstruction() {
    val e =
      try {
        OpenAiCompatProfile("grok", "https://api.x.ai", "grok-4", OpenAiAuthMode.BEARER)
        throw AssertionError("a keyed profile must not be constructible yet")
      } catch (expected: IllegalArgumentException) {
        expected
      }
    // Refusing by NAMING what is missing, so a misconfiguration reads as a fence rather
    // than a bug: the fault is the absent key lifecycle, not the value passed.
    assertTrue(e.message!!.contains("only key-free endpoints"))
    assertTrue(e.message!!.contains("key lifecycle"))
  }

  @Test
  fun aMalformedBaseUrlIsRefusedAtConstruction() {
    // No scheme; a trailing slash that would double up against the request path; empty.
    for (bad in listOf("localhost:11434", "http://localhost:11434/", "")) {
      try {
        OpenAiCompatProfile("p", bad, MODEL, OpenAiAuthMode.NONE)
        throw AssertionError("baseUrl '$bad' must be refused")
      } catch (expected: IllegalArgumentException) {
        assertTrue(expected.message!!.contains("baseUrl"))
      }
    }
  }

  // ---- the wire ----

  @Test
  fun theRequestIsTheProbedWire() {
    val (h, ep) = harnessFor(FakeOpenAiEndpoint.CAPTURED_OLLAMA_RESPONSE)
    h.chat(systemPrompt = "SYS", userPrompt = "USR", maxTokens = 500)

    val sent = JSONObject(ep.lastRequestBody!!)
    assertEquals(MODEL, sent.getString("model"))
    assertFalse("streaming would change the response shape entirely", sent.getBoolean("stream"))
    // Greedy decoding is what makes a within-wake retry a repeat rather than a resample —
    // the property the lead's attempt cap of 1 rests on.
    assertEquals(0, sent.getInt("temperature"))
    assertEquals(500, sent.getInt("max_tokens"))

    val messages = sent.getJSONArray("messages")
    assertEquals(2, messages.length())
    assertEquals("system", messages.getJSONObject(0).getString("role"))
    assertEquals("SYS", messages.getJSONObject(0).getString("content"))
    assertEquals("user", messages.getJSONObject(1).getString("role"))
    assertEquals("USR", messages.getJSONObject(1).getString("content"))

    assertNull("a key-free profile must send no Authorization header", ep.lastAuthHeader)
  }

  @Test
  fun aRealResponseYieldsItsContentAndTokenCounts() {
    val (h, _) = harnessFor(FakeOpenAiEndpoint.CAPTURED_OLLAMA_RESPONSE)
    val turn = h.chat("SYS", "USR")

    assertTrue(turn.ok)
    assertEquals(200, turn.status)
    assertNull(turn.error)
    assertEquals(331, turn.promptTokens)
    assertEquals(57, turn.completionTokens)
    // The content is handed on RAW: interpreting it is the cognition layer's boundary,
    // and a transport that trimmed or reshaped it would be deciding on that layer's behalf.
    assertTrue(turn.text.contains("\"taskRef\": \"plan:TEST-7\""))
    assertTrue(turn.text.trim().startsWith("{"))
  }

  // ---- failure classification: every remote-side fault is a value, never a throw ----

  @Test
  fun anErrorStatusIsAFailedTurnCarryingThatStatus() {
    val (h, _) = harnessFor("""{"error":"model not found"}""", status = 404)
    val turn = h.chat("SYS", "USR")

    assertFalse(turn.ok)
    assertEquals(404, turn.status)
    assertTrue(turn.error!!.contains("HTTP 404"))
    assertEquals("", turn.text)
  }

  @Test
  fun aNonJsonEnvelopeIsAFailedTurn() {
    val (h, _) = harnessFor("<html>proxy error</html>")
    val turn = h.chat("SYS", "USR")

    assertFalse(turn.ok)
    assertTrue(turn.error!!.contains("envelope was not JSON"))
  }

  @Test
  fun anEmptyChoicesListIsAFailedTurn() {
    val (h, _) = harnessFor("""{"choices":[],"usage":{}}""")
    val turn = h.chat("SYS", "USR")

    assertFalse(turn.ok)
    assertTrue(turn.error!!.contains("no choices"))
  }

  @Test
  fun aChoiceWithoutContentIsAFailedTurnNotAnEmptyAnswer() {
    val (h, _) = harnessFor("""{"choices":[{"message":{"role":"assistant"}}]}""")
    val turn = h.chat("SYS", "USR")

    // An absent content field and a model that genuinely said nothing are different facts;
    // reporting the first as an empty answer would hand the cognition layer a phantom turn.
    assertFalse(turn.ok)
    assertTrue(turn.error!!.contains("no content string"))
  }

  @Test
  fun absentUsageIsNullRatherThanZero() {
    val (h, _) = harnessFor("""{"choices":[{"message":{"role":"assistant","content":"{}"}}]}""")
    val turn = h.chat("SYS", "USR")

    assertTrue(turn.ok)
    // Zero is a legitimate token count, so it cannot double as "the endpoint didn't say".
    assertNull(turn.promptTokens)
    assertNull(turn.completionTokens)
  }

  @Test
  fun aTimeoutIsTheDocumentedSentinel() {
    val (h, _) = harnessFor(FakeOpenAiEndpoint.CAPTURED_OLLAMA_RESPONSE, delayMs = 3_000)
    val turn = h.chat("SYS", "USR", timeoutSec = 1)

    assertFalse(turn.ok)
    assertEquals(OpenAiCompatHarness.TIMEOUT_CODE, turn.status)
    assertTrue(turn.error!!.contains("timed out"))
  }

  @Test
  fun anUnreachableEndpointIsAConnectFailureNotAMidExchangeFault() {
    // Port 1 on loopback: nothing listens, so the connection is refused without leaving
    // the machine.
    val h = OpenAiCompatHarness(OpenAiCompatProfile.ollama(MODEL, "http://127.0.0.1:1"))
    val turn = h.chat("SYS", "USR")

    assertFalse(turn.ok)
    // The distinction callers act on: "nothing is serving this" is a different fact from
    // "something answered and the exchange broke", and only the first means absent.
    assertEquals(OpenAiCompatHarness.CONNECT_FAILURE_CODE, turn.status)
    assertTrue(turn.error!!.contains("could not connect"))
  }

  @Test
  fun aTruncatedReplyIsReportedAsTruncationNotHandedOnToBeParsed() {
    val (h, _) = harnessFor(FakeOpenAiEndpoint.reply("""{"proposals": [{"type": "sta""", finishReason = "length"))
    val turn = h.chat("SYS", "USR", maxTokens = 8)

    // Left unreported, this partial JSON would fail the parse and be journaled as MODEL
    // degradation — turning a max_tokens set too low into evidence the model is unreliable.
    assertFalse(turn.ok)
    assertTrue(turn.error!!.contains("truncated"))
    assertTrue(turn.error!!.contains("8-token cap"))
  }

  @Test
  fun theOllamaProfileRefusesARemoteEndpointEvenThoughTheUrlIsWellFormed() {
    val e =
      try {
        OpenAiCompatProfile.ollama(MODEL, "https://ollama.example.com")
        throw AssertionError("a remote endpoint must not be reachable through the ollama profile")
      } catch (expected: IllegalArgumentException) {
        expected
      }
    // Enforced, not merely defaulted: this profile carries no credential, so a remote
    // endpoint means an unauthenticated prompt — mail contents included — leaving the host.
    assertTrue(e.message!!.contains("loopback-only"))
  }

  @Test
  fun theSameQuestionPutTwiceSendsTheSameBytes() {
    val (h, ep) = harnessFor(FakeOpenAiEndpoint.CAPTURED_OLLAMA_RESPONSE)
    h.chat("SYS", "USR")
    val first = ep.lastRequestBody
    h.chat("SYS", "USR")

    // The premise the lead's single-attempt cap rests on: a retry within a wake re-sends an
    // identical request, so a second attempt cannot produce a different answer at
    // temperature 0. Asserted on the BYTES rather than argued from the code.
    assertEquals(2, ep.requestCount)
    assertEquals(first, ep.lastRequestBody)
  }

  // ---- the neutral seam ----

  @Test
  fun executeCarriesHttpStatusInExitCodeAndIgnoresWorkDir() {
    val (h, _) = harnessFor(FakeOpenAiEndpoint.CAPTURED_OLLAMA_RESPONSE)
    // A path that does not exist: proof by construction that workDir is never touched,
    // where passing a real directory would prove nothing.
    val result = h.execute("USR", File("/nonexistent/there/is/no/such/dir"), "SYS")

    assertTrue(result.ok)
    assertEquals(200, result.exitCode)
    assertNull("this wire has no tool-use turn to count", result.toolCalls)
    assertTrue(result.text.contains("plan:TEST-7"))
  }

  @Test
  fun executeReportsAFailureInsteadOfReturningEmptyText() {
    val (h, _) = harnessFor("nonsense", status = 500)
    val result = h.execute("USR", File("."), "SYS")

    assertFalse(result.ok)
    assertEquals(500, result.exitCode)
    assertTrue(result.text.contains("HTTP 500"))
  }

  companion object {
    private const val MODEL = "qwen3-coder:30b"
  }
}
