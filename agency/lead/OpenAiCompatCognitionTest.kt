package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.harness.FakeOpenAiEndpoint
import com.geekinasuit.agency.shared.harness.OpenAiCompatHarness
import com.geekinasuit.agency.shared.harness.OpenAiCompatProfile
import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.JournalState
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Deterministic coverage of the Ollama cognition strategy: a real captured model reply
 * becomes the typed proposal it names, unusable replies become classified MALFORMED
 * outcomes rather than proposals, and a dead endpoint is told apart from a degraded model.
 *
 * This is the CI floor for this cognition path. The live gate
 * ([OllamaCognitionSmokeTest]) is local/manual and may legitimately never run here, so
 * everything that can be pinned without a model is pinned in this file.
 */
class OpenAiCompatCognitionTest {

  @get:Rule val tmp = TemporaryFolder()

  private var endpoint: FakeOpenAiEndpoint? = null

  @After
  fun tearDown() {
    endpoint?.close()
  }

  private fun cognitionFor(body: String, status: Int = 200): OpenAiCompatCognition {
    val ep = FakeOpenAiEndpoint(body, status)
    endpoint = ep
    return OpenAiCompatCognition(
      OpenAiCompatHarness(OpenAiCompatProfile.ollama(MODEL, ep.baseUrl))
    )
  }

  private fun wake() =
    WakeContext(
      reason = WakeReason.Adopted,
      lead = LeadState(currentTicket = "TEST-7"),
      shared = JournalState(),
      undeliveredMail = emptyList(),
    )

  @Test
  fun aRealModelReplyBecomesTheTypedProposalItNames() {
    val out = cognitionFor(FakeOpenAiEndpoint.CAPTURED_OLLAMA_RESPONSE).decide(wake())

    assertNull("a well-formed reply is not a malformed turn", out.malformed)
    assertEquals(Proposal.ProposePodSpawn("plan:TEST-7"), out.proposals.single())
    assertTrue(out.reasoning.contains("No plan artifact"))
  }

  @Test
  fun metaCarriesTokensAndDeliberatelyNoCost() {
    val out = cognitionFor(FakeOpenAiEndpoint.CAPTURED_OLLAMA_RESPONSE).decide(wake())

    assertEquals(MODEL, out.meta["model"])
    assertEquals("331", out.meta["promptTokens"])
    assertEquals("57", out.meta["completionTokens"])
    // A free strategy writing 0.0 into the key the budget cap accumulates would quietly
    // redefine cognitionSpendUsd from "what cognition has spent" to "what the BILLED
    // strategies have spent" — weakening a number another strategy gates on.
    assertFalse("a loopback model has no cost to report", out.meta.containsKey("costUsd"))
  }

  @Test
  fun metaIsSubstrateOwnedAndNotTakenFromTheEndpointsReply() {
    // The envelope's own `model` field is endpoint-controlled. If it reached meta it would
    // reach the journal, where a provider could then name itself whatever it liked in a
    // row the substrate authored (AGENCY-029).
    val out =
      cognitionFor(
          FakeOpenAiEndpoint.reply(
            content = """{"proposals": [], "reasoning": "nothing to do"}""",
            topLevelModel = "not-the-configured-model",
          )
        )
        .decide(wake())

    assertEquals("meta must report the CONFIGURED model", MODEL, out.meta["model"])
    assertEquals(
      "meta carries only keys the substrate chose",
      setOf("model", "promptTokens", "completionTokens"),
      out.meta.keys,
    )
  }

  @Test
  fun proseInsteadOfJsonIsAClassifiedMalformedTurn() {
    val out = cognitionFor(FakeOpenAiEndpoint.reply("I'm not sure what you want.")).decide(wake())

    assertNotNull(out.malformed)
    assertTrue(out.proposals.isEmpty())
    assertTrue(out.malformed!!.contains("was not JSON"))
  }

  @Test
  fun aNearMissProposalIsMalformedRatherThanPartiallyExecuted() {
    val out =
      cognitionFor(
          FakeOpenAiEndpoint.reply(
            """{"proposals": [{"type": "status", "status": "working"},
               {"type": "pod-spawn", "taskRef": "../../etc/passwd"}]}"""
          )
        )
        .decide(wake())

    // The GOOD proposal in the same batch is discarded with the bad one: a model that got
    // one structurally wrong has not shown it meant the other.
    assertNotNull(out.malformed)
    assertTrue(out.proposals.isEmpty())
  }

  @Test
  fun aFencedCodeBlockIsAbsorbedTheWaySmallerModelsNeed() {
    // A live probe saw gemma4:12b wrap its JSON in markdown where qwen3-coder did not.
    val out =
      cognitionFor(
          FakeOpenAiEndpoint.reply(
            "```json\n{\"proposals\": [{\"type\": \"status\", \"status\": \"ok\"}]}\n```"
          )
        )
        .decide(wake())

    assertNull(out.malformed)
    assertEquals(Proposal.ProposeStatus("ok"), out.proposals.single())
  }

  @Test
  fun aDeadEndpointEscalatesAndIsNotRecordedAsModelDegradation() {
    val cognition =
      OpenAiCompatCognition(
        OpenAiCompatHarness(OpenAiCompatProfile.ollama(MODEL, "http://127.0.0.1:1"))
      )
    val out = cognition.decide(wake())

    // The model never answered, so there is no unusable output to classify. Recording this
    // as MALFORMED would put a network fault into the record of how reliable the model is.
    assertNull(out.malformed)
    val escalation = out.proposals.single() as Proposal.ProposeEscalate
    assertTrue(escalation.reason.contains("cognition turn failed"))
  }

  @Test
  fun anEmptyProposalListIsACleanIdle() {
    val out =
      cognitionFor(FakeOpenAiEndpoint.reply("""{"proposals": [], "reasoning": "waiting"}"""))
        .decide(wake())

    assertNull(out.malformed)
    assertTrue(out.proposals.isEmpty())
  }

  @Test
  fun theStrategyIsNamedForItsProfileSoTheJournalSaysWhoDecided() {
    assertEquals("ollama", cognitionFor(FakeOpenAiEndpoint.CAPTURED_OLLAMA_RESPONSE).name)
  }

  @Test
  fun aCostlessTurnJournalsAndFoldsWithoutDisturbingTheSpendCounter() {
    val ep = FakeOpenAiEndpoint(FakeOpenAiEndpoint.reply("""{"proposals": [], "reasoning": "waiting"}"""))
    endpoint = ep
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val daemon =
      LeadDaemon(
        store = store,
        cognition =
          OpenAiCompatCognition(
            OpenAiCompatHarness(OpenAiCompatProfile.ollama(MODEL, ep.baseUrl))
          ),
        podRunner = FakePodRunner(holdCompletions = true),
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(dir, "absent-ticket.txt")),
        workdir = dir,
        effects = EffectReceiver(dir.absolutePath),
        maxCognitionAttempts = OpenAiCompatCognition.MAX_ATTEMPTS_PER_WAKE,
      )

    val folded = daemon.driveUntilQuiescent()

    // The first strategy to omit costUsd, so the round trip through the journal AND the fold
    // is worth pinning rather than reasoning about: leadFold's accruedCost reads the key or
    // defaults to 0.0, and the counter it feeds is what the BILLED strategy gates on.
    val cog = store.readAll().filter { it.kind == LeadKinds.COGNITION_PROPOSED }
    assertTrue("the wake journaled no cognition row", cog.isNotEmpty())
    assertTrue(cog.all { it.origin == ORIGIN_COGNITION })
    assertFalse("this strategy reports no cost", cog.any { it.payloadJson.contains("costUsd") })
    assertTrue("token provenance must survive into the row", cog.any { it.payloadJson.contains("completionTokens") })
    assertEquals(0.0, folded.lead.cognitionSpendUsd, 0.0)
    store.close()
  }

  // ---- selection: the attempt cap must travel with the strategy ----

  @Test
  fun selectingOllamaWiresTheSingleAttemptCap() {
    val choice = CognitionSelection.ollama(MODEL)

    // Not a restatement of the constant: this is the wiring that would silently regress if
    // the selector were changed to take the daemon's billed-strategy default of 2.
    assertEquals(1, choice.maxCognitionAttempts)
    assertEquals("ollama", choice.strategy.name)
  }

  @Test
  fun selectingGrokFailsWithTheReasonRatherThanAsATypo() {
    val e =
      try {
        CognitionSelection.byName("grok", File("."), "grok-4")
        throw AssertionError("grok must not be selectable yet")
      } catch (expected: IllegalStateException) {
        expected
      }
    assertTrue(e.message!!.contains("scoped"))
    assertTrue(e.message!!.contains("activation guard"))
  }

  @Test
  fun selectingOllamaWithoutAModelTagIsRefused() {
    // There is no sensible default model tag: which one is pulled locally is a property of
    // the host, and guessing would fail at request time with a remote 404 instead.
    val e =
      try {
        CognitionSelection.byName("ollama", File("."), null)
        throw AssertionError("ollama must require an explicit model tag")
      } catch (expected: IllegalStateException) {
        expected
      }
    assertTrue(e.message!!.contains("requires an explicit model"))
  }

  companion object {
    private const val MODEL = "qwen3-coder:30b"
  }
}
