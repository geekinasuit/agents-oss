package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Deterministic, no-model coverage of the model-output
 * boundary: [CognitionProtocol.parseOutput] is where untrusted model text becomes typed
 * proposals, and [CognitionProtocol.renderContext] is what the model is shown. The live
 * smoke exercises them once against a real model; these cells pin the contract — including
 * that garbage becomes a classified MALFORMED outcome, never a silent no-op and never
 * a proposal the substrate would then act on.
 *
 * Covering the protocol rather than one strategy is the point: every model-backed strategy
 * shares it, so a provider added later inherits this contract instead of a second reading
 * of it.
 */
class CognitionParsingTest {

  private val meta = mapOf("sessionId" to "s1", "costUsd" to "0.01")

  private fun parse(text: String) = CognitionProtocol.parseOutput(text, meta)

  @Test
  fun wellFormedProposalsParseToTypedValues() {
    val out =
      parse(
        """{"proposals":[
             {"type":"pod-spawn","taskRef":"plan:t1"},
             {"type":"gate-open","gateKind":"plan-approval","payloadDigest":"abc123"},
             {"type":"status","status":"working"},
             {"type":"escalate","reason":"stuck"}
           ],"reasoning":"a full sweep"}"""
      )
    assertEquals(4, out.proposals.size)
    assertTrue(out.proposals[0] is Proposal.ProposePodSpawn)
    assertEquals("plan:t1", (out.proposals[0] as Proposal.ProposePodSpawn).taskRef)
    val gate = out.proposals[1] as Proposal.ProposeGateOpen
    assertEquals(GateKinds.PLAN_APPROVAL, gate.gateKind)
    assertEquals("abc123", gate.payloadDigest)
    assertEquals("a full sweep", out.reasoning)
    assertEquals(meta, out.meta)
  }

  @Test
  fun emptyProposalsArrayIsIdleNotEscalation() {
    val out = parse("""{"proposals":[],"reasoning":"nothing to do"}""")
    assertTrue(out.proposals.isEmpty())
  }

  @Test
  fun prosePaddingAroundTheJsonIsTolerated() {
    val out =
      parse("Sure! Here is my decision:\n{\"proposals\":[{\"type\":\"status\",\"status\":\"ok\"}]}\nHope that helps.")
    assertEquals(1, out.proposals.size)
    assertTrue(out.proposals.single() is Proposal.ProposeStatus)
  }

  @Test
  fun nonJsonOutputIsMalformedNotAnEscalationProposal() {
    val out = parse("I refuse to answer in JSON.")
    assertTrue(out.malformed!!.contains("not JSON"))
    // The distinction this outcome exists for: a malformed turn must NOT look like a model that
    // deliberately asked for a human, or a degrading model reads as a deliberating one.
    assertTrue(out.proposals.isEmpty())
    assertEquals(meta, out.meta) // provenance still carried — the turn was still billed
  }

  @Test
  fun truncatedJsonIsMalformed() {
    val out = parse("""{"proposals":[{"type":"pod-spawn"}""") // truncated, missing taskRef + braces
    assertTrue(out.malformed != null)
    assertTrue(out.proposals.isEmpty())
  }

  @Test
  fun unknownProposalTypeIsMalformedNotASilentDrop() {
    val out = parse("""{"proposals":[{"type":"delete-everything"}],"reasoning":"nope"}""")
    assertTrue(out.malformed!!.contains("unknown proposal type"))
    assertTrue(out.proposals.isEmpty())
  }

  @Test
  fun missingRequiredFieldIsMalformed() {
    val out = parse("""{"proposals":[{"type":"status"}]}""") // no status text
    assertTrue(out.malformed!!.contains("status"))
    assertTrue(out.proposals.isEmpty())
  }

  @Test
  fun blankRequiredFieldIsMalformed() {
    // Present-but-empty is the near-miss a small model actually produces; a bare
    // key-presence check would let it through as a well-formed no-op proposal.
    val out = parse("""{"proposals":[{"type":"escalate","reason":"   "}]}""")
    assertTrue(out.malformed != null)
  }

  @Test
  fun hallucinatedGateKindIsMalformed() {
    val out =
      parse("""{"proposals":[{"type":"gate-open","gateKind":"deploy-to-prod","payloadDigest":"a"}]}""")
    assertTrue(out.malformed!!.contains("unknown gate kind"))
    assertTrue(out.proposals.isEmpty())
  }

  @Test
  fun taskRefOutsideThePlanExecuteShapeIsMalformed() {
    for (bad in listOf("deploy:t1", "plan:../../etc/passwd", "plan:", "t1")) {
      val out = parse("""{"proposals":[{"type":"pod-spawn","taskRef":"$bad"}]}""")
      assertTrue("expected malformed for taskRef '$bad'", out.malformed != null)
      assertTrue(out.proposals.isEmpty())
    }
  }

  @Test
  fun oneNearMissInvalidatesTheWholeBatch() {
    // A model that got one proposal structurally wrong has not demonstrated it meant the
    // others: executing the good half of a bad batch is the silent partial fold the
    // malformed contract forbids.
    val out =
      parse(
        """{"proposals":[
             {"type":"status","status":"working"},
             {"type":"gate-open","gateKind":"deploy-to-prod","payloadDigest":"a"}
           ]}"""
      )
    assertTrue(out.malformed != null)
    assertTrue(out.proposals.isEmpty())
  }

  @Test
  fun proposalsPresentButNotAnArrayIsMalformed() {
    // The container-level near-miss. optJSONArray answers null for a wrong TYPE exactly as
    // it does for an absent key, so without an explicit check each of these parses as a
    // clean idle decision — a degrading model reading as a deliberating one.
    for (bad in listOf("""{"a":1}""", "\"just a string\"", "null", "42")) {
      val out = parse("""{"proposals":$bad,"reasoning":"r"}""")
      assertTrue("expected malformed for proposals=$bad", out.malformed != null)
      assertTrue(out.proposals.isEmpty())
    }
  }

  @Test
  fun omittingProposalsEntirelyIsStillIdleNotMalformed() {
    // The case deliberately NOT swept up by the check above: a turn that proposed nothing
    // has decided something, and saying so by omission is not a shape error.
    val out = parse("""{"reasoning":"nothing worth doing this wake"}""")
    assertEquals(null, out.malformed)
    assertTrue(out.proposals.isEmpty())
  }

  @Test
  fun aRequiredFieldOfTheWrongJsonTypeIsMalformed() {
    // Stringifying these would turn a wrong-shaped field into a plausible-looking value:
    // a status of "42", or an escalation reason that is a serialized JSON object.
    assertTrue(parse("""{"proposals":[{"type":"status","status":42}]}""").malformed != null)
    assertTrue(parse("""{"proposals":[{"type":"escalate","reason":{"a":1}}]}""").malformed != null)
    assertTrue(parse("""{"proposals":[{"type":"status","status":["x"]}]}""").malformed != null)
  }

  @Test
  fun wellFormedOutputIsNotMarkedMalformed() {
    assertEquals(null, parse("""{"proposals":[],"reasoning":"nothing to do"}""").malformed)
    assertEquals(
      null,
      parse("""{"proposals":[{"type":"escalate","reason":"stuck"}]}""").malformed,
    )
  }

  @Test
  fun podSpawnProposalCannotSmuggleDescriptorFields() {
    // Substrate-constructed provenance, parse side: the descriptor
    // (provider/baseUrl/authMode/model/transport) is lead-owned config; cognition proposes
    // a TASK. Smuggled descriptor fields on a pod-spawn proposal must neither fail the
    // parse nor reach the typed value — [Proposal.ProposePodSpawn] has nowhere to put them
    // (compile-time), and this cell is the tripwire a future field addition must confront.
    // GuardsTest pins the runtime half (the spawned spec is exactly the lead's).
    val out =
      parse(
        """{"proposals":[{"type":"pod-spawn","taskRef":"plan:t1",
             "provider":"grok","baseUrl":"http://attacker.example","authMode":"none",
             "model":"other","transport":"acp","pinnedVersion":"0.0.1"}]}"""
      )
    // FULL data-class equality: if ProposePodSpawn ever grows a field that
    // parseOutput maps, a smuggled value here makes this inequality fire — a cast plus a
    // taskRef check alone could not see it.
    assertEquals(Proposal.ProposePodSpawn("plan:t1"), out.proposals.single())
  }

  @Test
  fun renderContextShowsTheDecisionSurfaceIncludingDigestsAndMail() {
    val lead =
      LeadState(
        currentTicket = "t1",
        phase = TicketPhase.PLAN_RECORDED,
        planArtifactSha = "sha-plan",
      )
    val wc =
      WakeContext(
        reason = WakeReason.MailArrived("please review"),
        lead = lead,
        shared = JournalState(),
        undeliveredMail = listOf(1L to "please review"),
      )
    val rendered = CognitionProtocol.renderContext(wc)
    assertTrue(rendered.contains("ticket: t1"))
    assertTrue(rendered.contains("planArtifactSha: sha-plan"))
    assertTrue(rendered.contains("please review"))
    assertTrue(rendered.contains("MailArrived"))
  }
}
