package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalState
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The contract between [ComposedCognitionProtocol] and a [WorkflowProtocol]. The parser suites
 * read only [ComposedCognitionProtocol.parseOutput]'s result, which is the same whether a
 * workflow returns a near-miss or throws it, and they run one workflow, which claims no host type
 * and is the only one they could see the host speak through. These cells read the boundary itself.
 */
class WorkflowProtocolTest {

  @Test
  fun theTicketWorkflowReturnsAMissingFieldInsteadOfThrowingIt() {
    val cases =
      listOf(
        Triple("pod-spawn", "{}", "taskRef"),
        Triple("gate-open", "{}", "gateKind"),
        Triple("gate-open", """{"gateKind":"plan-approval"}""", "payloadDigest"),
      )
    for ((type, body, field) in cases) {
      assertEquals(
        "$type $body",
        ProposalParse.Malformed(MalformedReasons.missingField(field)),
        TicketWorkflowProtocol.parseProposal(type, JSONObject(body)),
      )
    }
  }

  @Test
  fun aWorkflowClaimingAHostTypeIsRefused() {
    for (type in listOf("", "status", "escalate")) {
      assertThrows(type, IllegalArgumentException::class.java) { ComposedCognitionProtocol(workflowOwning(type)) }
    }
  }

  @Test
  fun theTicketWorkflowComposes() {
    ComposedCognitionProtocol(TicketWorkflowProtocol)
  }

  @Test
  fun theHostSpeaksThroughTheWorkflowItIsGiven() {
    val stub =
      object : WorkflowProtocol<LeadState> {
        override val proposalShapes = listOf("""{"type": "stub-note"}""")
        override val rules = "Stub rules."
        override val proposalTypes = setOf("stub-note")

        override fun renderLines(lead: LeadState) = listOf("stub: ${lead.currentTicket}")

        override fun gateReadsApproved(lead: LeadState, gate: OpenGate) = true

        override fun parseProposal(type: String, p: JSONObject): ProposalParse =
          ProposalParse.Ok(Proposal.ProposeStatus("from the stub"))
      }
    val protocol = ComposedCognitionProtocol(stub)

    assertTrue(protocol.systemPrompt, protocol.systemPrompt.contains("""   {"type": "stub-note"}"""))
    assertTrue(protocol.systemPrompt, protocol.systemPrompt.endsWith("Stub rules."))
    assertFalse(protocol.systemPrompt, protocol.systemPrompt.contains("pod-spawn"))

    fun parse(text: String) = protocol.parseOutput(text, emptyMap(), ContextPresentation.PRESENTED)
    assertEquals(listOf(Proposal.ProposeStatus("from the stub")), parse("""{"proposals":[{"type":"stub-note"}]}""").proposals)
    // A ticket workflow type is unknown to a protocol composed without it.
    assertEquals(
      MalformedReasons.UNKNOWN_TYPE,
      parse("""{"proposals":[{"type":"pod-spawn","taskRef":"plan:t1"}]}""").malformed,
    )

    val gate = OpenGate(gateId = "g1", gateKind = "stub-kind", payloadDigest = "d", openedSeq = 1)
    val rendered =
      protocol.renderContext(
        AgentWakeContext(
          WakeReason.Adopted,
          LeadState(currentTicket = "t9", openGates = mapOf("g1" to gate)),
          JournalState(),
          emptyList(),
        )
      )
    assertTrue(rendered, rendered.contains("stub: t9"))
    assertTrue(rendered, rendered.contains("g1(digest=d, approved=true)"))
    assertFalse(rendered, rendered.contains("planArtifactSha"))
  }

  private fun workflowOwning(type: String) =
    object : WorkflowProtocol<LeadState> {
      override val proposalShapes = emptyList<String>()
      override val rules = ""
      override val proposalTypes = setOf(type)

      override fun renderLines(lead: LeadState) = emptyList<String>()

      override fun gateReadsApproved(lead: LeadState, gate: OpenGate) = false

      override fun parseProposal(type: String, p: JSONObject): ProposalParse = ProposalParse.Malformed("unused")
    }
}
