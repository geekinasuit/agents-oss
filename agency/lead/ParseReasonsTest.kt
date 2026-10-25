package com.geekinasuit.agency.lead

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The exact reason [CognitionProtocol.parseOutput] gives each malformed output, and which near-miss
 * decides the reason when an output has more than one. CognitionParsingTest pins that each such
 * output is malformed and that every reason is one the fold holds; this pins which reason, so a
 * change that moves part of the parser elsewhere cannot swap one for another unnoticed.
 */
class ParseReasonsTest {

  private fun reason(text: String): String? =
    CognitionProtocol.parseOutput(text, emptyMap(), ContextPresentation.PRESENTED).malformed

  private fun proposals(vararg p: String) = """{"proposals":[${p.joinToString(",")}]}"""

  @Test
  fun eachMalformedOutputGetsItsOwnReason() {
    val cases =
      listOf(
        "not json at all" to MalformedReasons.NOT_JSON,
        // A close brace before the first open one is not JSON either: no text reaches the
        // parser's catch-all for an exception other than a JSON one.
        "} {" to MalformedReasons.NOT_JSON,
        """{"proposals":{}}""" to MalformedReasons.PROPOSALS_NOT_ARRAY,
        """{"proposals":"x"}""" to MalformedReasons.PROPOSALS_NOT_ARRAY,
        """{"proposals":null}""" to MalformedReasons.PROPOSALS_NOT_ARRAY,
        proposals("1") to MalformedReasons.PROPOSAL_NOT_OBJECT,
        proposals("{}") to MalformedReasons.PROPOSAL_NO_TYPE,
        proposals("""{"type":"delete-everything"}""") to MalformedReasons.UNKNOWN_TYPE,
        // A type that is not a JSON string is read as its text, an unknown type, not as no type.
        proposals("""{"type":5}""") to MalformedReasons.UNKNOWN_TYPE,
        proposals("""{"type":true}""") to MalformedReasons.UNKNOWN_TYPE,
        proposals("""{"type":"pod-spawn","taskRef":"deploy:t1"}""") to MalformedReasons.BAD_TASK_REF,
        proposals("""{"type":"pod-spawn","taskRef":"plan:"}""") to MalformedReasons.BAD_TASK_REF,
        proposals("""{"type":"pod-spawn"}""") to MalformedReasons.missingField("taskRef"),
        proposals("""{"type":"pod-spawn","taskRef":42}""") to MalformedReasons.missingField("taskRef"),
        proposals("""{"type":"gate-open","gateKind":"deploy","payloadDigest":"a"}""") to
          MalformedReasons.UNKNOWN_GATE_KIND,
        proposals("""{"type":"gate-open","payloadDigest":"a"}""") to MalformedReasons.missingField("gateKind"),
        proposals("""{"type":"gate-open","gateKind":"plan-approval"}""") to
          MalformedReasons.missingField("payloadDigest"),
        proposals("""{"type":"status"}""") to MalformedReasons.missingField("status"),
        proposals("""{"type":"escalate","reason":" "}""") to MalformedReasons.missingField("reason"),
        """{"proposals":[],"k":1,"k":2}""" to MalformedReasons.PARSE_FAILURE_JSON,
      )
    for ((input, expected) in cases) assertEquals(input, expected, reason(input))
  }

  @Test
  fun everyRequiredFieldMustBeANonBlankString() {
    // Each proposal with one required field left as a slot; the others well-formed.
    val withField =
      mapOf<String, (String) -> String>(
        "taskRef" to { v -> """{"type":"pod-spawn","taskRef":$v}""" },
        "gateKind" to { v -> """{"type":"gate-open","gateKind":$v,"payloadDigest":"a"}""" },
        "payloadDigest" to { v -> """{"type":"gate-open","gateKind":"plan-approval","payloadDigest":$v}""" },
        "status" to { v -> """{"type":"status","status":$v}""" },
        "reason" to { v -> """{"type":"escalate","reason":$v}""" },
      )
    // A number, an empty string and a blank one are each the field missing, never a value read
    // from it, a bad task ref, or an unknown gate kind.
    for ((field, proposal) in withField) for (value in listOf("5", "\"\"", "\" \"")) {
      val input = proposals(proposal(value))
      assertEquals(input, MalformedReasons.missingField(field), reason(input))
    }
  }

  @Test
  fun tokensAreMatchedVerbatim() {
    // A padded or differently-cased type, task ref or gate kind is not the token it resembles:
    // nothing is trimmed or case-folded before it is compared.
    val cases =
      listOf(
        proposals("""{"type":" "}""") to MalformedReasons.UNKNOWN_TYPE,
        proposals("""{"type":" status ","status":"s"}""") to MalformedReasons.UNKNOWN_TYPE,
        proposals("""{"type":"STATUS","status":"s"}""") to MalformedReasons.UNKNOWN_TYPE,
        proposals("""{"type":"pod-spawn","taskRef":" plan:t1"}""") to MalformedReasons.BAD_TASK_REF,
        proposals("""{"type":"pod-spawn","taskRef":"PLAN:t1"}""") to MalformedReasons.BAD_TASK_REF,
        // The shape must match the whole ref: a trailing newline is not part of a ticket ref.
        proposals("""{"type":"pod-spawn","taskRef":"plan:t1\n"}""") to MalformedReasons.BAD_TASK_REF,
        proposals("""{"type":"gate-open","gateKind":" plan-approval","payloadDigest":"a"}""") to
          MalformedReasons.UNKNOWN_GATE_KIND,
        proposals("""{"type":"gate-open","gateKind":"PLAN-APPROVAL","payloadDigest":"a"}""") to
          MalformedReasons.UNKNOWN_GATE_KIND,
        """{"proposals":42}""" to MalformedReasons.PROPOSALS_NOT_ARRAY,
      )
    for ((input, expected) in cases) assertEquals(input, expected, reason(input))
  }

  @Test
  fun valuesAreReturnedVerbatim() {
    val out =
      CognitionProtocol.parseOutput(
        proposals(
          """{"type":"gate-open","gateKind":"plan-approval","payloadDigest":" d "}""",
          """{"type":"status","status":" s "}""",
          """{"type":"escalate","reason":" r "}""",
        ),
        emptyMap(),
        ContextPresentation.PRESENTED,
      )
    assertEquals(null, out.malformed)
    assertEquals(
      listOf(
        Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, " d "),
        Proposal.ProposeStatus(" s "),
        Proposal.ProposeEscalate(" r "),
      ),
      out.proposals,
    )
  }

  @Test
  fun aWellFormedBatchKeepsItsOrderAcrossTypes() {
    // The daemon executes proposals in list order, so host and workflow types stay interleaved
    // exactly as the output gave them.
    val out =
      CognitionProtocol.parseOutput(
        proposals(
          """{"type":"status","status":"s"}""",
          """{"type":"pod-spawn","taskRef":"plan:t1"}""",
          """{"type":"escalate","reason":"r"}""",
          """{"type":"gate-open","gateKind":"plan-approval","payloadDigest":"d"}""",
        ),
        emptyMap(),
        ContextPresentation.PRESENTED,
      )
    assertEquals(
      listOf(
        Proposal.ProposeStatus("s"),
        Proposal.ProposePodSpawn("plan:t1"),
        Proposal.ProposeEscalate("r"),
        Proposal.ProposeGateOpen(GateKinds.PLAN_APPROVAL, "d"),
      ),
      out.proposals,
    )
  }

  @Test
  fun aGateKindIsJudgedBeforeItsDigestIsRequired() {
    // An unknown kind is reported even when the digest is missing too.
    assertEquals(
      MalformedReasons.UNKNOWN_GATE_KIND,
      reason(proposals("""{"type":"gate-open","gateKind":"deploy"}""")),
    )
    // With neither field, the kind is the one named.
    assertEquals(MalformedReasons.missingField("gateKind"), reason(proposals("""{"type":"gate-open"}""")))
  }

  @Test
  fun theFirstMalformedProposalDecidesTheReason() {
    val badTaskRef = """{"type":"pod-spawn","taskRef":"deploy:t1"}"""
    val badKind = """{"type":"gate-open","gateKind":"deploy","payloadDigest":"a"}"""
    val unknownType = """{"type":"delete-everything"}"""
    val good = """{"type":"status","status":"ok"}"""
    assertEquals(MalformedReasons.BAD_TASK_REF, reason(proposals(good, badTaskRef, badKind)))
    assertEquals(MalformedReasons.UNKNOWN_GATE_KIND, reason(proposals(badKind, badTaskRef)))
    assertEquals(MalformedReasons.UNKNOWN_TYPE, reason(proposals(unknownType, badKind)))
    assertEquals(MalformedReasons.missingField("status"), reason(proposals("""{"type":"status"}""", unknownType)))
    // A workflow type's near-miss ahead of a host type's: the proposals are read in order, not by
    // kind, so the first one still decides.
    assertEquals(MalformedReasons.BAD_TASK_REF, reason(proposals(badTaskRef, unknownType)))
    assertEquals(MalformedReasons.UNKNOWN_GATE_KIND, reason(proposals(badKind, """{"type":"escalate"}""")))
    // A later element that is not an object, or has no type, does not decide either: the shape of
    // each element is judged when it is reached, not in a pass over all of them first.
    assertEquals(MalformedReasons.BAD_TASK_REF, reason(proposals(badTaskRef, "1")))
    assertEquals(MalformedReasons.BAD_TASK_REF, reason(proposals(badTaskRef, "{}")))
  }

  @Test
  fun everyTaskRefTheShapeAcceptsParses() {
    // The accepting side of the plan:/execute: shape: each charset the ref may use.
    for (ref in listOf("plan:t1", "execute:T9", "plan:a_b.c", "execute:t-1", "plan:a.b-c_d9")) {
      val out = CognitionProtocol.parseOutput(proposals("""{"type":"pod-spawn","taskRef":"$ref"}"""), emptyMap(), ContextPresentation.PRESENTED)
      assertEquals(ref, null, out.malformed)
      assertEquals(ref, listOf(Proposal.ProposePodSpawn(ref)), out.proposals)
    }
  }

  @Test
  fun aWellFormedOutputKeepsItsProposalsReasoningAndMeta() {
    val meta = mapOf("model" to "m")
    val out =
      CognitionProtocol.parseOutput(
        proposals(
          """{"type":"pod-spawn","taskRef":"execute:t1"}""",
          """{"type":"gate-open","gateKind":"commit-approval","payloadDigest":"d"}""",
          """{"type":"status","status":"s"}""",
          """{"type":"escalate","reason":"r"}""",
        )
          .dropLast(1) + ""","reasoning":"why"}""",
        meta,
        ContextPresentation.PRESENTED,
      )
    assertEquals(null, out.malformed)
    assertEquals(
      listOf(
        Proposal.ProposePodSpawn("execute:t1"),
        Proposal.ProposeGateOpen(GateKinds.COMMIT_APPROVAL, "d"),
        Proposal.ProposeStatus("s"),
        Proposal.ProposeEscalate("r"),
      ),
      out.proposals,
    )
    assertEquals("why", out.reasoning)
    assertEquals(meta, out.meta)
    assertEquals(ContextPresentation.PRESENTED, out.presentation)
  }
}
