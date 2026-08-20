package com.geekinasuit.agency.shared.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Quorum evaluator cells: the built-in 1-of-1 default, multi-group trees (the "2 of 3
 * council AND 1 of 2 ops" shape a bare count cannot express), constructor bounds, and the
 * data codec — round-trip fidelity plus loud refusal of malformed or over-deep data.
 */
class QuorumTest {

  private fun council(vararg ids: String) = QuorumGroup(2, ids.map { SignerLeaf(it) })

  private val multiGroup =
    QuorumGroup(
      2,
      listOf(
        council("council-a", "council-b", "council-c"),
        QuorumGroup(1, listOf(SignerLeaf("ops-a"), SignerLeaf("ops-b"))),
      ),
    )

  @Test
  fun oneOfOneDefaultSatisfiedOnlyByItsPrincipal() {
    val policy = oneOfOne("operator")
    assertTrue(quorumSatisfied(policy, setOf("operator")))
    assertFalse(quorumSatisfied(policy, emptySet()))
    assertFalse(quorumSatisfied(policy, setOf("someone-else")))
  }

  @Test
  fun multiGroupTreeRequiresBothGroups() {
    // Both groups satisfied: 2 council + 1 ops.
    assertTrue(quorumSatisfied(multiGroup, setOf("council-a", "council-c", "ops-b")))
    // Council alone — even unanimously — is one satisfied child of a threshold-2 root.
    assertFalse(quorumSatisfied(multiGroup, setOf("council-a", "council-b", "council-c")))
    // Ops alone likewise.
    assertFalse(quorumSatisfied(multiGroup, setOf("ops-a", "ops-b")))
    // One council approver is below that group's own threshold.
    assertFalse(quorumSatisfied(multiGroup, setOf("council-a", "ops-a")))
  }

  @Test
  fun approversAreASetSoDoubleApprovalCountsOnce() {
    // A set cannot carry duplicates; the cell pins the CONTRACT that evaluation is
    // per-principal, not per-approval-message. (This input alone cannot distinguish
    // per-leaf from per-principal counting — the tree-wide leaf-distinctness bound,
    // pinned by the refusal cell below, is what makes the two identical.)
    assertFalse(quorumSatisfied(council("a", "b", "c"), setOf("a")))
  }

  @Test
  fun repeatedPrincipalAnywhereInTheTreeIsRefused() {
    // One key clearing a threshold-2 root is the quorum-weakening shape the identity
    // bound exists to refuse — same group or across sibling groups, constructed or
    // parsed. Without it, `[shared, shared]` at k=2 (or two subgroups both holding
    // `shared`) is satisfied by a single approver, and "a second required signer" stops
    // meaning a second PERSON.
    assertThrows { QuorumGroup(2, listOf(SignerLeaf("a"), SignerLeaf("a"))) }
    assertThrows {
      QuorumGroup(
        2,
        listOf(
          QuorumGroup(1, listOf(SignerLeaf("shared"), SignerLeaf("x"))),
          QuorumGroup(1, listOf(SignerLeaf("shared"), SignerLeaf("y"))),
        ),
      )
    }
    assertThrows {
      parseQuorum(
        """{"type":"group","threshold":2,"children":[{"type":"signer","principalId":"a"},{"type":"signer","principalId":"a"}]}"""
      )
    }
  }

  @Test
  fun constructorBoundsRefused() {
    assertThrows { QuorumGroup(0, listOf(SignerLeaf("a"))) } // threshold < 1
    assertThrows { QuorumGroup(2, listOf(SignerLeaf("a"))) } // threshold > n
    assertThrows { QuorumGroup(1, emptyList()) } // empty group
    assertThrows { QuorumGroup(1, (1..33).map { SignerLeaf("p$it") }) } // n > 32
    assertThrows { SignerLeaf("") } // blank principal
    QuorumGroup(1, (1..32).map { SignerLeaf("p$it") }) // n == 32 is the admitted edge
  }

  @Test
  fun codecRoundTripsTheTree() {
    val back = quorumFromJson(quorumToJson(multiGroup))
    assertEquals(multiGroup, back)
    val leaf = quorumFromJson(quorumToJson(SignerLeaf("solo")))
    assertEquals(SignerLeaf("solo"), leaf)
  }

  private fun parseQuorum(json: String) =
    quorumFromJson(kotlinx.serialization.json.Json.parseToJsonElement(json).let { it as kotlinx.serialization.json.JsonObject })

  @Test
  fun malformedDataRefusedLoudly() {
    assertThrows { parseQuorum("""{"type":"cabal","principalId":"a"}""") } // unknown type
    assertThrows { parseQuorum("""{"type":"signer"}""") } // missing field
    assertThrows { parseQuorum("""{"type":"signer","principalId":null}""") } // null field: JsonNull is a primitive whose content is "null" — must refuse, not build SignerLeaf("null")
    assertThrows { parseQuorum("""{"type":"group","threshold":1}""") } // missing children
    assertThrows { parseQuorum("""{"type":"group","threshold":1,"children":"kids"}""") } // children not an array
    assertThrows { parseQuorum("""{"type":"group","threshold":1,"children":["leaf"]}""") } // child not an object
    assertThrows { parseQuorum("""{"type":"group","threshold":"many","children":[{"type":"signer","principalId":"a"}]}""") } // non-integer threshold
    assertThrows { parseQuorum("""{"type":"group","threshold":2,"children":[{"type":"signer","principalId":"a"}]}""") } // bounds via constructor
  }

  @Test
  fun oversizedGroupAsDataIsRefusedBeforeItsChildrenParse() {
    val children = (1..33).joinToString(",") { """{"type":"signer","principalId":"p$it"}""" }
    val message =
      try {
        parseQuorum("""{"type":"group","threshold":1,"children":[$children]}""")
        throw AssertionError("expected IllegalArgumentException")
      } catch (expected: IllegalArgumentException) {
        expected.message.orEmpty()
      }
    // The PARSE-side guard fires (its message says so): the count is refused before the
    // 33 children are recursively materialised, not by the constructor afterwards.
    assertTrue("before parsing" in message)
  }

  @Test
  fun depthCapBoundsHostileData() {
    // Nested single-child groups as data: [wraps] groups around a leaf is depth wraps+1.
    fun nested(wraps: Int): kotlinx.serialization.json.JsonObject {
      var json = quorumToJson(SignerLeaf("deep"))
      repeat(wraps) {
        json =
          kotlinx.serialization.json.buildJsonObject {
            put("type", kotlinx.serialization.json.JsonPrimitive("group"))
            put("threshold", kotlinx.serialization.json.JsonPrimitive(1))
            put("children", kotlinx.serialization.json.buildJsonArray { add(json) })
          }
      }
      return json
    }
    // Both edges, matching constructorBoundsRefused's rigour: the leaf exactly AT the cap
    // parses (an off-by-one refusing legal policy fails here) …
    quorumFromJson(nested(MAX_QUORUM_DEPTH - 1))
    // … and one past it is refused.
    assertThrows { quorumFromJson(nested(MAX_QUORUM_DEPTH)) }
  }

  private fun assertThrows(block: () -> Any) {
    try {
      block()
    } catch (expected: IllegalArgumentException) {
      return
    }
    throw AssertionError("expected IllegalArgumentException")
  }
}
