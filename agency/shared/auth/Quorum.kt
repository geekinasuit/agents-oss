package com.geekinasuit.agency.shared.auth

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Quorum predicate: a tree of signer groups, each with its own k-of-n threshold, evaluated
 * bottom-up (the MCMS-style shape). The predicate is DATA — policy changes by supplying a
 * different tree, never by touching gate logic. The substrate ships one built-in policy,
 * [oneOfOne]; populating anything richer is later policy work (AGENCY-013) that this
 * evaluator exists to grow into.
 *
 * Expressiveness: "2 of the 3 council keys AND 1 of the 2 ops keys" is
 * `QuorumGroup(2, [council leaves…])` and `QuorumGroup(1, [ops leaves…])` under a root
 * `QuorumGroup(2, [both groups])` — a bare count cannot say that.
 *
 * These types are substrate-neutral on purpose: no transport, event, or key-encoding
 * concept appears here, so the predicate outlives whatever substrate carries approvals.
 */
sealed interface QuorumNode

/** A leaf: satisfied when [principalId] is among the approvers. */
data class SignerLeaf(val principalId: String) : QuorumNode {
  init {
    require(principalId.isNotBlank()) { "a signer leaf requires a non-blank principalId" }
  }
}

/**
 * A group: satisfied when at least [threshold] of its [children] are satisfied.
 * Bounds are the MCMS ones — 1 ≤ threshold ≤ children.size ≤ [MAX_GROUP_SIZE] — so a
 * group can neither be vacuously satisfiable (threshold 0) nor unsatisfiable by
 * construction (threshold > n).
 *
 * One IDENTITY bound joins the arity bounds: a principal appears in at most one leaf of
 * the whole subtree. Evaluation counts satisfied CHILDREN, so a repeated principal would
 * let one approver satisfy several children at once — a threshold-2 group over
 * `[shared, shared]` (or over two subgroups both containing `shared`) would be cleared by
 * one key. With leaves distinct, sibling subtrees have disjoint principal support, so k
 * satisfied children require k distinct approvers: leaf distinctness is what makes k-of-n
 * mean k PRINCIPALS, which is the property the key-custody argument rests on (a second
 * required signer makes one lost key insufficient — given the allow-list's matching
 * guarantee that distinct principals hold byte-distinct keys; [AllowList] refuses
 * cross-principal byte-sharing for exactly this reason, since two principals holding the
 * same key bytes are one custodian however many schemes tag them).
 *
 * Not a data class: [children] is SNAPSHOTTED at construction (as [AllowList] snapshots
 * its inputs), because every guarantee above is about this list — an aliased caller-held
 * mutable list could otherwise carry a constructor-rejected tree into [quorumSatisfied],
 * whose contract is that it evaluates trees the constructors admitted.
 */
class QuorumGroup(val threshold: Int, children: List<QuorumNode>) : QuorumNode {
  val children: List<QuorumNode> = children.toList()

  init {
    require(this.children.isNotEmpty()) { "a quorum group requires at least one child" }
    require(this.children.size <= MAX_GROUP_SIZE) {
      "a quorum group holds at most $MAX_GROUP_SIZE children (got ${this.children.size})"
    }
    require(threshold in 1..this.children.size) {
      "threshold $threshold is outside 1..${this.children.size}"
    }
    val repeated =
      this.children
        .flatMap { leafIds(it) }
        .groupingBy { it }
        .eachCount()
        .filterValues { it > 1 }
        .keys
        .firstOrNull()
    if (repeated != null) {
      throw IllegalArgumentException(
        "principal '$repeated' appears in more than one leaf — thresholds count satisfied " +
          "children, so a repeated principal would satisfy several children with one approval"
      )
    }
  }

  override fun equals(other: Any?): Boolean =
    other is QuorumGroup && other.threshold == threshold && other.children == children

  override fun hashCode(): Int = 31 * threshold + children.hashCode()

  override fun toString(): String = "QuorumGroup(threshold=$threshold, children=$children)"
}

private fun leafIds(node: QuorumNode): List<String> =
  when (node) {
    is SignerLeaf -> listOf(node.principalId)
    is QuorumGroup -> node.children.flatMap { leafIds(it) }
  }

/** MCMS group bound: 1 ≤ k ≤ n ≤ 32. */
const val MAX_GROUP_SIZE = 32

/**
 * Depth cap enforced on the DATA path ([quorumFromJson]): the predicate arrives as data,
 * and recursion over hostile data must be bounded before it is walked. Programmatic
 * construction is substrate code and is not depth-checked.
 */
const val MAX_QUORUM_DEPTH = 16

/** The built-in default policy: a single named principal releases alone. */
fun oneOfOne(principalId: String): QuorumGroup = QuorumGroup(1, listOf(SignerLeaf(principalId)))

/**
 * Bottom-up evaluation. [approvers] is a SET of principal ids, so one principal approving
 * twice counts once. Groups count satisfied CHILDREN; it is [QuorumGroup]'s tree-wide
 * leaf-distinctness bound that makes that identical to counting distinct principals —
 * this evaluator assumes trees the constructors admitted.
 */
fun quorumSatisfied(node: QuorumNode, approvers: Set<String>): Boolean =
  when (node) {
    is SignerLeaf -> node.principalId in approvers
    is QuorumGroup -> node.children.count { quorumSatisfied(it, approvers) } >= node.threshold
  }

/** Serializes a predicate tree to the journal-payload JSON shape. */
fun quorumToJson(node: QuorumNode): JsonObject =
  when (node) {
    is SignerLeaf ->
      buildJsonObject {
        put("type", "signer")
        put("principalId", node.principalId)
      }
    is QuorumGroup ->
      buildJsonObject {
        put("type", "group")
        put("threshold", node.threshold)
        put("children", buildJsonArray { node.children.forEach { add(quorumToJson(it)) } })
      }
  }

/**
 * Parses a predicate tree from data, refusing anything malformed loudly: unknown node
 * type, missing or null field, non-array children, non-object child, out-of-bounds
 * threshold or group size, a principal repeated across leaves (via the constructors), and
 * depth beyond [MAX_QUORUM_DEPTH]. The group-size bound is checked BEFORE the children
 * parse, so an oversized hostile array is refused for its count rather than walked first.
 * (The depth cap bounds THIS walk; the text→JsonObject parse upstream has no depth
 * refusal of its own — kotlinx 1.8.1 heap-walks deep input rather than overflowing — so a
 * caller turning hostile TEXT into the [JsonObject] handed here needs its own input-size
 * bound at that boundary.) A predicate that does not parse is a policy that does not
 * exist — never a defaulted one.
 */
fun quorumFromJson(json: JsonObject): QuorumNode = parseNode(json, depth = 1)

private fun parseNode(json: JsonObject, depth: Int): QuorumNode {
  require(depth <= MAX_QUORUM_DEPTH) { "quorum tree exceeds max depth $MAX_QUORUM_DEPTH" }
  return when (val type = json.req("type", "quorum node")) {
    "signer" -> SignerLeaf(json.req("principalId", "quorum node"))
    "group" -> {
      val threshold = json.reqInt("threshold", "quorum group")
      val childrenField =
        json["children"] ?: throw IllegalArgumentException("quorum group is missing 'children'")
      val children =
        childrenField as? JsonArray
          ?: throw IllegalArgumentException("quorum group 'children' is not an array")
      require(children.size <= MAX_GROUP_SIZE) {
        "a quorum group holds at most $MAX_GROUP_SIZE children (got ${children.size}) — refused before parsing them"
      }
      QuorumGroup(
        threshold,
        children.map {
          parseNode(
            it as? JsonObject
              ?: throw IllegalArgumentException("quorum group child is not an object"),
            depth + 1,
          )
        },
      )
    }
    else -> throw IllegalArgumentException("unknown quorum node type '$type'")
  }
}

