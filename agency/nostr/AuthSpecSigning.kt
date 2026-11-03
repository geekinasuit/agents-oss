package com.geekinasuit.agency.nostr

import com.geekinasuit.agency.shared.auth.AuthorizationSpec
import com.geekinasuit.agency.shared.auth.Principal
import com.geekinasuit.agency.shared.auth.QuorumGroup
import com.geekinasuit.agency.shared.auth.QuorumNode
import com.geekinasuit.agency.shared.auth.SignerLeaf
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.SpecLoadResult
import com.geekinasuit.agency.shared.auth.authSpecPreimage
import com.geekinasuit.agency.shared.auth.loadAuthorizationSpec
import com.geekinasuit.agency.shared.auth.quorumFromJson
import com.geekinasuit.agency.shared.json.jsonMayNestDeeperThan
import java.security.MessageDigest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Signing an authorization spec with a bip340 root key (A4-8): the allow-list and quorum an operator
 * writes, turned into the root-signed [AuthorizationSpec] a lead loads with
 * [loadAuthorizationSpec] against the pinned root.
 *
 * The operator writes the spec as plain JSON:
 * ```
 * {"principals": [{"principalId": "operator", "role": "approver",
 *                  "keys": [{"schemeId": "bip340", "publicKey": "<64 lowercase hex>"}]}],
 *  "quorum": {"type": "signer", "principalId": "operator"}}
 * ```
 * where `quorum` is a quorum tree as `quorumToJson` writes one. [sign] signs the canonical
 * [authSpecPreimage] of it, so the order the operator wrote principals and keys in does not matter,
 * and then loads the result itself with [Bip340ApprovalVerifier], so a spec that would not load (a
 * misspelled or off-curve key, a duplicate principal) is refused here, before it is ever deployed.
 * It also refuses two specs that would load but could never be met: a quorum naming a principal the
 * spec does not list, and a principal with no key under [ROOT_SCHEME], the one scheme the lead's
 * verifier answers for (so a scheme id spelled `BIP340` is refused here too).
 */
object AuthSpecSigning {
  /** The scheme a root key signs under. */
  const val ROOT_SCHEME = "bip340"

  // principals > principal > keys > key: the deepest legitimate structure outside the quorum tree,
  // which quorumFromJson bounds itself once the text is parsed. 40 covers a quorum tree at its own
  // depth cap with room.
  private const val MAX_SPEC_JSON_DEPTH = 40

  /** The principals and quorum [text] describes, or an [IllegalArgumentException] naming what is
   * wrong. Its nesting is bounded before it is parsed. */
  fun parse(text: String): Pair<List<Principal>, QuorumNode> {
    require(!jsonMayNestDeeperThan(text, MAX_SPEC_JSON_DEPTH)) { "the spec nests deeper than any spec can" }
    val root =
      try {
        Json.parseToJsonElement(text) as? JsonObject
      } catch (x: Exception) {
        throw IllegalArgumentException("the spec is not JSON: ${x.javaClass.simpleName}")
      } ?: throw IllegalArgumentException("the spec is not a JSON object")
    val principals =
      (root["principals"] as? JsonArray ?: throw IllegalArgumentException("the spec has no principals array")).map {
        principalOf(it as? JsonObject ?: throw IllegalArgumentException("a principal is not an object"))
      }
    val quorum = quorumFromJson(root["quorum"] as? JsonObject ?: throw IllegalArgumentException("the spec has no quorum object"))
    return principals to quorum
  }

  /**
   * Sign [principals] and [quorum] with the root key [rootKey] (raw bytes the caller holds and
   * zeroes), and check that the result loads under that root's public key. Throws
   * [IllegalArgumentException] with the loader's reason when it would not. [auxRandHex] is the
   * signature's aux randomness, 32 bytes of hex: fresh in production, fixed in a test.
   */
  fun sign(principals: List<Principal>, quorum: QuorumNode, rootKey: ByteArray, auxRandHex: String): AuthorizationSpec {
    val listed = principals.map { it.principalId }.toSet()
    val unlisted = leaves(quorum).filter { it !in listed }
    require(unlisted.isEmpty()) { "the quorum names principals the spec does not list: ${unlisted.joinToString()}" }
    // The lead verifies with the bip340 verifier alone, so a principal with no bip340 key could
    // never approve.
    val keyless = principals.filter { p -> p.keys.none { it.schemeId == ROOT_SCHEME } }.map { it.principalId }
    require(keyless.isEmpty()) { "principals with no $ROOT_SCHEME key could never approve: ${keyless.joinToString()}" }
    val preimage = authSpecPreimage(principals, quorum)
    val digest = MessageDigest.getInstance("SHA-256").digest(preimage.toByteArray(Charsets.UTF_8))
    val spec = AuthorizationSpec(Bip340.signWithKeyBytes(Hex.encode(digest), rootKey, auxRandHex), preimage)
    val root = SchemeKey(ROOT_SCHEME, Bip340.xonlyPubkeyFromKeyBytes(rootKey))
    when (val loaded = loadAuthorizationSpec(spec, root, Bip340ApprovalVerifier)) {
      is SpecLoadResult.Loaded -> return spec
      is SpecLoadResult.Refused -> throw IllegalArgumentException("the signed spec would not load: ${loaded.reason}")
    }
  }

  /** [spec] as the JSON file a lead reads: `{"rootSignature": …, "specPreimage": …}`. */
  fun toJson(spec: AuthorizationSpec): String =
    buildJsonObject {
        put("rootSignature", spec.rootSignature)
        put("specPreimage", spec.specPreimage)
      }
      .toString()

  /** The [AuthorizationSpec] a file [toJson] wrote holds, or null when [text] is not one. Total. The
   * spec's own preimage is parsed only by [loadAuthorizationSpec], after its signature verifies. */
  fun fromJson(text: String): AuthorizationSpec? {
    if (jsonMayNestDeeperThan(text, 1)) return null
    val obj =
      try {
        Json.parseToJsonElement(text) as? JsonObject
      } catch (_: Exception) {
        null
      } ?: return null
    val signature = (obj["rootSignature"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
    val preimage = (obj["specPreimage"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
    return AuthorizationSpec(signature, preimage)
  }

  private fun leaves(node: QuorumNode): List<String> =
    when (node) {
      is SignerLeaf -> listOf(node.principalId)
      is QuorumGroup -> node.children.flatMap { leaves(it) }
    }

  private fun principalOf(obj: JsonObject): Principal {
    fun str(o: JsonObject, k: String, what: String) =
      (o[k] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw IllegalArgumentException("$what has no string '$k'")
    val id = str(obj, "principalId", "a principal")
    val keys =
      (obj["keys"] as? JsonArray ?: throw IllegalArgumentException("principal '$id' has no keys array")).map {
        val k = it as? JsonObject ?: throw IllegalArgumentException("a key of principal '$id' is not an object")
        SchemeKey(str(k, "schemeId", "a key of principal '$id'"), str(k, "publicKey", "a key of principal '$id'"))
      }
    return Principal(id, str(obj, "role", "principal '$id'"), keys)
  }
}
