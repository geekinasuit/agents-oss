package com.geekinasuit.agency.shared.auth

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray

/**
 * Root-signed loading of the authorization spec (A4-8): the allow-list and quorum a gate
 * verifies approvals against are not trusted because they sit in a config file — they are
 * trusted because a PINNED root key signed them. [loadAuthorizationSpec] verifies the spec's
 * signature against a root key the CALLER supplies (the deployment pins it somewhere the agent
 * cannot rewrite) and only then parses the allow-list and quorum out of the signed bytes.
 *
 * The hole this closes: step 2b re-verifies each APPROVAL, but a host-write attacker (or a
 * prompt-hijacked mind) can append its own key to a host-resident allow-list, self-sign an
 * approval, and pass every mechanical check 2b makes — the added ENTRY looks authentic because
 * nothing proved the allow-list itself is. Making the authorizing set a root-signed artifact
 * moves the trust root off the host: an attacker who cannot forge the root signature cannot add
 * a principal, however freely it writes the file.
 *
 * The load-bearing NEGATIVE (A4-8): no code path lets a spec nominate the root it is verified
 * against. [AuthorizationSpec] carries the signed bytes and a signature — and no field for a
 * key or a scheme. The verification key comes ONLY from [loadAuthorizationSpec]'s [SchemeKey]
 * pin parameter, never from anything inside the spec. A spec that plants a key internally (as a
 * principal) and self-signs — the attack — verifies against the pin, not the planted key, so it
 * is refused unless the pin IS that key, which the deployment decides and the spec cannot. The
 * pin's PROVENANCE (that it lives somewhere the agent cannot write) is a deployment constraint
 * enforced at step 5, not code-enforceable in this substrate-neutral module; what this module
 * enforces is that the pin is EXTERNAL to the spec, which is the part code can prove — and the
 * paired discriminator in the tests is what proves it.
 *
 * Substrate-neutral like the rest of this package: the root signature reuses [ApprovalVerifier]
 * — the same "key K signed bytes B under scheme S" port the approval path uses, since the
 * trust-role (root vs approver) lives in WHO the pinned key is, not in a second primitive — so
 * no crypto dependency enters here and the real signature adapter is a later step's business.
 */
data class AuthorizationSpec(val rootSignature: String, val specPreimage: String)

/**
 * The outcome of a load: [Loaded] with the authenticated allow-list + quorum, or [Refused] with
 * a human-readable reason. A refusal is VISIBLE and auditable, never a silently permissive
 * default — a spec that does not verify or does not parse yields NO authorizer at all, not an
 * empty or default-open one.
 */
sealed interface SpecLoadResult {
  data class Loaded(val allowList: AllowList, val quorum: QuorumNode) : SpecLoadResult

  data class Refused(val reason: String) : SpecLoadResult
}

/** The canonical-form encoder: default config, so no pretty-printing and no incidental
 * whitespace — the same allow-list must produce byte-identical preimages wherever it is
 * serialized (file-private, as in [committedPreimage]'s file). */
private val CANONICAL = Json

/**
 * The canonical serialization the root signs: a positional JSON array `[principals, quorum]`,
 * where `principals` is an array of `[principalId, role, [[schemeId, publicKey], …]]`. It is
 * CANONICALIZED so the same allow-list yields the same bytes regardless of how a caller
 * assembled the lists: principals are sorted by [Principal.principalId], and each principal's
 * keys by (schemeId, publicKey). `quorum` reuses [quorumToJson] — its object form is already
 * deterministic (fixed field order; children stay in TREE order, which is meaningful and so is
 * not sorted). A positional array at the top (rather than an object) keeps the bytes canonical
 * without leaning on a field-ordering convention, the same reason [committedPreimage] is one.
 *
 * Sorting by principalId is a total order on any spec that can LOAD: [AllowList] refuses
 * duplicate principal ids, so a loadable allow-list has distinct ids. A duplicate-id list would
 * sort ambiguously here, but [parseAuthSpec] refuses it anyway, so its preimage canonicality is
 * moot.
 *
 * Byte-stability is load-bearing because step 5's signer signs these exact bytes OFFLINE: if
 * the encoder stopped canonicalizing, a spec assembled in a different order would sign to
 * different bytes and fail to load. A test pins the order-independence so the sort cannot
 * silently decay into decoration.
 */
fun authSpecPreimage(principals: List<Principal>, quorum: QuorumNode): String {
  val principalsArray =
    buildJsonArray {
      principals
        .sortedBy { it.principalId }
        .forEach { p ->
          add(
            buildJsonArray {
              add(JsonPrimitive(p.principalId))
              add(JsonPrimitive(p.role))
              add(
                buildJsonArray {
                  p.keys
                    .sortedWith(compareBy({ it.schemeId }, { it.publicKey }))
                    .forEach { k ->
                      add(
                        buildJsonArray {
                          add(JsonPrimitive(k.schemeId))
                          add(JsonPrimitive(k.publicKey))
                        }
                      )
                    }
                }
              )
            }
          )
        }
    }
  val root =
    buildJsonArray {
      add(principalsArray)
      add(quorumToJson(quorum))
    }
  return CANONICAL.encodeToString(JsonArray.serializer(), root)
}

/**
 * Parses a canonical [authSpecPreimage] serialization back into an [AllowList] + [QuorumNode],
 * or [SpecLoadResult.Refused] with a reason. TOTAL and fail-closed: it never throws — a
 * malformed, hostile, or truncated preimage folds to Refused, never a boot crash and never a
 * defaulted authorizer. Structural refusals reuse the same throw-with-a-message idiom the rest
 * of this module refuses by (the SchemeKey/Principal/AllowList inits and [quorumFromJson]); one
 * catch turns any of them — and kotlinx's own parse exception — into a Refused carrying the
 * message.
 *
 * Nesting caveat, the same one [quorumFromJson] documents at its own text boundary: the
 * STRUCTURED level is bounded by the reused constructors ([quorumFromJson]'s depth cap,
 * [AllowList]'s id/key distinctness), but the text→JsonElement step is kotlinx's recursive
 * descent and is NOT depth-refused — deep enough nesting overflows the stack with an Error that
 * `catch (Exception)` does not see; the KDoc on jsonMayNestDeeperThan (//agency/shared/json) says
 * which nesting. This function does not itself bound that; a caller handing it UNVERIFIED text
 * must bound its nesting first. In the [loadAuthorizationSpec] path it is
 * moot: the root signature is verified BEFORE the parse, so only bytes the pinned root actually
 * signed reach here, and an attacker who cannot forge that signature cannot drive a depth-bomb
 * into this parser.
 */
fun parseAuthSpec(preimage: String): SpecLoadResult =
  try {
    val root =
      (CANONICAL.parseToJsonElement(preimage) as? JsonArray)
        ?: throw IllegalArgumentException("spec preimage is not a JSON array")
    require(root.size == 2) {
      "spec preimage must be [principals, quorum], got ${root.size} element(s)"
    }
    val principals =
      (root[0] as? JsonArray
          ?: throw IllegalArgumentException("spec principals is not an array"))
        .map { parsePrincipal(it) }
    val quorum =
      quorumFromJson(
        root[1] as? JsonObject
          ?: throw IllegalArgumentException("spec quorum is not an object")
      )
    SpecLoadResult.Loaded(AllowList(principals), quorum)
  } catch (e: Exception) {
    SpecLoadResult.Refused(e.message ?: "spec is structurally invalid")
  }

private fun parsePrincipal(el: JsonElement): Principal {
  val arr = el as? JsonArray ?: throw IllegalArgumentException("a principal entry is not an array")
  require(arr.size == 3) { "a principal must be [principalId, role, keys]" }
  val principalId = specString(arr[0], "principalId")
  val role = specString(arr[1], "role")
  val keys =
    (arr[2] as? JsonArray
        ?: throw IllegalArgumentException("principal '$principalId' keys is not an array"))
      .map { parseKey(it) }
  return Principal(principalId, role, keys)
}

private fun parseKey(el: JsonElement): SchemeKey {
  val arr = el as? JsonArray ?: throw IllegalArgumentException("a key entry is not an array")
  require(arr.size == 2) { "a key must be [schemeId, publicKey]" }
  return SchemeKey(specString(arr[0], "schemeId"), specString(arr[1], "publicKey"))
}

private fun specString(el: JsonElement, field: String): String {
  val prim =
    el as? JsonPrimitive ?: throw IllegalArgumentException("$field is not a scalar value")
  require(prim.isString) { "$field must be a JSON string" }
  return prim.content
}

/**
 * Loads an [AuthorizationSpec] IF AND ONLY IF its [AuthorizationSpec.rootSignature] verifies —
 * under [verifier] — as [pinnedRoot]'s signature over exactly [AuthorizationSpec.specPreimage],
 * then parses the allow-list + quorum from those bytes. The verification key is [pinnedRoot] and
 * ONLY [pinnedRoot]: nothing inside the spec can supply or influence it (the A4-8 closure).
 * Fail-closed all the way down — an unverified signature and an unparseable preimage both yield
 * [SpecLoadResult.Refused], and [RejectingVerifier] (the honest default) refuses every spec.
 */
fun loadAuthorizationSpec(
  spec: AuthorizationSpec,
  pinnedRoot: SchemeKey,
  verifier: ApprovalVerifier,
): SpecLoadResult {
  val verified =
    verifier.verifies(
      pinnedRoot.schemeId,
      pinnedRoot.publicKey,
      spec.rootSignature,
      spec.specPreimage,
    )
  if (!verified) {
    return SpecLoadResult.Refused("root signature does not verify against the pinned root key")
  }
  return parseAuthSpec(spec.specPreimage)
}
