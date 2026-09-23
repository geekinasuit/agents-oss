package com.geekinasuit.agency.shared.auth

import com.geekinasuit.agency.shared.json.jsonMayNestDeeperThan
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive

/**
 * The verifying half of the 3-way ceremony (notification → authenticated approval →
 * mechanical re-verification): the crypto PORT the mechanical layer calls, the canonical
 * serialization an approval's signature commits to, and the parse that recovers the
 * committed identity from it.
 *
 * Substrate-neutral like the rest of this module — no transport, relay, or event-format
 * concept appears — and dependent only on kotlinx-serialization and the shared JSON nesting
 * bound (the BUILD file states the layering), so the canonical form is a JSON array and
 * nothing here reaches for a hash or a curve. The actual signature check is the substrate
 * adapter's business, wired behind [ApprovalVerifier]; the fold consumes the interface, so it
 * stays testable with a deterministic verifier and free of a crypto dependency until the real
 * adapter lands.
 */
fun interface ApprovalVerifier {
  /**
   * True iff [signature] is a valid signature by [publicKey] (under [schemeId]) over exactly
   * [preimage]. [preimage] is the bytes the signature commits to — [committedPreimage]
   * produces it and [parseCommitted] reads the committed fields back out of it; a verifier
   * neither parses nor trusts anything but these four arguments. A verifier that consulted a
   * record's flat columns instead of the preimage it was handed would defeat the purpose of
   * being handed the preimage.
   */
  fun verifies(schemeId: String, publicKey: String, signature: String, preimage: String): Boolean
}

/**
 * The fail-closed default verifier: no signature ever verifies. A fold wired with this
 * admits zero approvals, so a quorum is never met and no gate clears — the honest state of a
 * substrate whose real verifier is not yet installed, and the reason a fold's verifier is a
 * required argument with no silent pass-through default.
 */
object RejectingVerifier : ApprovalVerifier {
  override fun verifies(
    schemeId: String,
    publicKey: String,
    signature: String,
    preimage: String,
  ): Boolean = false
}

/**
 * The fields an approval's signature COMMITS to, recovered from the verified preimage —
 * never read from a record's flat columns. [publicKey] is the signer's key as committed (the
 * allow-list resolves it to a principal); [gateId], [payloadDigest], and [nonce] are what the
 * approval bound itself to. The mechanical layer trusts THESE, and treats the flat copies
 * beside them in a record as lookup indices to cross-check, never as authority — see
 * [ApprovalEvidence]'s KDoc for why a signature over a flattened record proves less than it
 * appears to.
 */
data class CommittedApproval(
  val publicKey: String,
  val gateId: String,
  val payloadDigest: String,
  val nonce: String,
)

/** The canonical-form encoder: default config, so no pretty-printing and no incidental
 * whitespace — two writers of the same four values must produce byte-identical preimages. */
private val CANONICAL = Json

/**
 * The canonical serialization an approval signs: a JSON array of exactly
 * `[publicKey, gateId, payloadDigest, nonce]`, all strings, in that order. A fixed positional
 * array (not an object) so the bytes are canonical without depending on a field-ordering
 * convention — which is what lets an independent re-serialization of the same four values be
 * a CHECK on provenance rather than codec self-agreement.
 */
fun committedPreimage(
  publicKey: String,
  gateId: String,
  payloadDigest: String,
  nonce: String,
): String =
  CANONICAL.encodeToString(
    JsonArray.serializer(),
    JsonArray(
      listOf(
        JsonPrimitive(publicKey),
        JsonPrimitive(gateId),
        JsonPrimitive(payloadDigest),
        JsonPrimitive(nonce),
      )
    ),
  )

/**
 * Recovers the committed fields from a [committedPreimage] serialization, or null if the
 * bytes are not that shape: not a JSON array, not exactly four elements, any element not a
 * JSON string, or any field blank. Null is the fail-closed signal — the verifying layer
 * treats a preimage it cannot parse as unverifiable, never as a pass. Total and
 * deterministic: it never throws, so a hostile preimage folds to "unverified", not a boot
 * crash.
 *
 * Safe on untrusted text, which a preimage is until a signature over it verifies — and a
 * caller may parse before it verifies. A preimage that may nest deeper than the committed
 * shape (one flat array) is refused before the parse: the parser recurses once per level,
 * and deep enough nesting would overflow the stack with an Error, which the parse's
 * `catch (Exception)` does not see.
 */
fun parseCommitted(preimage: String): CommittedApproval? {
  if (jsonMayNestDeeperThan(preimage, COMMITTED_DEPTH)) return null
  val arr =
    try {
      CANONICAL.parseToJsonElement(preimage) as? JsonArray ?: return null
    } catch (_: Exception) {
      return null
    }
  if (arr.size != 4) return null
  val fields =
    arr.map { el -> (el as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null }
  if (fields.any { it.isBlank() }) return null
  return CommittedApproval(
    publicKey = fields[0],
    gateId = fields[1],
    payloadDigest = fields[2],
    nonce = fields[3],
  )
}

/** How deep a [committedPreimage] nests: one flat array of strings. */
private const val COMMITTED_DEPTH = 1
