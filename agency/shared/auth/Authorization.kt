package com.geekinasuit.agency.shared.auth

import java.security.SecureRandom
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Authorization vocabulary for the 3-way ceremony (notification → authenticated approval →
 * mechanical re-verification). These types are the substrate-neutral half: no transport,
 * relay, or event-format concept appears here — the mechanical layer verifies against
 * THESE, whatever substrate carried the approval.
 *
 * The scheme tag exists so evidence outlives any single signature scheme: a journal
 * holding approvals under two schemes must say per-record which verifier applies — a bare
 * 32-byte key does not disclose its curve. [SchemeKey.schemeId] is an OPAQUE identifier in
 * this vocabulary; registering concrete schemes is the verifying layer's business.
 */
data class SchemeKey(val schemeId: String, val publicKey: String) {
  init {
    require(schemeId.isNotBlank()) { "schemeId must be non-blank" }
    require(publicKey.isNotBlank()) { "publicKey must be non-blank" }
  }
}

/**
 * An identity permitted to take part in authorization: who ([principalId]), as what
 * ([role]), verified how ([keys] — at least one, because an approver with no registered
 * key can never produce a verifiable approval). Key equality is byte-exact on the stored
 * string; any per-scheme normalization happens before a key enters an allow-list.
 *
 * Not a data class: [keys] is SNAPSHOTTED at construction, same reason as
 * [QuorumGroup.children] — the init guarantees are about this list, and an aliased
 * caller-held mutable list could change what the type reports after validation ran.
 */
class Principal(val principalId: String, val role: String, keys: List<SchemeKey>) {
  val keys: List<SchemeKey> = keys.toList()

  init {
    require(principalId.isNotBlank()) { "principalId must be non-blank" }
    require(role.isNotBlank()) { "role must be non-blank" }
    require(this.keys.isNotEmpty()) { "a principal requires at least one key" }
    // Refused here, at the type that owns the list, so the message names the actual
    // mistake — one principal repeating its own key — rather than surfacing later as a
    // "claimed by both X and X" collision between a principal and itself.
    val repeated =
      this.keys.groupingBy { it }.eachCount().filterValues { it > 1 }.keys.firstOrNull()
    if (repeated != null) {
      throw IllegalArgumentException(
        "principal '$principalId' lists key ${repeated.schemeId}:${repeated.publicKey} twice"
      )
    }
  }

  override fun equals(other: Any?): Boolean =
    other is Principal &&
      other.principalId == principalId &&
      other.role == role &&
      other.keys == keys

  override fun hashCode(): Int =
    (principalId.hashCode() * 31 + role.hashCode()) * 31 + keys.hashCode()

  override fun toString(): String = "Principal(principalId=$principalId, role=$role, keys=$keys)"
}

/**
 * The allow-list of authorizing principals — it lives with us, never with whatever
 * carries the approvals (a fully compromised carrier cannot add a signer). Duplicate
 * principal ids and cross-principal duplicate keys are refused at construction: a key
 * resolving to two principals would make "who approved" ambiguous at exactly the moment
 * it must not be. (A principal repeating its own key is refused earlier, at [Principal]
 * construction, with a message that says so.)
 *
 * Cross-principal BYTE-sharing is refused regardless of scheme tag: two principals whose
 * keys share bytes are one custodian, however many schemes tag the bytes — under a
 * quorum tree they would read as two leaves while one keyholder clears both, which is
 * exactly the "second required signer" collapse the tree's leaf-distinctness bound
 * exists to prevent. The SAME principal may register the same bytes under two schemes
 * (scheme migration); scheme-tagged lookup identity is unchanged.
 *
 * "Bytes" here means the STORED string, compared exactly — [SchemeKey]'s contract is
 * that any per-scheme normalization happens before a key enters an allow-list. Two
 * unnormalized spellings of one underlying key are distinct strings to this refusal, so
 * the custodian-collapse guarantee is only as strong as that pre-entry normalization.
 */
class AllowList(principals: List<Principal>) {
  private val byId: Map<String, Principal>
  private val byKey: Map<SchemeKey, Principal>

  init {
    val ids = mutableMapOf<String, Principal>()
    val keys = mutableMapOf<SchemeKey, Principal>()
    val bytesHolder = mutableMapOf<String, Principal>()
    for (p in principals) {
      val priorId = ids.put(p.principalId, p)
      if (priorId != null) {
        throw IllegalArgumentException("duplicate principalId '${p.principalId}'")
      }
      for (k in p.keys) {
        val prior = keys.put(k, p)
        if (prior != null) {
          throw IllegalArgumentException(
            "key ${k.schemeId}:${k.publicKey} is claimed by both '${prior.principalId}' and '${p.principalId}'"
          )
        }
        val holder = bytesHolder.put(k.publicKey, p)
        if (holder != null && holder !== p) {
          throw IllegalArgumentException(
            "public key ${k.publicKey} is held by both '${holder.principalId}' and '${p.principalId}' — " +
              "a different scheme tag does not make it a different custodian, and byte-shared keys " +
              "collapse quorum distinctness"
          )
        }
      }
    }
    byId = ids
    byKey = keys
  }

  fun principalFor(key: SchemeKey): Principal? = byKey[key]

  fun byId(principalId: String): Principal? = byId[principalId]
}

/**
 * The evidence record a release (or a rejected attempt) carries: the signed approval
 * itself — scheme-tagged key + signature over [signedPreimage], the canonical serialization
 * the signature commits to — plus the carrier's own id for the artifact and a copy of what
 * the approval committed to (gate, payload digest, nonce). Journaled verbatim so every
 * release is independently re-verifiable after the fact by anyone holding the allow-list,
 * without trusting the process that wrote it.
 *
 * [signedPreimage] is the evidence; the flat [publicKey], [payloadDigest], and [nonce]
 * beside it are INDICES, not what a verifier trusts. A signature is over an identity
 * derived by hashing the preimage, so a record giving only (key, signature, digest, nonce)
 * proves the key signed SOME identity — never that the identity commits to THAT digest and
 * THAT nonce (the committing fields are exactly what such a flattening omits). The
 * mechanical layer recomputes the identity from [signedPreimage], verifies the signature
 * over it, and reads the committed key/digest/nonce out of the verified serialization; the
 * flat columns are for lookup only. [signedPreimage] is opaque here — how it serializes and
 * how an identity recomputes from it is the verifying layer's business, kept out of this
 * substrate-neutral vocabulary.
 */
data class ApprovalEvidence(
  val schemeId: String,
  val publicKey: String,
  val signature: String,
  /** The approval artifact's id in whatever substrate carried it — opaque here. Named for
   * the CARRIER abstraction, not any carrier's own noun, so the one field that points
   * outward still reads substrate-neutral. A convenience for locating the artifact in its
   * carrier, never a verification input: the mechanical layer recomputes identity from
   * [signedPreimage] and never trusts this id. */
  val carrierArtifactId: String,
  val gateId: String,
  val payloadDigest: String,
  val nonce: String,
  /** The canonical serialization the [signature] commits to — the evidence proper (see the
   * class KDoc). Opaque bytes here; the verifying layer recomputes the signed identity from
   * it. Nullable so a record that predates the field still parses: a null preimage cannot be
   * re-verified, so the verifying layer treats it as unverifiable (fail-closed), never a
   * pass. */
  val signedPreimage: String? = null,
) {
  init {
    for ((name, v) in
      listOf(
        "schemeId" to schemeId,
        "publicKey" to publicKey,
        "signature" to signature,
        "carrierArtifactId" to carrierArtifactId,
        "gateId" to gateId,
        "payloadDigest" to payloadDigest,
        "nonce" to nonce,
      )) {
      require(v.isNotBlank()) { "$name must be non-blank" }
    }
    // Nullable — a record predating the field parses to null — but a PRESENT preimage is
    // held to the same non-blank bar as the required fields.
    signedPreimage?.let {
      require(it.isNotBlank()) { "signedPreimage, when present, must be non-blank" }
    }
  }

  fun toJson(): JsonObject =
    buildJsonObject {
      put("schemeId", schemeId)
      put("publicKey", publicKey)
      put("signature", signature)
      put("carrierArtifactId", carrierArtifactId)
      put("gateId", gateId)
      put("payloadDigest", payloadDigest)
      put("nonce", nonce)
      // Omitted when null so a record without a preimage serializes to exactly the pre-field
      // shape — absence and a written value stay distinguishable on the way back in.
      signedPreimage?.let { put("signedPreimage", it) }
    }

  companion object {
    fun fromJson(json: JsonObject): ApprovalEvidence =
      ApprovalEvidence(
        schemeId = json.req("schemeId", "approval evidence"),
        publicKey = json.req("publicKey", "approval evidence"),
        signature = json.req("signature", "approval evidence"),
        carrierArtifactId = json.req("carrierArtifactId", "approval evidence"),
        gateId = json.req("gateId", "approval evidence"),
        payloadDigest = json.req("payloadDigest", "approval evidence"),
        nonce = json.req("nonce", "approval evidence"),
        signedPreimage = json.optStr("signedPreimage", "approval evidence"),
      )
  }
}

/**
 * A fresh substrate-issued nonce: 32 random bytes, hex. Substrate-issued is load-bearing
 * (the approval surface must not mint what it also authorizes against); single-use is the
 * consuming fold's discipline, not a property of the value.
 *
 * Byte-identical to the journal module's `Envelope.newSaltHex`, and deliberately not
 * shared with it: this module is substrate-neutral and depends only on
 * kotlinx-serialization (the BUILD file states the layering), so it re-types four lines
 * rather than importing a journal dep — or minting a shared module — to borrow them.
 */
fun freshNonceHex(rng: SecureRandom = SecureRandom()): String {
  val bytes = ByteArray(32)
  rng.nextBytes(bytes)
  return bytes.joinToString("") { "%02x".format(it) }
}

