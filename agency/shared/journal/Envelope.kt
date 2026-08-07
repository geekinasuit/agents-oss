package com.geekinasuit.agency.shared.journal

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Journal entry envelope, v3: schema + salted payload-commitment are active; signing is
 * staged behind the key-epoch seam.
 *
 * The hash chain binds the STORED form: verification recomputes over raw stored fields with
 * the preimage rules of each entry's own [schemaVersion] (stored forms are versioned), so
 * upcast-on-read (a projection, see Upcast.kt) never invalidates the chain.
 *
 * [salt]/[payloadCommitment] exist from entry 1 on every v3 chain — both are unrecoverable
 * retrofits: an entry hashed without a commitment can never later be redacted (payload
 * withheld, commitment proven) or re-bound. Pre-v3 entries carry them empty
 * (absent-by-version; commitments are never retro-minted).
 *
 * [chainContext] ("agency/<componentId>/<chainKind>/v<era>") is stored on every v3 entry and
 * included in its preimage, so an entry from one journal can never be spliced into another —
 * a same-seq/same-kind collision across components is a chain break, not a silent adoption.
 *
 * [keyEpoch] 0 = the unsigned era ([sig] must be null). A future KIND_KEY_EPOCH_STARTED
 * entry (reserved, not yet emitted) introduces epoch N+1 and the signing key identity;
 * from then on [sig] is required. Dual-signature introduction rules (old key signs the new
 * key's introduction) arrive with active signing.
 */
data class JournalEntry(
  val seq: Long,
  val schemaVersion: Int,
  val kind: String,
  val chainContext: String,
  val origin: String,
  val keyEpoch: Int,
  val salt: String,
  val payloadCommitment: String,
  val payloadJson: String,
  val idempotencyKey: String?,
  val prevHash: String,
  val hash: String,
  val sig: String?,
)

const val SUPPORTED_SCHEMA_VERSION = 3
const val GENESIS_HASH = "genesis"

/** Reserved entry kinds the envelope layer itself gives meaning to. */
const val KIND_GENESIS = "genesis"
const val KIND_KEY_EPOCH_STARTED = "key-epoch-started"

/**
 * Origins (the layer that AUTHORED the decision an entry records — provenance, not kind).
 * The substrate is the mechanical WRITER of every entry regardless of origin;
 * the origin stamp is what a fold's provenance checks key on, so a cognition-authored
 * entry can never satisfy the gate-release check no matter what kind it claims to be.
 */
const val ORIGIN_SUBSTRATE = "substrate"
const val ORIGIN_AUTH_LAYER = "auth-layer"
const val ORIGIN_COGNITION = "cognition"

/** Signing seam. Epoch 0 wires [NoopSigner]; a real signer arrives with key-epoch activation. */
interface EntrySigner {
  fun sign(hashHex: String): String?
}

object NoopSigner : EntrySigner {
  override fun sign(hashHex: String): String? = null
}

/**
 * Injective canonical encoding shared by every preimage version: length-prefixed fields so
 * boundaries can never shift (a separator inside payloadJson or idempotencyKey cannot
 * re-partition into a different-but-colliding stored form), and null encodes distinctly
 * from any literal string.
 */
private fun enc(s: String?): String =
  if (s == null) "null;" else "${s.toByteArray(Charsets.UTF_8).size}:$s;"

private fun sha256Hex(bytes: ByteArray): String =
  MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

/**
 * v3 preimage — domain tag + every stored field except hash/sig, fixed order
 * (seq, schemaVersion, kind, chainContext, origin, keyEpoch, salt,
 * payloadCommitment, payloadJson, idempotencyKey, prevHash).
 */
fun entryHashV3(
  seq: Long,
  schemaVersion: Int,
  kind: String,
  chainContext: String,
  origin: String,
  keyEpoch: Int,
  salt: String,
  payloadCommitment: String,
  payloadJson: String,
  idempotencyKey: String?,
  prevHash: String,
): String {
  val canonical =
    "agency-journal-v3;" + enc(seq.toString()) + enc(schemaVersion.toString()) + enc(kind) +
      enc(chainContext) + enc(origin) + enc(keyEpoch.toString()) + enc(salt) +
      enc(payloadCommitment) + enc(payloadJson) + enc(idempotencyKey) + enc(prevHash)
  return sha256Hex(canonical.toByteArray(Charsets.UTF_8))
}

/**
 * v1/v2 preimage — byte-exact legacy encoding (domain tag "s3-entry;", six fields) so
 * pre-v3 journals verify under the preimage they were written with.
 */
fun entryHashV2(
  seq: Long,
  schemaVersion: Int,
  kind: String,
  payloadJson: String,
  idempotencyKey: String?,
  prevHash: String,
): String {
  val canonical =
    "s3-entry;" + enc(seq.toString()) + enc(schemaVersion.toString()) + enc(kind) +
      enc(payloadJson) + enc(idempotencyKey) + enc(prevHash)
  return sha256Hex(canonical.toByteArray(Charsets.UTF_8))
}

/** Recomputes an entry's hash under the preimage rules of its own stored schemaVersion. */
fun entryHashFor(e: JournalEntry): String =
  if (e.schemaVersion >= 3) {
    entryHashV3(
      e.seq, e.schemaVersion, e.kind, e.chainContext, e.origin, e.keyEpoch, e.salt,
      e.payloadCommitment, e.payloadJson, e.idempotencyKey, e.prevHash,
    )
  } else {
    entryHashV2(e.seq, e.schemaVersion, e.kind, e.payloadJson, e.idempotencyKey, e.prevHash)
  }

/** 32 random bytes, hex — one fresh salt per entry. */
fun newSaltHex(rng: SecureRandom = SecureRandom()): String {
  val bytes = ByteArray(32)
  rng.nextBytes(bytes)
  return bytes.joinToString("") { "%02x".format(it) }
}

/**
 * Salted payload commitment: SHA-256(saltBytes ‖ payloadJson-UTF8). The salt keeps a
 * withheld payload undictionaryable; the commitment lets a redacted entry still prove what
 * it committed to (selective-disclosure seam; disclosure protocol is later work).
 */
fun payloadCommitment(saltHex: String, payloadJson: String): String {
  val saltBytes = hexToBytes(saltHex)
  return sha256Hex(saltBytes + payloadJson.toByteArray(Charsets.UTF_8))
}

private fun hexToBytes(hex: String): ByteArray {
  require(hex.length % 2 == 0) { "hex string must have even length" }
  return ByteArray(hex.length / 2) { i ->
    ((Character.digit(hex[2 * i], 16) shl 4) + Character.digit(hex[2 * i + 1], 16)).toByte()
  }
}

class ChainBrokenException(seq: Long, detail: String) :
  RuntimeException("journal hash chain broken at seq=$seq: $detail")

class JournalVersionException(seq: Long, version: Int) :
  RuntimeException(
    "unsupported journal schemaVersion=$version at seq=$seq " +
      "(this build reads <= $SUPPORTED_SCHEMA_VERSION; refusing replay rather than misreading)"
  )

class EpochRuleException(seq: Long, detail: String) :
  RuntimeException("key-epoch rule violated at seq=$seq: $detail")
