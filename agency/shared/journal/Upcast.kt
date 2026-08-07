package com.geekinasuit.agency.shared.journal

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * Upcast-on-read: entries below [SUPPORTED_SCHEMA_VERSION] are projected forward
 * version-by-version at read time; the stored bytes are never rewritten, so the hash chain
 * (which binds the stored form under each entry's own preimage version) stays valid.
 *
 * v1 → v2 renames effect-intent `msg` to `message` and defaults payload `origin`.
 * v2 → v3 lifts pre-v3 entries into the v3
 * envelope: entry-level origin defaults to "unknown", keyEpoch to 0 (the pre-signing era),
 * chainContext to the reading store's context; salt/payloadCommitment stay EMPTY —
 * absent-by-version, because a commitment minted after the fact would be a fabricated
 * claim about what the writer committed to.
 *
 * Anything newer than supported throws [JournalVersionException] — refuse replay rather
 * than misread a future journal.
 */
fun upcastToSupported(e: JournalEntry, readerChainContext: String): JournalEntry {
  if (e.schemaVersion > SUPPORTED_SCHEMA_VERSION) throw JournalVersionException(e.seq, e.schemaVersion)
  var cur = e
  while (cur.schemaVersion < SUPPORTED_SCHEMA_VERSION) {
    cur = when (cur.schemaVersion) {
      1 -> upcastV1toV2(cur)
      2 -> upcastV2toV3(cur, readerChainContext)
      else -> throw JournalVersionException(cur.seq, cur.schemaVersion)
    }
  }
  return cur
}

private fun upcastV1toV2(e: JournalEntry): JournalEntry {
  if (e.kind != "effect-intent") return e.copy(schemaVersion = 2)
  val payload = Json.parseToJsonElement(e.payloadJson).jsonObject
  if (!payload.containsKey("msg")) return e.copy(schemaVersion = 2)
  val migrated = buildJsonObject {
    for ((k, v) in payload) {
      if (k == "msg") put("message", v.jsonPrimitive.content) else put(k, v)
    }
    if (!payload.containsKey("origin")) put("origin", "unknown")
  }
  // Upcast is a read projection: seq/hash/prevHash/sig stay as stored.
  return e.copy(schemaVersion = 2, payloadJson = migrated.toString())
}

private fun upcastV2toV3(e: JournalEntry, readerChainContext: String): JournalEntry =
  e.copy(
    schemaVersion = 3,
    chainContext = readerChainContext,
    origin = if (e.origin.isEmpty()) "unknown" else e.origin,
    keyEpoch = 0,
    // salt/payloadCommitment stay as stored (empty for pre-v3 entries): absent-by-version.
  )

/** Genesis payload for a fresh v3 chain: the chain's identity + the ledger-key seam (null until signing activates). */
fun genesisPayload(componentId: String, chainKind: String): String =
  buildJsonObject {
    put("componentId", componentId)
    put("chainKind", chainKind)
    put("chainSchemaVersion", SUPPORTED_SCHEMA_VERSION)
    put("ledgerKeyId", JsonNull)
  }.toString()
