package com.geekinasuit.agency.shared.journal

import kotlinx.serialization.json.JsonObject

/**
 * Store seam for the journal. One store = one component's chain — the lead is today's only
 * journaled component; per-component isolation is a substrate rule (AGENCY-008 at-rest
 * scoping — one owner-only DB file per component, never a shared database other components
 * can read).
 *
 * Durability contract: [append] returns only after the entry is durable (WAL commit,
 * synchronous=FULL). The fsync guarantee itself is design-asserted (cooperative fault
 * injection cannot observe power loss); process death at instruction boundaries is what the
 * scenario tests exercise.
 *
 * Single-writer rule: exactly one PROCESS opens a component's store for writing. Within
 * that process, implementations serialize appends and reads internally (AGENCY-021 §2):
 * accept boundaries journal arrival facts from caller threads while the daemon loop
 * journals derived facts — thread placement is the daemon's discipline; chain integrity
 * under it is the store's. Nothing enforces cross-process locking beyond SQLite's own — a
 * second writing process is a design violation (contention handling arrives only if a
 * store ever legitimately gains one).
 */
interface JournalStore : AutoCloseable {
  val componentId: String
  val chainKind: String

  /** The chain-context tag stamped on (and hashed into) every v3 entry of this store. */
  val chainContext: String

  /**
   * Appends one entry (assigns seq, salts + commits the payload, chains the hash, signs via
   * the epoch seam); durable on return. [origin] is required, not defaulted — it is the
   * provenance a fold's gate-release check keys on, and a silently-defaulted provenance is
   * a footgun.
   */
  fun append(kind: String, payload: JsonObject, origin: String, idempotencyKey: String? = null): JournalEntry

  /**
   * Reads the full journal: verifies the hash chain over the RAW stored form (per-version
   * preimages), the chain-context binding, and the key-epoch rules (throws
   * [ChainBrokenException]/[EpochRuleException]), then upcasts each entry to
   * [SUPPORTED_SCHEMA_VERSION] (throws [JournalVersionException] on newer-than-supported).
   */
  fun readAll(): List<JournalEntry>

  /** Raw read without verify/upcast — fixture generation and chain checks only. */
  fun readRaw(): List<JournalEntry>

  /** Appends a pre-built entry verbatim (legacy/fixture writer only — no salting, no epoch logic). */
  fun appendRaw(entry: JournalEntry)

  /**
   * The chain head (last seq + hash) — cheap, public, and the retention surface for
   * truncation detection: a prefix of a valid chain is a valid chain, so in-place tamper is
   * detectable from the file alone but TRUNCATION IS NOT — catching it is the retained
   * head's job (heartbeat/off-host anchoring is an operator surface; AGENCY-007).
   */
  fun chainHead(): Pair<Long, String>
}

/**
 * Chain verification + upcast, shared by stores. Verifies over raw stored forms:
 * per-version hash preimages, prevHash linkage, chain-context binding (v3+ entries must
 * carry [expectedChainContext] — the local half of the anti-splice guarantee; the preimage
 * carries the cross-journal half), genesis discipline (a chain that BEGINS at v3 must begin
 * with a seq-1 [KIND_GENESIS] entry; legacy v2-era chains are exempt), and key-epoch rules
 * (epoch transitions only via [KIND_KEY_EPOCH_STARTED] stepping exactly +1; epoch 0 entries
 * must be unsigned; epoch >0 entries must carry a sig — presence rules now, cryptographic
 * verification arrives with active signing).
 */
fun verifyAndUpcast(raw: List<JournalEntry>, expectedChainContext: String): List<JournalEntry> {
  var prevHash = GENESIS_HASH
  var epoch = 0
  for (e in raw) {
    val recomputed = entryHashFor(e)
    if (e.prevHash != prevHash) throw ChainBrokenException(e.seq, "prevHash does not link to prior entry")
    if (recomputed != e.hash) throw ChainBrokenException(e.seq, "stored hash does not match recomputed hash")
    prevHash = e.hash

    if (e.schemaVersion >= 3) {
      if (e.chainContext != expectedChainContext) {
        throw ChainBrokenException(e.seq, "chainContext '${e.chainContext}' is not this store's '$expectedChainContext'")
      }
      if (e.seq == 1L && e.kind != KIND_GENESIS) {
        throw ChainBrokenException(e.seq, "a v3-born chain must begin with a genesis entry")
      }
      if (e.kind == KIND_KEY_EPOCH_STARTED) {
        if (e.keyEpoch != epoch + 1) throw EpochRuleException(e.seq, "epoch ${e.keyEpoch} does not step from $epoch by 1")
        epoch = e.keyEpoch
      } else if (e.keyEpoch != epoch) {
        throw EpochRuleException(e.seq, "entry carries epoch ${e.keyEpoch} while chain is in epoch $epoch")
      }
      if (epoch == 0 && e.sig != null) throw EpochRuleException(e.seq, "epoch 0 is the unsigned era; entry carries a sig")
      if (epoch > 0 && e.sig == null) throw EpochRuleException(e.seq, "epoch $epoch requires a signature")
    }
  }
  return raw.map { upcastToSupported(it, expectedChainContext) }
}

fun chainContextOf(componentId: String, chainKind: String): String =
  "agency/$componentId/$chainKind/v$SUPPORTED_SCHEMA_VERSION"
