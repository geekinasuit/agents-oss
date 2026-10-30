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
   *
   * The payload is stored as [storedPayloadJson] prints it, so it reads back equal to [payload],
   * except for a `JsonUnquotedLiteral`, which reads back as whatever its raw text parses to.
   * THROWS [IllegalArgumentException], writing nothing, if [storedPayloadJson] refuses [payload],
   * or if [kind], [origin] or [idempotencyKey] holds an unpaired surrogate ([appendRaw]).
   */
  fun append(kind: String, payload: JsonObject, origin: String, idempotencyKey: String? = null): JournalEntry

  /**
   * Reads the full journal: verifies the hash chain over the RAW stored form (per-version
   * preimages), the chain-context binding, and the key-epoch rules (throws
   * [ChainBrokenException]/[EpochRuleException]), then upcasts each entry to
   * [SUPPORTED_SCHEMA_VERSION] (throws [JournalVersionException] on newer-than-supported).
   */
  fun readAll(): List<JournalEntry>

  /**
   * Reads the entries after [from], verified and upcast as [readAll] verifies and upcasts them, with
   * the chain continuing from [from]: the first entry must link to [from]'s hash, and the key-epoch
   * rules start from [from]'s epoch. Returns the entries and the cursor after the last of them
   * ([from] itself when there are none).
   *
   * The entry at [from] must still be stored with [from]'s hash, else this throws
   * [ChainBrokenException]: so a truncation below [from], a rewrite that changes the hash at [from],
   * and a cursor past the head are each seen. [from]'s epoch must be the stored chain's epoch after
   * [from], else this throws [EpochRuleException]. The entries up to and including [from] are not verified
   * again (only [from]'s stored hash is compared, never recomputed), so an in-place change among
   * them that leaves that stored hash alone goes unseen here; [readAll] sees it.
   */
  fun readAfter(from: ChainCursor): TailRead

  /** Raw read without verify/upcast — fixture generation and chain checks only. */
  fun readRaw(): List<JournalEntry>

  /**
   * Appends a pre-built entry verbatim (legacy/fixture writer only — no salting, no epoch logic).
   *
   * THROWS [IllegalArgumentException], writing nothing, if a text field holds an unpaired
   * surrogate. Such a field has no UTF-8 encoding: a UTF-8 store would keep a different string
   * from the one the entry was hashed over, and the hash's lenient encoding gives it the bytes of
   * the same field with `?` in its place.
   */
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
fun verifyAndUpcast(raw: List<JournalEntry>, expectedChainContext: String): List<JournalEntry> =
  verifyAndUpcastAfter(raw, expectedChainContext, ChainCursor.START).entries

/**
 * Where a verified read stopped: the last entry's seq and stored hash, and the key epoch the chain
 * is in after it. [START] is the position before any entry.
 */
data class ChainCursor(val seq: Long, val hash: String, val keyEpoch: Int) {
  companion object {
    val START = ChainCursor(0L, GENESIS_HASH, 0)
  }
}

/** Entries read after a cursor, verified and upcast, and the cursor after the last of them. */
data class TailRead(val entries: List<JournalEntry>, val cursor: ChainCursor)

/**
 * [verifyAndUpcast] over entries that continue a chain from [from]. Every entry is verified before
 * any is upcast, so a chain fault is reported ahead of an unsupported version wherever each occurs.
 */
fun verifyAndUpcastAfter(raw: List<JournalEntry>, expectedChainContext: String, from: ChainCursor): TailRead {
  val cursor = verifyChain(raw, expectedChainContext, from)
  return TailRead(raw.map { upcastToSupported(it, expectedChainContext) }, cursor)
}

private fun verifyChain(raw: List<JournalEntry>, expectedChainContext: String, from: ChainCursor): ChainCursor {
  var seq = from.seq
  var prevHash = from.hash
  var epoch = from.keyEpoch
  for (e in raw) {
    val recomputed = entryHashFor(e)
    if (e.prevHash != prevHash) throw ChainBrokenException(e.seq, "prevHash does not link to prior entry")
    if (recomputed != e.hash) throw ChainBrokenException(e.seq, "stored hash does not match recomputed hash")
    seq = e.seq
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
  return ChainCursor(seq, prevHash, epoch)
}

fun chainContextOf(componentId: String, chainKind: String): String =
  "agency/$componentId/$chainKind/v$SUPPORTED_SCHEMA_VERSION"
