package com.geekinasuit.agency.shared.journal

import com.geekinasuit.agency.shared.text.hasUtf8Encoding
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.sql.Connection
import java.sql.DriverManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject

/**
 * The default journal substrate: embedded SQLite, WAL +
 * synchronous=FULL, append inside a transaction — [append] returns only after commit. One
 * `journal.db` per component directory, directory owner-only (AGENCY-008 at-rest scoping;
 * best-effort on non-POSIX filesystems).
 *
 * A fresh store (empty table) writes its own genesis entry — kind [KIND_GENESIS], origin
 * [ORIGIN_SUBSTRATE], payload carrying the chain identity + the ledgerKeyId seam — so every
 * v3-born chain declares its context at seq 1.
 */
class SqliteStore(
  dir: String,
  override val componentId: String,
  override val chainKind: String = "main",
  private val signer: EntrySigner = NoopSigner,
) : JournalStore {
  override val chainContext: String = chainContextOf(componentId, chainKind)

  private val conn: Connection
  private val rng = SecureRandom()

  /** Serializes every store op (AGENCY-021 §2): accept boundaries append ARRIVAL facts
   * from caller threads while the daemon loop appends derived facts — one connection, one
   * chain, so seq assignment + prevHash linkage must be atomic per append, and a read
   * must never interleave with a half-committed append. Monitor is reentrant
   * (appendBuilt → appendRaw). Cross-PROCESS writers remain a design violation — this
   * lock arbitrates threads within the single writing process only. */
  private val ioLock = Any()

  init {
    val d = File(dir)
    d.mkdirs()
    try {
      Files.setPosixFilePermissions(d.toPath(), PosixFilePermissions.fromString("rwx------"))
    } catch (_: UnsupportedOperationException) {
      // Non-POSIX filesystem: ownership scoping is best-effort here, the substrate rule stands.
    }
    conn = DriverManager.getConnection("jdbc:sqlite:$dir/journal.db")
    conn.createStatement().use { st ->
      st.execute("PRAGMA journal_mode=WAL")
      st.execute("PRAGMA synchronous=FULL")
      st.execute(
        """CREATE TABLE IF NOT EXISTS journal(
             seq INTEGER PRIMARY KEY,
             schema_version INTEGER NOT NULL,
             kind TEXT NOT NULL,
             chain_context TEXT NOT NULL,
             origin TEXT NOT NULL,
             key_epoch INTEGER NOT NULL,
             salt TEXT NOT NULL,
             payload_commitment TEXT NOT NULL,
             payload TEXT NOT NULL,
             idempotency_key TEXT,
             prev_hash TEXT NOT NULL,
             hash TEXT NOT NULL,
             sig TEXT)"""
      )
    }
    conn.autoCommit = false
    // The empty check and the genesis insert share one transaction, as appendBuilt's head read and
    // insert do; on a journal that is not empty, the check's transaction ends here.
    synchronized(ioLock) {
      if (readHead(conn).first == 0L) {
        appendBuilt(KIND_GENESIS, genesisPayload(componentId, chainKind), ORIGIN_SUBSTRATE, null)
      } else {
        conn.commit()
      }
    }
  }

  override fun append(kind: String, payload: JsonObject, origin: String, idempotencyKey: String?): JournalEntry =
    appendBuilt(kind, storedPayloadJson(payload), origin, idempotencyKey)

  private fun appendBuilt(kind: String, payloadJson: String, origin: String, idempotencyKey: String?): JournalEntry = synchronized(ioLock) {
    // Read inside the transaction the insert below commits: should another connection commit an
    // append in between, which the single-writer rule forbids, the insert fails on the stale
    // snapshot instead of linking past that append.
    val (lastSeq, lastHash) = readHead(conn)
    val seq = lastSeq + 1
    val salt = newSaltHex(rng)
    val commitment = payloadCommitment(salt, payloadJson)
    val hash =
      entryHashV3(
        seq, SUPPORTED_SCHEMA_VERSION, kind, chainContext, origin, keyEpoch = 0, salt,
        commitment, payloadJson, idempotencyKey, lastHash,
      )
    val entry =
      JournalEntry(
        seq, SUPPORTED_SCHEMA_VERSION, kind, chainContext, origin, keyEpoch = 0, salt,
        commitment, payloadJson, idempotencyKey, lastHash, hash, signer.sign(hash),
      )
    appendRaw(entry)
    return entry
  }

  override fun appendRaw(entry: JournalEntry): Unit = synchronized(ioLock) {
    requireUtf8Fields(entry)
    conn.prepareStatement(
      """INSERT INTO journal(seq, schema_version, kind, chain_context, origin, key_epoch,
           salt, payload_commitment, payload, idempotency_key, prev_hash, hash, sig)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)"""
    ).use { ps ->
      ps.setLong(1, entry.seq)
      ps.setInt(2, entry.schemaVersion)
      ps.setString(3, entry.kind)
      ps.setString(4, entry.chainContext)
      ps.setString(5, entry.origin)
      ps.setInt(6, entry.keyEpoch)
      ps.setString(7, entry.salt)
      ps.setString(8, entry.payloadCommitment)
      ps.setString(9, entry.payloadJson)
      ps.setString(10, entry.idempotencyKey)
      ps.setString(11, entry.prevHash)
      ps.setString(12, entry.hash)
      ps.setString(13, entry.sig)
      ps.executeUpdate()
    }
    conn.commit()
  }

  /** Each text field must have a UTF-8 encoding: the driver writes `?` for an unpaired surrogate,
   * so the stored field would not be the one the entry was hashed over. */
  private fun requireUtf8Fields(entry: JournalEntry) {
    val fields =
      listOf(
        "kind" to entry.kind,
        "chainContext" to entry.chainContext,
        "origin" to entry.origin,
        "salt" to entry.salt,
        "payloadCommitment" to entry.payloadCommitment,
        "payloadJson" to entry.payloadJson,
        "idempotencyKey" to entry.idempotencyKey,
        "prevHash" to entry.prevHash,
        "hash" to entry.hash,
        "sig" to entry.sig,
      )
    for ((name, value) in fields) {
      require(value == null || hasUtf8Encoding(value)) {
        "$name holds an unpaired surrogate, which has no UTF-8 encoding"
      }
    }
  }

  override fun readRaw(): List<JournalEntry> = reading { readRowsAfter(conn, Long.MIN_VALUE) }

  override fun readAll(): List<JournalEntry> = verifyAndUpcast(readRaw(), chainContext)

  override fun readAfter(from: ChainCursor): TailRead {
    val raw = reading {
      requireCursorStored(conn, from)
      readRowsAfter(conn, from.seq)
    }
    return verifyAndUpcastAfter(raw, chainContext, from)
  }

  override fun chainHead(): Pair<Long, String> = reading { readHead(conn) }

  // One read, in one transaction that ends here: with autoCommit off, a read would otherwise leave
  // its transaction open, and this connection would go on seeing that snapshot, blind to rows
  // another connection on the same file commits later.
  private fun <T> reading(block: () -> T): T = synchronized(ioLock) {
    try {
      block()
    } finally {
      conn.commit()
    }
  }

  override fun close(): Unit = synchronized(ioLock) {
    // Under the same lock as every other op: with accept boundaries appending from caller
    // threads (AGENCY-021 §2), close must not race an in-flight append on the shared
    // connection — a closing store waits for the append to commit, and the append never
    // sees a half-closed connection.
    conn.close()
  }
}

/** Convenience for tests and tools: an empty JsonObject. */
fun emptyPayload(): JsonObject = buildJsonObject {}
