package com.geekinasuit.agency.shared.journal

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
   * (appendBuilt → chainHead). Cross-PROCESS writers remain a design violation — this
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
    if (chainHead().first == 0L) {
      appendBuilt(KIND_GENESIS, genesisPayload(componentId, chainKind), ORIGIN_SUBSTRATE, null)
    }
  }

  override fun append(kind: String, payload: JsonObject, origin: String, idempotencyKey: String?): JournalEntry =
    appendBuilt(kind, payload.toString(), origin, idempotencyKey)

  private fun appendBuilt(kind: String, payloadJson: String, origin: String, idempotencyKey: String?): JournalEntry = synchronized(ioLock) {
    val (lastSeq, lastHash) = chainHead()
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

  override fun readRaw(): List<JournalEntry> = synchronized(ioLock) {
    val out = mutableListOf<JournalEntry>()
    conn.createStatement().use { st ->
      st.executeQuery(
        """SELECT seq, schema_version, kind, chain_context, origin, key_epoch, salt,
             payload_commitment, payload, idempotency_key, prev_hash, hash, sig
           FROM journal ORDER BY seq"""
      ).use { rs ->
        while (rs.next()) {
          out.add(
            JournalEntry(
              seq = rs.getLong(1),
              schemaVersion = rs.getInt(2),
              kind = rs.getString(3),
              chainContext = rs.getString(4),
              origin = rs.getString(5),
              keyEpoch = rs.getInt(6),
              salt = rs.getString(7),
              payloadCommitment = rs.getString(8),
              payloadJson = rs.getString(9),
              idempotencyKey = rs.getString(10),
              prevHash = rs.getString(11),
              hash = rs.getString(12),
              sig = rs.getString(13),
            )
          )
        }
      }
    }
    return out
  }

  override fun readAll(): List<JournalEntry> = verifyAndUpcast(readRaw(), chainContext)

  override fun chainHead(): Pair<Long, String> = synchronized(ioLock) {
    conn.createStatement().use { st ->
      st.executeQuery("SELECT seq, hash FROM journal ORDER BY seq DESC LIMIT 1").use { rs ->
        return if (rs.next()) rs.getLong(1) to rs.getString(2) else 0L to GENESIS_HASH
      }
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
