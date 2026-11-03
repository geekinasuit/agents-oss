package com.geekinasuit.agency.shared.journal

import java.io.File
import java.io.FileNotFoundException
import java.sql.Connection
import java.sql.DriverManager
import java.util.Properties

/**
 * A read-only view of a component's SQLite journal, for a process that is not its writer: a status
 * reader beside a running lead. It opens `<dir>/journal.db` read-only and never writes or migrates
 * the journal, nor creates the database or its directory: a missing file is [FileNotFoundException].
 *
 * Reads are verified as [JournalReader] states, against [chainContextOf] of the [componentId] and
 * [chainKind] the caller names, never against a context read from the file. Each read runs in one
 * read transaction that ends with it, so the cursor check and the tail of [readAfter] see one
 * snapshot, and the next read sees what the writer has committed since.
 *
 * The store's directory is owner-only (AGENCY-008), so this runs as the component's owner. It also
 * needs write permission on that directory, though it writes no journal data: the store runs in WAL
 * mode, and when no writer has the database open SQLite creates the WAL files (`journal.db-wal`, and
 * its shared-memory index `journal.db-shm`) beside it for any reader, and they stay after the reader
 * closes; the store opens and appends over them as usual. In a directory it cannot write,
 * construction throws [java.sql.SQLException]; it reads once while opening, so this is found there,
 * not at first use.
 */
class SqliteJournalReader(dir: String, componentId: String, chainKind: String = "main") : JournalReader {
  override val chainContext: String = chainContextOf(componentId, chainKind)

  private val conn: Connection
  private val lock = Any()

  init {
    val db = File(dir, "journal.db")
    if (!db.isFile) throw FileNotFoundException("no journal at ${db.path}")
    val props = Properties()
    // SQLITE_OPEN_READONLY alone: no write, and no create if the file has gone.
    props.setProperty("open_mode", "1")
    props.setProperty("busy_timeout", "5000")
    conn = DriverManager.getConnection("jdbc:sqlite:${db.path}", props)
    try {
      conn.createStatement().use { it.execute("PRAGMA query_only=1") }
      conn.autoCommit = false
      reading { readHead(conn) }
    } catch (x: Exception) {
      try {
        conn.close()
      } catch (c: Exception) {
        x.addSuppressed(c)
      }
      throw x
    }
  }

  override fun readAll(): List<JournalEntry> = verifyAndUpcast(reading { readRowsAfter(conn, Long.MIN_VALUE) }, chainContext)

  override fun readAfter(from: ChainCursor): TailRead {
    val raw = reading {
      requireCursorStored(conn, from)
      readRowsAfter(conn, from.seq)
    }
    return verifyAndUpcastAfter(raw, chainContext, from)
  }

  override fun chainHead(): Pair<Long, String> = reading { readHead(conn) }

  private fun <T> reading(block: () -> T): T = synchronized(lock) {
    try {
      block()
    } finally {
      conn.rollback()
    }
  }

  override fun close(): Unit = synchronized(lock) { conn.close() }
}
