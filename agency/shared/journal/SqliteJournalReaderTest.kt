package com.geekinasuit.agency.shared.journal

import java.io.File
import java.io.FileNotFoundException
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The read-only reader over a store another instance writes: it sees what the writer commits, in a
 * writer that is open, closed, or in a directory it cannot write; it creates nothing; and it
 * verifies against the component it is told, not the one the file claims.
 */
class SqliteJournalReaderTest {

  @get:Rule val tmp = TemporaryFolder()

  private fun payload(n: Int) = buildJsonObject { put("n", JsonPrimitive(n)) }

  private fun SqliteStore.appendN(n: Int) = append("test.event", payload(n), ORIGIN_SUBSTRATE)

  @Test
  fun aMissingJournalIsRefusedAndNothingIsCreated() {
    val dir = File(tmp.root, "absent")
    assertThrows(FileNotFoundException::class.java) { SqliteJournalReader(dir.path, "lead") }
    assertFalse("the directory is not created", dir.exists())
  }

  @Test
  fun whileTheWriterIsOpenEachReadSeesWhatItHasCommitted() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { writer ->
      writer.appendN(1)
      SqliteJournalReader(dir, "lead").use { reader ->
        assertEquals(2, reader.readAll().size)
        val cursor = reader.readAfter(ChainCursor.START).cursor
        writer.appendN(2)
        writer.appendN(3)
        assertEquals("a later read sees later commits", 4, reader.readAll().size)
        val tail = reader.readAfter(cursor)
        assertEquals(listOf(3L, 4L), tail.entries.map { it.seq })
        assertEquals(writer.chainHead(), reader.chainHead())
      }
    }
  }

  @Test
  fun afterTheWriterClosesTheJournalStillReads() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { it.appendN(1) }
    SqliteJournalReader(dir, "lead").use { reader -> assertEquals(2, reader.readAll().size) }
  }

  @Test
  fun aDirectoryTheReaderCannotWriteIsRefusedWhenItOpens() {
    // With no writer open, SQLite must create the WAL's shared-memory index beside the database.
    val dir = tmp.newFolder()
    SqliteStore(dir.path, "lead").use { it.appendN(1) }
    Files.setPosixFilePermissions(dir.toPath(), PosixFilePermissions.fromString("r-x------"))
    try {
      assertThrows(java.sql.SQLException::class.java) { SqliteJournalReader(dir.path, "lead") }
    } finally {
      Files.setPosixFilePermissions(dir.toPath(), PosixFilePermissions.fromString("rwx------"))
    }
  }

  @Test
  fun readingLeavesTheJournalAsItWas() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { it.appendN(1) }
    val db = File(dir, "journal.db")
    val before = db.readBytes()
    SqliteJournalReader(dir, "lead").use { reader ->
      reader.readAll()
      reader.chainHead()
    }
    assertTrue("the database file is unchanged", before.contentEquals(db.readBytes()))
  }

  @Test
  fun aReaderThatClosesLastDoesNotCheckpointTheWritersAppendsIntoTheDatabase() {
    // Only a connection that can write checkpoints the WAL into journal.db as the last to close.
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { it.appendN(1) }
    val db = File(dir, "journal.db")
    val reader = SqliteJournalReader(dir, "lead")
    try {
      SqliteStore(dir, "lead").use { writer ->
        writer.appendN(2)
        writer.appendN(3)
      }
      val before = db.readBytes()
      assertEquals(4, reader.readAll().size)
      reader.close()
      assertTrue("the reader did not write the database", before.contentEquals(db.readBytes()))
    } finally {
      reader.close()
    }
  }

  @Test
  fun anotherComponentsJournalDoesNotVerify() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "pod").use { it.appendN(1) }
    SqliteJournalReader(dir, "lead").use { reader ->
      assertThrows(ChainBrokenException::class.java) { reader.readAll() }
    }
  }

  @Test
  fun aCursorTheJournalNoLongerHoldsIsRefused() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { it.appendN(1) }
    SqliteJournalReader(dir, "lead").use { reader ->
      val stale = ChainCursor(9, "0".repeat(64), 0)
      assertThrows(ChainBrokenException::class.java) { reader.readAfter(stale) }
    }
  }
}
