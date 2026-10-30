package com.geekinasuit.agency.shared.journal

import java.sql.DriverManager
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class VerifyUpcastTest {

  @get:Rule val tmp = TemporaryFolder()

  private fun newDir(): String = tmp.newFolder().absolutePath

  /** Crafts a hash-valid v3 entry chained onto [prevHash] — the raw-writer path for red-path fixtures. */
  private fun v3Entry(
    seq: Long,
    kind: String,
    chainContext: String,
    prevHash: String,
    origin: String = ORIGIN_SUBSTRATE,
    keyEpoch: Int = 0,
    sig: String? = null,
    schemaVersion: Int = 3,
    payloadJson: String = "{}",
  ): JournalEntry {
    val salt = newSaltHex()
    val commitment = payloadCommitment(salt, payloadJson)
    val hash =
      entryHashV3(seq, schemaVersion, kind, chainContext, origin, keyEpoch, salt, commitment, payloadJson, null, prevHash)
    return JournalEntry(seq, schemaVersion, kind, chainContext, origin, keyEpoch, salt, commitment, payloadJson, null, prevHash, hash, sig)
  }

  @Test
  fun inPlaceTamperBreaksTheChain() {
    val dir = newDir()
    SqliteStore(dir, componentId = "lead").use { store ->
      store.append("note", buildJsonObject { put("n", 1) }, origin = ORIGIN_SUBSTRATE)
      store.append("note", buildJsonObject { put("n", 2) }, origin = ORIGIN_SUBSTRATE)
    }
    DriverManager.getConnection("jdbc:sqlite:$dir/journal.db").use { c ->
      c.createStatement().use { st -> st.executeUpdate("UPDATE journal SET payload='{\"n\":99}' WHERE seq=2") }
    }
    SqliteStore(dir, componentId = "lead").use { store ->
      assertThrows(ChainBrokenException::class.java) { store.readAll() }
    }
  }

  @Test
  fun truncationIsTheDocumentedBlindSpotAndTheRetainedHeadCatchesIt() {
    val dir = newDir()
    val headBefore: Pair<Long, String>
    SqliteStore(dir, componentId = "lead").use { store ->
      store.append("note", buildJsonObject { put("n", 1) }, origin = ORIGIN_SUBSTRATE)
      store.append("note", buildJsonObject { put("n", 2) }, origin = ORIGIN_SUBSTRATE)
      headBefore = store.chainHead()
    }
    DriverManager.getConnection("jdbc:sqlite:$dir/journal.db").use { c ->
      c.createStatement().use { st -> st.executeUpdate("DELETE FROM journal WHERE seq=3") }
    }
    SqliteStore(dir, componentId = "lead").use { store ->
      // Standalone verification PASSES — a prefix of a valid chain is a valid chain. This
      // assertion exists to keep the blind spot documented, not to bless it.
      assertEquals(2, store.readAll().size)
      // The retained head is what catches truncation (AGENCY-007 anchoring hook).
      assertNotEquals(headBefore, store.chainHead())
      assertEquals(headBefore.first - 1, store.chainHead().first)
    }
  }

  @Test
  fun newerThanSupportedVersionIsRefusedNotMisread() {
    val dir = newDir()
    SqliteStore(dir, componentId = "lead").use { store ->
      val head = store.chainHead()
      store.appendRaw(v3Entry(head.first + 1, "note", store.chainContext, head.second, schemaVersion = 4))
      assertThrows(JournalVersionException::class.java) { store.readAll() }
    }
  }

  @Test
  fun foreignChainContextIsAChainBreakNotAnAdoption() {
    val dir = newDir()
    SqliteStore(dir, componentId = "lead").use { store ->
      val head = store.chainHead()
      store.appendRaw(v3Entry(head.first + 1, "note", "agency/other/main/v3", head.second))
      assertThrows(ChainBrokenException::class.java) { store.readAll() }
    }
  }

  @Test
  fun epochZeroEntriesMustBeUnsigned() {
    val dir = newDir()
    SqliteStore(dir, componentId = "lead").use { store ->
      val head = store.chainHead()
      store.appendRaw(v3Entry(head.first + 1, "note", store.chainContext, head.second, sig = "ff"))
      assertThrows(EpochRuleException::class.java) { store.readAll() }
    }
  }

  @Test
  fun epochOnlyAdvancesThroughTheReservedTransitionKind() {
    val dir = newDir()
    SqliteStore(dir, componentId = "lead").use { store ->
      val head = store.chainHead()
      store.appendRaw(v3Entry(head.first + 1, "note", store.chainContext, head.second, keyEpoch = 1, sig = "ff"))
      assertThrows(EpochRuleException::class.java) { store.readAll() }
    }
  }

  @Test
  fun epochTransitionThenSignedEntriesSatisfyPresenceRules() {
    val dir = newDir()
    SqliteStore(dir, componentId = "lead").use { store ->
      var head = store.chainHead()
      store.appendRaw(
        v3Entry(head.first + 1, KIND_KEY_EPOCH_STARTED, store.chainContext, head.second, keyEpoch = 1, sig = "aa")
      )
      head = store.chainHead()
      store.appendRaw(v3Entry(head.first + 1, "note", store.chainContext, head.second, keyEpoch = 1, sig = "bb"))
      val all = store.readAll() // presence rules pass; cryptographic verification arrives with active signing
      assertEquals(1, all.last().keyEpoch)
    }
  }

  @Test
  fun legacyJournalUpcastsWithAbsentByVersionCommitments() {
    val dir = newDir()
    val v1Payload = """{"msg":"do-it","key":"k1"}"""
    val v1Hash = entryHashV2(1, 1, "effect-intent", v1Payload, "k1", GENESIS_HASH)
    val v2Payload = """{"key":"k1","attempt":1}"""
    val v2Hash = entryHashV2(2, 2, "effect-done", v2Payload, null, v1Hash)
    SqliteStore(dir, componentId = "lead").use { store ->
      // Rebuild the table as a pure legacy (v1/v2) journal the way pre-v3 writers wrote
      // it: no genesis, v2 preimages, empty v3 columns. The delete runs after the store
      // opens — an empty table at open time auto-mints a fresh v3 genesis.
      DriverManager.getConnection("jdbc:sqlite:$dir/journal.db").use { c ->
        c.createStatement().use { st -> st.executeUpdate("DELETE FROM journal") }
      }
      store.appendRaw(JournalEntry(1, 1, "effect-intent", "", "", 0, "", "", v1Payload, "k1", GENESIS_HASH, v1Hash, null))
      store.appendRaw(JournalEntry(2, 2, "effect-done", "", "", 0, "", "", v2Payload, null, v1Hash, v2Hash, null))
      val all = store.readAll()
      assertEquals(2, all.size)
      for (e in all) {
        assertEquals(SUPPORTED_SCHEMA_VERSION, e.schemaVersion)
        assertEquals("unknown", e.origin)
        assertEquals(0, e.keyEpoch)
        assertEquals(store.chainContext, e.chainContext)
        assertEquals("", e.salt) // absent-by-version: commitments are never retro-minted
        assertEquals("", e.payloadCommitment)
      }
      // The v1→v2 payload migration: msg renamed, origin defaulted.
      assertTrue(all[0].payloadJson.contains("\"message\""))
      assertTrue(!all[0].payloadJson.contains("\"msg\""))
      assertTrue(all[0].payloadJson.contains("\"origin\""))
    }
  }

  @Test
  fun aTailReadReturnsWhatAFullReadReturnsAfterTheCursor() {
    SqliteStore(newDir(), componentId = "lead").use { store ->
      store.append("note", buildJsonObject { put("n", 1) }, origin = ORIGIN_SUBSTRATE)
      val first = store.readAfter(ChainCursor.START)
      assertEquals(store.readAll(), first.entries)
      val head = store.chainHead()
      assertEquals(ChainCursor(head.first, head.second, 0), first.cursor)

      store.append("note", buildJsonObject { put("n", 2) }, origin = ORIGIN_SUBSTRATE)
      store.append("note", buildJsonObject { put("n", 3) }, origin = ORIGIN_SUBSTRATE)
      val tail = store.readAfter(first.cursor)
      assertEquals(store.readAll().drop(first.entries.size), tail.entries)
      assertEquals(store.readAfter(ChainCursor.START).cursor, tail.cursor)
    }
  }

  @Test
  fun anEmptyTailLeavesTheCursorWhereItWas() {
    SqliteStore(newDir(), componentId = "lead").use { store ->
      val cursor = store.readAfter(ChainCursor.START).cursor
      val tail = store.readAfter(cursor)
      assertEquals(emptyList<JournalEntry>(), tail.entries)
      assertEquals(cursor, tail.cursor)
    }
  }

  @Test
  fun aTamperedEntryInTheTailFailsAsAFullReadFails() {
    val dir = newDir()
    val cursor: ChainCursor
    SqliteStore(dir, componentId = "lead").use { store ->
      cursor = store.readAfter(ChainCursor.START).cursor
      store.append("note", buildJsonObject { put("n", 1) }, origin = ORIGIN_SUBSTRATE)
    }
    DriverManager.getConnection("jdbc:sqlite:$dir/journal.db").use { c ->
      c.createStatement().use { st -> st.executeUpdate("UPDATE journal SET payload='{\"n\":99}' WHERE seq=2") }
    }
    SqliteStore(dir, componentId = "lead").use { store ->
      assertSameFailure(ChainBrokenException::class.java, { store.readAll() }, { store.readAfter(cursor) })
    }
  }

  @Test
  fun aRewriteAtTheCursorFailsTheTailThoughTheRewrittenChainIsValid() {
    val dir = newDir()
    val cursor: ChainCursor
    SqliteStore(dir, componentId = "lead").use { store ->
      store.append("note", buildJsonObject { put("n", 1) }, origin = ORIGIN_SUBSTRATE)
      cursor = store.readAfter(ChainCursor.START).cursor
    }
    DriverManager.getConnection("jdbc:sqlite:$dir/journal.db").use { c ->
      c.createStatement().use { st -> st.executeUpdate("DELETE FROM journal WHERE seq=2") }
    }
    SqliteStore(dir, componentId = "lead").use { store ->
      val genesis = store.chainHead()
      store.appendRaw(v3Entry(2, "note", store.chainContext, genesis.second, payloadJson = "{\"n\":99}"))
      store.append("note", buildJsonObject { put("n", 2) }, origin = ORIGIN_SUBSTRATE)
      // A rewritten chain is a valid chain, so a read from genesis passes. The cursor holds the hash
      // the rewrite replaced, as a retained head does.
      assertEquals(3, store.readAll().size)
      val x = assertThrows(ChainBrokenException::class.java) { store.readAfter(cursor) }
      assertEquals("journal hash chain broken at seq=2: the cursor's hash is not the stored hash", x.message)
    }
  }

  @Test
  fun aTruncationBelowTheCursorFailsTheTailEvenAfterTheChainRegrows() {
    val dir = newDir()
    val cursor: ChainCursor
    SqliteStore(dir, componentId = "lead").use { store ->
      store.append("note", buildJsonObject { put("n", 1) }, origin = ORIGIN_SUBSTRATE)
      store.append("note", buildJsonObject { put("n", 2) }, origin = ORIGIN_SUBSTRATE)
      cursor = store.readAfter(ChainCursor.START).cursor
    }
    DriverManager.getConnection("jdbc:sqlite:$dir/journal.db").use { c ->
      c.createStatement().use { st -> st.executeUpdate("DELETE FROM journal WHERE seq>=2") }
    }
    SqliteStore(dir, componentId = "lead").use { store ->
      // The regrown chain is valid and shorter than the cursor, so no entry after it exists to fail
      // a link check.
      store.append("note", buildJsonObject { put("n", 9) }, origin = ORIGIN_SUBSTRATE)
      assertEquals(2, store.readAll().size)
      val x = assertThrows(ChainBrokenException::class.java) { store.readAfter(cursor) }
      assertEquals("journal hash chain broken at seq=3: the cursor's entry is not in the store", x.message)
    }
  }

  @Test
  fun aCursorPastTheHeadIsRefused() {
    SqliteStore(newDir(), componentId = "lead").use { store ->
      val x = assertThrows(ChainBrokenException::class.java) { store.readAfter(ChainCursor(1000, "f".repeat(64), 0)) }
      assertEquals("journal hash chain broken at seq=1000: the cursor's entry is not in the store", x.message)
    }
  }

  @Test
  fun aDeletionJustAfterTheCursorFailsTheTail() {
    val dir = newDir()
    val cursor: ChainCursor
    SqliteStore(dir, componentId = "lead").use { store ->
      cursor = store.readAfter(ChainCursor.START).cursor
      store.append("note", buildJsonObject { put("n", 1) }, origin = ORIGIN_SUBSTRATE)
      store.append("note", buildJsonObject { put("n", 2) }, origin = ORIGIN_SUBSTRATE)
    }
    DriverManager.getConnection("jdbc:sqlite:$dir/journal.db").use { c ->
      c.createStatement().use { st -> st.executeUpdate("DELETE FROM journal WHERE seq=2") }
    }
    SqliteStore(dir, componentId = "lead").use { store ->
      assertSameFailure(ChainBrokenException::class.java, { store.readAll() }, { store.readAfter(cursor) })
    }
  }

  @Test
  fun anInPlaceChangeAtTheCursorIsTheTailsBlindSpotAndAFullReadCatchesIt() {
    val dir = newDir()
    val cursor: ChainCursor
    SqliteStore(dir, componentId = "lead").use { store ->
      store.append("note", buildJsonObject { put("n", 1) }, origin = ORIGIN_SUBSTRATE)
      cursor = store.readAfter(ChainCursor.START).cursor
      store.append("note", buildJsonObject { put("n", 2) }, origin = ORIGIN_SUBSTRATE)
    }
    DriverManager.getConnection("jdbc:sqlite:$dir/journal.db").use { c ->
      c.createStatement().use { st -> st.executeUpdate("UPDATE journal SET payload='{\"n\":99}' WHERE seq=2") }
    }
    SqliteStore(dir, componentId = "lead").use { store ->
      // The stored hash at the cursor is unchanged, so the tail links and passes. This assertion
      // keeps the blind spot documented, not blessed.
      assertEquals(1, store.readAfter(cursor).entries.size)
      assertThrows(ChainBrokenException::class.java) { store.readAll() }
    }
  }

  @Test
  fun theCursorCarriesTheKeyEpochIntoTheTail() {
    SqliteStore(newDir(), componentId = "lead").use { store ->
      var head = store.chainHead()
      store.appendRaw(
        v3Entry(head.first + 1, KIND_KEY_EPOCH_STARTED, store.chainContext, head.second, keyEpoch = 1, sig = "aa")
      )
      val cursor = store.readAfter(ChainCursor.START).cursor
      assertEquals(1, cursor.keyEpoch)
      head = store.chainHead()
      store.appendRaw(v3Entry(head.first + 1, "note", store.chainContext, head.second, keyEpoch = 1, sig = "bb"))
      val tail = store.readAfter(cursor)
      assertEquals(1, tail.entries.single().keyEpoch)
      assertEquals(1, tail.cursor.keyEpoch)
    }
  }

  @Test
  fun aCursorWhoseEpochIsNotTheStoredEpochIsRefused() {
    SqliteStore(newDir(), componentId = "lead").use { store ->
      val cursor = store.readAfter(ChainCursor.START).cursor
      val head = store.chainHead()
      store.appendRaw(v3Entry(head.first + 1, "note", store.chainContext, head.second, keyEpoch = 1, sig = "ff"))
      // With the cursor's epoch taken on trust, the tail would accept an entry readAll refuses.
      assertThrows(EpochRuleException::class.java) { store.readAll() }
      val x = assertThrows(EpochRuleException::class.java) { store.readAfter(cursor.copy(keyEpoch = 1)) }
      assertEquals("key-epoch rule violated at seq=1: the cursor's epoch 1 is not the stored epoch 0", x.message)
    }
  }

  @Test
  fun aCursorOnALegacyEntryIsHeldToTheEpochTheChainIsIn() {
    val dir = newDir()
    val v1Payload = """{"msg":"do-it","key":"k1"}"""
    val v1Hash = entryHashV2(1, 1, "effect-intent", v1Payload, "k1", GENESIS_HASH)
    val v2Payload = """{"key":"k1","attempt":1}"""
    val v2Hash = entryHashV2(2, 2, "effect-done", v2Payload, null, v1Hash)
    SqliteStore(dir, componentId = "lead").use { store ->
      DriverManager.getConnection("jdbc:sqlite:$dir/journal.db").use { c ->
        c.createStatement().use { st -> st.executeUpdate("DELETE FROM journal") }
      }
      store.appendRaw(JournalEntry(1, 1, "effect-intent", "", "", 0, "", "", v1Payload, "k1", GENESIS_HASH, v1Hash, null))
      store.appendRaw(JournalEntry(2, 2, "effect-done", "", "", 0, "", "", v2Payload, null, v1Hash, v2Hash, null))
      val cursor = store.readAfter(ChainCursor.START).cursor
      assertEquals(ChainCursor(2, v2Hash, 0), cursor)
      store.appendRaw(v3Entry(3, "note", store.chainContext, v2Hash, keyEpoch = 1, sig = "ff"))
      assertThrows(EpochRuleException::class.java) { store.readAll() }
      val x = assertThrows(EpochRuleException::class.java) { store.readAfter(cursor.copy(keyEpoch = 1)) }
      assertEquals("key-epoch rule violated at seq=2: the cursor's epoch 1 is not the stored epoch 0", x.message)
    }
  }

  @Test
  fun aCursorOnALegacyEntryAfterAnEpochStepCarriesThatEpoch() {
    SqliteStore(newDir(), componentId = "lead").use { store ->
      var head = store.chainHead()
      store.appendRaw(
        v3Entry(head.first + 1, KIND_KEY_EPOCH_STARTED, store.chainContext, head.second, keyEpoch = 1, sig = "aa")
      )
      head = store.chainHead()
      val legacyPayload = """{"key":"k1","attempt":1}"""
      val legacyHash = entryHashV2(head.first + 1, 2, "effect-done", legacyPayload, null, head.second)
      store.appendRaw(
        JournalEntry(head.first + 1, 2, "effect-done", "", "", 0, "", "", legacyPayload, null, head.second, legacyHash, null)
      )
      // The epoch rules skip the legacy entry, so the chain is still in epoch 1 after it.
      val cursor = store.readAfter(ChainCursor.START).cursor
      assertEquals(ChainCursor(head.first + 1, legacyHash, 1), cursor)
      store.appendRaw(v3Entry(cursor.seq + 1, "note", store.chainContext, legacyHash, keyEpoch = 1, sig = "bb"))
      assertEquals(store.readAll().last(), store.readAfter(cursor).entries.single())
      assertThrows(EpochRuleException::class.java) { store.readAfter(cursor.copy(keyEpoch = 0)) }
    }
  }

  @Test
  fun anEpochRuleBrokenInTheTailFailsAsAFullReadFails() {
    SqliteStore(newDir(), componentId = "lead").use { store ->
      val cursor = store.readAfter(ChainCursor.START).cursor
      val head = store.chainHead()
      store.appendRaw(v3Entry(head.first + 1, "note", store.chainContext, head.second, keyEpoch = 1, sig = "ff"))
      assertSameFailure(EpochRuleException::class.java, { store.readAll() }, { store.readAfter(cursor) })
    }
  }

  @Test
  fun aChainFaultIsReportedAheadOfAnEarlierUnsupportedVersionInBothReads() {
    SqliteStore(newDir(), componentId = "lead").use { store ->
      val cursor = store.readAfter(ChainCursor.START).cursor
      val head = store.chainHead()
      val newer = v3Entry(head.first + 1, "note", store.chainContext, head.second, schemaVersion = 4)
      store.appendRaw(newer)
      store.appendRaw(v3Entry(newer.seq + 1, "note", store.chainContext, prevHash = "0".repeat(64)))
      assertSameFailure(ChainBrokenException::class.java, { store.readAll() }, { store.readAfter(cursor) })
    }
  }

  /** Both reads throw [type], with the same message, which names the seq. */
  private fun <T : RuntimeException> assertSameFailure(type: Class<T>, full: () -> Any, tail: () -> Any) {
    val a = assertThrows(type) { full() }
    val b = assertThrows(type) { tail() }
    assertEquals(a.message, b.message)
  }

  @Test
  fun v3BornChainMustBeginWithGenesis() {
    val dir = newDir()
    SqliteStore(dir, componentId = "lead").use {}
    DriverManager.getConnection("jdbc:sqlite:$dir/journal.db").use { c ->
      c.createStatement().use { st -> st.executeUpdate("DELETE FROM journal") }
    }
    SqliteStore(dir, componentId = "lead").use { store ->
      // Reopening an empty table auto-wrote a fresh genesis; clear it so a crafted
      // non-genesis seq-1 entry is what verification sees.
      DriverManager.getConnection("jdbc:sqlite:$dir/journal.db").use { c ->
        c.createStatement().use { st -> st.executeUpdate("DELETE FROM journal") }
      }
      store.appendRaw(v3Entry(1, "note", store.chainContext, GENESIS_HASH))
      assertThrows(ChainBrokenException::class.java) { store.readAll() }
    }
  }
}
