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
