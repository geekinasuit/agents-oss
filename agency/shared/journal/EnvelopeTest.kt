package com.geekinasuit.agency.shared.journal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class EnvelopeTest {

  @Test
  fun v2PreimageIsInjectiveAcrossFieldBoundaries() {
    // A bare-separator join would let "a" + "b;c" collide with "a;b" + "c"; the
    // length-prefixed encoding must keep them distinct.
    val h1 = entryHashV2(1, 2, "a", "b;c", null, GENESIS_HASH)
    val h2 = entryHashV2(1, 2, "a;b", "c", null, GENESIS_HASH)
    assertNotEquals(h1, h2)
  }

  @Test
  fun nullIdempotencyKeyIsDistinctFromLiteralNullString() {
    val h1 = entryHashV2(1, 2, "k", "{}", null, GENESIS_HASH)
    val h2 = entryHashV2(1, 2, "k", "{}", "null", GENESIS_HASH)
    assertNotEquals(h1, h2)
  }

  @Test
  fun v3PreimageIsInjectiveAcrossitsNewFieldBoundaries() {
    // Shift bytes between adjacent v3 fields (chainContext|origin) — must not collide.
    val h1 = entryHashV3(1, 3, "k", "ctx;x", "orig", 0, "aa", "bb", "{}", null, GENESIS_HASH)
    val h2 = entryHashV3(1, 3, "k", "ctx", ";xorig", 0, "aa", "bb", "{}", null, GENESIS_HASH)
    assertNotEquals(h1, h2)
  }

  @Test
  fun v3AndV2PreimagesNeverCollideOnSameFields() {
    // Distinct domain tags: the same logical fields must hash differently per version.
    val v2 = entryHashV2(1, 2, "k", "{}", null, GENESIS_HASH)
    val v3 = entryHashV3(1, 2, "k", "", "", 0, "", "", "{}", null, GENESIS_HASH)
    assertNotEquals(v2, v3)
  }

  @Test
  fun commitmentIsDeterministicAndSaltSensitive() {
    val salt1 = newSaltHex()
    val salt2 = newSaltHex()
    assertNotEquals(salt1, salt2)
    assertEquals(64, salt1.length)
    val payload = """{"a":1}"""
    assertEquals(payloadCommitment(salt1, payload), payloadCommitment(salt1, payload))
    assertNotEquals(payloadCommitment(salt1, payload), payloadCommitment(salt2, payload))
    assertNotEquals(payloadCommitment(salt1, payload), payloadCommitment(salt1, """{"a":2}"""))
  }

  @Test
  fun entryHashForDispatchesOnStoredVersion() {
    val v2Entry =
      JournalEntry(1, 2, "k", "", "", 0, "", "", "{}", null, GENESIS_HASH,
        entryHashV2(1, 2, "k", "{}", null, GENESIS_HASH), null)
    assertEquals(v2Entry.hash, entryHashFor(v2Entry))
    val v3Hash = entryHashV3(1, 3, "k", "ctx", ORIGIN_SUBSTRATE, 0, "ab", "cd", "{}", null, GENESIS_HASH)
    val v3Entry =
      JournalEntry(1, 3, "k", "ctx", ORIGIN_SUBSTRATE, 0, "ab", "cd", "{}", null, GENESIS_HASH, v3Hash, null)
    assertEquals(v3Entry.hash, entryHashFor(v3Entry))
  }
}
