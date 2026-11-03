package com.geekinasuit.agency.shared.journal

import java.sql.Connection

// The reads of a journal table, shared by the writing store and the read-only reader. Each runs
// inside whatever transaction its caller holds; the caller ends it.

/** The stored entries with seq above [afterSeq], in seq order, unverified. */
internal fun readRowsAfter(conn: Connection, afterSeq: Long): List<JournalEntry> {
  val out = mutableListOf<JournalEntry>()
  conn.prepareStatement(
    """SELECT seq, schema_version, kind, chain_context, origin, key_epoch, salt,
         payload_commitment, payload, idempotency_key, prev_hash, hash, sig
       FROM journal WHERE seq > ? ORDER BY seq"""
  ).use { ps ->
    ps.setLong(1, afterSeq)
    ps.executeQuery().use { rs ->
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

/** The entry at [from] must still be stored with [from]'s hash, and [from]'s key epoch must be the
 * chain's epoch after it: the stored epoch of the last v3 entry at or before it, or 0 when there
 * is none, since the epoch rules skip older entries. Without this, a store truncated below the
 * cursor reads as an empty tail until it grows past the cursor's seq, and a cursor's epoch would
 * set where the tail's epoch rules start. */
internal fun requireCursorStored(conn: Connection, from: ChainCursor) {
  if (from == ChainCursor.START) return
  val hash =
    conn.prepareStatement("SELECT hash FROM journal WHERE seq = ?").use { ps ->
      ps.setLong(1, from.seq)
      ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
    }
  if (hash == null) throw ChainBrokenException(from.seq, "the cursor's entry is not in the store")
  if (hash != from.hash) throw ChainBrokenException(from.seq, "the cursor's hash is not the stored hash")
  val epoch =
    conn.prepareStatement(
      "SELECT key_epoch FROM journal WHERE seq <= ? AND schema_version >= 3 ORDER BY seq DESC LIMIT 1"
    ).use { ps ->
      ps.setLong(1, from.seq)
      ps.executeQuery().use { rs -> if (rs.next()) rs.getInt(1) else 0 }
    }
  if (epoch != from.keyEpoch) {
    throw EpochRuleException(from.seq, "the cursor's epoch ${from.keyEpoch} is not the stored epoch $epoch")
  }
}

/** The last stored entry's seq and hash, or (0, [GENESIS_HASH]) for an empty table. */
internal fun readHead(conn: Connection): Pair<Long, String> =
  conn.createStatement().use { st ->
    st.executeQuery("SELECT seq, hash FROM journal ORDER BY seq DESC LIMIT 1").use { rs ->
      if (rs.next()) rs.getLong(1) to rs.getString(2) else 0L to GENESIS_HASH
    }
  }
