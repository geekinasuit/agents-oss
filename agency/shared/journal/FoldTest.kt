package com.geekinasuit.agency.shared.journal

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class FoldTest {

  @get:Rule val tmp = TemporaryFolder()

  @Test
  fun effectLifecycleFoldsToPendingThenDone() {
    SqliteStore(tmp.newFolder().absolutePath, componentId = "lead").use { store ->
      store.append("effect-intent", buildJsonObject { put("message", "m") }, ORIGIN_SUBSTRATE, idempotencyKey = "k1")
      var state = fold(store.readAll())
      assertEquals(listOf("k1"), state.pendingEffectKeys)
      store.append(
        "effect-done",
        buildJsonObject {
          put("key", "k1")
          put("attempt", 1)
        },
        ORIGIN_SUBSTRATE,
      )
      state = fold(store.readAll())
      assertTrue(state.pendingEffectKeys.isEmpty())
      assertEquals(mapOf("k1" to 1), state.doneKeys)
    }
  }

  @Test
  fun gateReleaseIsAProvenanceCheckNotAKindCheck() {
    SqliteStore(tmp.newFolder().absolutePath, componentId = "lead").use { store ->
      val forged =
        store.append(KIND_GATE_RELEASED, buildJsonObject { put("gateId", "g1") }, origin = ORIGIN_SUBSTRATE)
      store.append(KIND_GATE_RELEASED, buildJsonObject { put("gateId", "g2") }, origin = ORIGIN_AUTH_LAYER)
      val state = fold(store.readAll())
      // The auth-layer release counts; the same KIND from the wrong origin is retained
      // visibly as rejected — distinguishable, never honored, never silently dropped.
      assertEquals(listOf("g2"), state.gateReleases)
      assertEquals(listOf(forged.seq to "g1"), state.rejectedGateReleases)
    }
  }

  @Test
  fun unknownKindsFoldAsNoOps() {
    SqliteStore(tmp.newFolder().absolutePath, componentId = "lead").use { store ->
      store.append("some-future-kind", buildJsonObject { put("x", 1) }, ORIGIN_SUBSTRATE)
      val state = fold(store.readAll())
      assertEquals(JournalState(), state)
    }
  }

  @Test
  fun timerAndMailboxVocabularyFolds() {
    SqliteStore(tmp.newFolder().absolutePath, componentId = "lead").use { store ->
      store.append(
        "timer-armed",
        buildJsonObject {
          put("id", "t1")
          put("fireAtEpochMs", 123L)
          put("action", "a")
        },
        ORIGIN_SUBSTRATE,
      )
      val appended =
        store.append("mailbox-appended", buildJsonObject { put("message", "hi") }, ORIGIN_SUBSTRATE)
      var state = fold(store.readAll())
      assertEquals(listOf("t1"), state.pendingTimers.map { it.id })
      assertEquals(listOf(appended.seq to "hi"), state.undeliveredMail)
      store.append("timer-fired", buildJsonObject { put("id", "t1") }, ORIGIN_SUBSTRATE)
      store.append("mailbox-delivered", buildJsonObject { put("appendSeq", appended.seq) }, ORIGIN_SUBSTRATE)
      state = fold(store.readAll())
      assertTrue(state.pendingTimers.isEmpty())
      assertTrue(state.undeliveredMail.isEmpty())
    }
  }
}
