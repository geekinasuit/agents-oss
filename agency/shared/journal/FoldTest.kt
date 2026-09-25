package com.geekinasuit.agency.shared.journal

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonUnquotedLiteral
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

  @Test
  @OptIn(ExperimentalSerializationApi::class)
  fun anEntryTheFoldCannotReadFailsItNamingTheEntryButNotItsText() {
    // Each payload holds the marker Qx7, which no refusal's own text contains. An unquoted literal
    // is stored as its raw text, so the last payload is stored as {"id":Qx7 marker}, which is not
    // JSON.
    val cases: List<Triple<String, JsonObject, String>> =
      listOf(
        Triple(
          "effect-done",
          buildJsonObject {
            put("key", "k1")
            put("attempt", "Qx7")
          },
          "payload field 'attempt' is not an integer",
        ),
        Triple(
          "mailbox-delivered",
          buildJsonObject { put("appendSeq", "Qx7") },
          "payload field 'appendSeq' is not an integer",
        ),
        Triple(
          "timer-fired",
          buildJsonObject { put("id", buildJsonObject { put("Qx7", 1) }) },
          "payload field 'id' is missing or not a JSON scalar",
        ),
        Triple(
          "timer-fired",
          buildJsonObject { put("id", JsonUnquotedLiteral("Qx7 marker")) },
          "payload is not valid JSON",
        ),
      )
    val mismatches =
      cases.mapNotNull { (kind, payload, reason) ->
        SqliteStore(tmp.newFolder().absolutePath, componentId = "lead").use { store ->
          val entry = store.append(kind, payload, ORIGIN_SUBSTRATE)
          val expected = "journal fold failed at seq=${entry.seq} kind='$kind': $reason"
          val thrown = runCatching { fold(store.readAll()) }.exceptionOrNull()
          if (thrown is JournalFoldException && thrown.message == expected) null
          else "expected JournalFoldException($expected), got $thrown"
        }
      }
    assertEquals(emptyList<String>(), mismatches)
  }

  @Test
  fun aLongThatOpensAQuoteAndEndsInsideItsDigitsIsRefusedNamingTheField() {
    // The lexer behind JsonPrimitive.long reads past the end of "1 looking for the closing quote,
    // and throws StringIndexOutOfBoundsException rather than IllegalArgumentException.
    SqliteStore(tmp.newFolder().absolutePath, componentId = "lead").use { store ->
      val payload = buildJsonObject { put("appendSeq", "\"1") }
      val entry = store.append("mailbox-delivered", payload, ORIGIN_SUBSTRATE)
      val thrown = runCatching { fold(store.readAll()) }.exceptionOrNull()
      assertTrue("expected a JournalFoldException, got $thrown", thrown is JournalFoldException)
      assertEquals(
        "journal fold failed at seq=${entry.seq} kind='mailbox-delivered': " +
          "payload field 'appendSeq' is not an integer",
        thrown!!.message,
      )
    }
  }
}
