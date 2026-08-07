package com.geekinasuit.agency.shared.journal

import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class SqliteStoreTest {

  @get:Rule val tmp = TemporaryFolder()

  private fun newDir(): String = tmp.newFolder().absolutePath

  @Test
  fun freshStoreWritesGenesisDeclaringChainIdentity() {
    SqliteStore(newDir(), componentId = "lead").use { store ->
      val entries = store.readAll()
      assertEquals(1, entries.size)
      val genesis = entries[0]
      assertEquals(1L, genesis.seq)
      assertEquals(KIND_GENESIS, genesis.kind)
      assertEquals(ORIGIN_SUBSTRATE, genesis.origin)
      assertEquals("agency/lead/main/v3", genesis.chainContext)
      val payload = Json.parseToJsonElement(genesis.payloadJson).jsonObject
      assertEquals("lead", payload["componentId"]!!.jsonPrimitive.content)
      assertEquals("main", payload["chainKind"]!!.jsonPrimitive.content)
      assertEquals(JsonNull, payload["ledgerKeyId"])
      assertEquals(1L to genesis.hash, store.chainHead())
    }
  }

  @Test
  fun appendRoundTripsWithSaltedCommitmentAndRequiredOrigin() {
    SqliteStore(newDir(), componentId = "lead").use { store ->
      val payload = buildJsonObject { put("message", "hello") }
      val e = store.append("note", payload, origin = ORIGIN_SUBSTRATE)
      assertEquals(2L, e.seq)
      assertEquals(SUPPORTED_SCHEMA_VERSION, e.schemaVersion)
      assertTrue(e.salt.isNotEmpty())
      assertEquals(payloadCommitment(e.salt, e.payloadJson), e.payloadCommitment)
      assertEquals(null, e.sig) // epoch 0 = unsigned era
      val second = store.append("note", payload, origin = ORIGIN_AUTH_LAYER, idempotencyKey = "k1")
      assertNotEquals(e.salt, second.salt) // fresh salt per entry
      val all = store.readAll()
      assertEquals(3, all.size)
      assertEquals(e.hash, all[1].hash)
      assertEquals("k1", all[2].idempotencyKey)
      assertEquals(ORIGIN_AUTH_LAYER, all[2].origin)
      assertEquals(all[1].hash, all[2].prevHash)
    }
  }

  @Test
  fun freshProcessReopensRefoldsAndContinuesChain() {
    val dir = newDir()
    val headBefore: Pair<Long, String>
    SqliteStore(dir, componentId = "lead").use { store ->
      store.append("note", buildJsonObject { put("n", 1) }, origin = ORIGIN_SUBSTRATE)
      headBefore = store.chainHead()
    }
    // A fresh open of the same directory is the re-embodiment path: verify + upcast + resume.
    SqliteStore(dir, componentId = "lead").use { reopened ->
      assertEquals(headBefore, reopened.chainHead())
      val all = reopened.readAll()
      assertEquals(2, all.size) // genesis + note; no second genesis on non-empty table
      val next = reopened.append("note", buildJsonObject { put("n", 2) }, origin = ORIGIN_SUBSTRATE)
      assertEquals(headBefore.second, next.prevHash)
    }
  }

  @Test
  fun componentDirectoryIsOwnerOnlyOnPosix() {
    val dir = newDir()
    SqliteStore(dir, componentId = "lead").use {}
    val path = File(dir).toPath()
    try {
      val perms = Files.getPosixFilePermissions(path)
      assertEquals(
        setOf(
          PosixFilePermission.OWNER_READ,
          PosixFilePermission.OWNER_WRITE,
          PosixFilePermission.OWNER_EXECUTE,
        ),
        perms,
      )
    } catch (_: UnsupportedOperationException) {
      // Non-POSIX filesystem: scoping is best-effort by design; nothing to assert here.
    }
  }
}
