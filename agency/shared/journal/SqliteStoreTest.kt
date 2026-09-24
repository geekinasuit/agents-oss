package com.geekinasuit.agency.shared.journal

import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.sql.DriverManager
import kotlinx.serialization.SerializationException
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

  // An unpaired surrogate, and a string that holds one between two ASCII letters.
  private val lone = Char(0xD800)
  private val withLone = "a" + lone + "b"

  @Test
  fun kotlinxPrintsAnUnpairedSurrogateRawAndParsesItsEscapeBack() {
    // The premises of the stored payload form: kotlinx prints the surrogate as it is, and parses a
    // JSON escape of it back into that one char.
    val printed = buildJsonObject { put("m", withLone) }.toString()
    assertEquals("{\"m\":\"" + withLone + "\"}", printed)
    val escaped = "{\"m\":\"a" + Char(0x5C) + "ud800b\"}"
    assertEquals(withLone, Json.parseToJsonElement(escaped).jsonObject["m"]!!.jsonPrimitive.content)
  }

  @Test
  fun kotlinxParsesAnUnpairedSurrogateInAnUnquotedLiteralButNotItsEscape() {
    // Outside a string JSON has no escape: kotlinx reads a bare token holding the surrogate as a
    // literal, and refuses the same token with the surrogate escaped.
    val literal = Json.parseToJsonElement("{\"n\":1" + lone + "}").jsonObject["n"]!!.jsonPrimitive
    assertEquals(false, literal.isString)
    assertEquals("1" + lone, literal.content)
    val escaped = "{\"n\":1" + Char(0x5C) + "ud800}"
    val refused =
      try {
        Json.parseToJsonElement(escaped)
        null
      } catch (e: SerializationException) {
        e
      }
    assertTrue("an escape outside a string does not parse", refused != null)
  }

  @Test
  fun theDriverStoresAnUnpairedSurrogateAsAQuestionMark() {
    // What a TEXT column holds after the driver writes a string with an unpaired surrogate: the
    // driver encodes it as UTF-8 and writes `?` for the surrogate, so no string it reads back holds
    // one.
    DriverManager.getConnection("jdbc:sqlite:${newDir()}/probe.db").use { conn ->
      conn.createStatement().use { it.execute("CREATE TABLE t(v TEXT)") }
      conn.prepareStatement("INSERT INTO t(v) VALUES(?)").use {
        it.setString(1, withLone)
        it.executeUpdate()
      }
      val back = conn.createStatement().use { st ->
        st.executeQuery("SELECT v FROM t").use { rs ->
          rs.next()
          rs.getString(1)
        }
      }
      assertEquals("a?b", back)
    }
  }

  @Test
  fun aPayloadHoldingAnUnpairedSurrogateReadsBackAsItWasAppended() {
    val dir = newDir()
    // In a value, and in a key.
    val payload =
      buildJsonObject {
        put("m", withLone)
        put("${lone}k", "v")
      }
    val appended: JournalEntry
    SqliteStore(dir, componentId = "lead").use { store ->
      appended = store.append("note", payload, origin = ORIGIN_SUBSTRATE)
    }
    // A fresh open reads the stored form back and verifies the chain over it.
    SqliteStore(dir, componentId = "lead").use { store ->
      val stored = store.readAll()[1]
      assertEquals("the stored form is the one the entry was hashed over", appended.payloadJson, stored.payloadJson)
      assertEquals(appended.hash, stored.hash)
      assertEquals(payloadCommitment(stored.salt, stored.payloadJson), stored.payloadCommitment)
      assertTrue("the stored form holds no unpaired surrogate", stored.payloadJson.none { it.isSurrogate() })
      assertEquals(payload, Json.parseToJsonElement(stored.payloadJson).jsonObject)
    }
  }

  @Test
  fun theStoredPayloadFormEscapesOnlyUnpairedSurrogates() {
    val backslash = Char(0x5C)
    // A character outside the Basic Multilingual Plane is a surrogate pair, and stays as it is.
    val astral = String(Character.toChars(0x1F600))
    // Text that spells an escape is not an escape: its backslash is escaped when printed.
    val spelled = backslash + "ud800"
    val lowFirst = Char(0xDC00).toString() + Char(0xD800)
    // Only a high surrogate followed by a low one is a pair: a high right before a pair is unpaired,
    // and so is each of two lows in a row.
    val highBeforePair = astral[0].toString() + astral
    val twoLows = astral[1].toString() + astral[1]
    val payload =
      buildJsonObject {
        put("pair", astral)
        put("spelled", spelled)
        put("lone", withLone)
        put("reversed", lowFirst)
        put("highBeforePair", highBeforePair)
        put("twoLows", twoLows)
        // A key is printed as a string, so a surrogate in one is escaped as in a value.
        put("${lone}k", "v")
      }
    val stored = storedPayloadJson(payload)
    assertTrue("a surrogate pair stays as it is", stored.contains(astral))
    assertTrue(stored.contains("\"a" + backslash + "ud800b\""))
    assertTrue(stored.contains("\"" + backslash + "udc00" + backslash + "ud800\""))
    assertTrue(stored.contains("\"" + backslash + "ud83d" + astral + "\""))
    assertTrue(stored.contains("\"" + backslash + "ude00" + backslash + "ude00\""))
    assertTrue(stored.contains("\"" + backslash + "ud800k\":\"v\""))
    assertTrue("no unpaired surrogate is left", stored.replace(astral, "").none { it.isSurrogate() })
    assertEquals(payload, Json.parseToJsonElement(stored).jsonObject)
  }

  @Test
  fun appendRawRefusesAFieldHoldingAnUnpairedSurrogate() {
    SqliteStore(newDir(), componentId = "lead").use { store ->
      val good = store.append("note", buildJsonObject { put("n", 1) }, origin = ORIGIN_SUBSTRATE)
      val head = store.chainHead()
      // Each field that is text, holding the surrogate in turn. The entry is not hashed again: the
      // refusal comes before anything is written, whatever the hash says.
      val variants =
        listOf(
          "kind" to good.copy(seq = good.seq + 1, kind = withLone),
          "chainContext" to good.copy(seq = good.seq + 1, chainContext = withLone),
          "origin" to good.copy(seq = good.seq + 1, origin = withLone),
          "salt" to good.copy(seq = good.seq + 1, salt = withLone),
          "payloadCommitment" to good.copy(seq = good.seq + 1, payloadCommitment = withLone),
          "payloadJson" to good.copy(seq = good.seq + 1, payloadJson = "{\"m\":\"" + withLone + "\"}"),
          "idempotencyKey" to good.copy(seq = good.seq + 1, idempotencyKey = withLone),
          "prevHash" to good.copy(seq = good.seq + 1, prevHash = withLone),
          "hash" to good.copy(seq = good.seq + 1, hash = withLone),
          "sig" to good.copy(seq = good.seq + 1, sig = withLone),
        )
      for ((field, entry) in variants) {
        val refused =
          try {
            store.appendRaw(entry)
            null
          } catch (e: IllegalArgumentException) {
            e
          }
        assertTrue("$field: an unpaired surrogate is refused", refused != null)
        assertTrue("$field: the refusal names the field", refused!!.message!!.contains(field))
        assertEquals("$field: nothing was written", head, store.chainHead())
      }
    }
  }

  @Test
  fun appendRefusesAPayloadWithAnUnquotedLiteralHoldingAnUnpairedSurrogate() {
    SqliteStore(newDir(), componentId = "lead").use { store ->
      val head = store.chainHead()
      // At the top level, and as a literal in an array in an object.
      val payloads =
        listOf("{\"n\":1" + lone + "}", "{\"a\":[{\"n\":tru" + lone + "}]}").map {
          Json.parseToJsonElement(it).jsonObject
        }
      for (payload in payloads) {
        val refused =
          try {
            store.append("note", payload, origin = ORIGIN_SUBSTRATE)
            null
          } catch (e: IllegalArgumentException) {
            e
          }
        assertTrue("a surrogate no escape can stand for is refused", refused != null)
        assertTrue(refused!!.message!!, refused.message!!.contains("unquoted literal"))
        assertEquals("nothing was written", head, store.chainHead())
      }
    }
  }

  @Test
  fun appendRefusesAnIdempotencyKeyHoldingAnUnpairedSurrogate() {
    SqliteStore(newDir(), componentId = "lead").use { store ->
      val head = store.chainHead()
      val refused =
        try {
          store.append("note", buildJsonObject {}, origin = ORIGIN_SUBSTRATE, idempotencyKey = withLone)
          null
        } catch (e: IllegalArgumentException) {
          e
        }
      assertTrue("an unpaired surrogate in the key is refused", refused != null)
      assertEquals("nothing was written", head, store.chainHead())
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
