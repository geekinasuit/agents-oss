package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.lead.GateKinds
import com.geekinasuit.agency.lead.HostKinds
import com.geekinasuit.agency.lead.LeadAuth
import com.geekinasuit.agency.nostr.AuthSpecSigning
import com.geekinasuit.agency.nostr.Bip340
import com.geekinasuit.agency.shared.auth.Principal
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.oneOfOne
import com.geekinasuit.agency.shared.journal.EntrySigner
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SUPPORTED_SCHEMA_VERSION
import com.geekinasuit.agency.shared.journal.SqliteStore
import com.geekinasuit.agency.shared.journal.entryHashFor
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.sql.DriverManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The status tool, run in-process over a journal one store wrote and a spec the real signer signed:
 * it folds under the spec it loads and says which, shows journal text inert, and tells a refusal, an
 * unverifiable journal and a refused entry apart by exit code.
 */
class LeadStatusToolTest {

  @get:Rule val tmp = TemporaryFolder()

  private class Run(val code: Int, val out: String, val err: String)

  private fun run(vararg args: String): Run {
    val out = ByteArrayOutputStream()
    val err = ByteArrayOutputStream()
    val code = LeadStatusTool.run(args.toList(), PrintStream(out, true), PrintStream(err, true))
    return Run(code, out.toString(), err.toString())
  }

  private val specFile: File by lazy {
    val principals = listOf(Principal("operator", "approver", listOf(SchemeKey("bip340", Bip340.xonlyPubkeyHex(OPERATOR_SECRET)))))
    val spec = AuthSpecSigning.sign(principals, oneOfOne("operator"), bytes(ROOT_SECRET), "0".repeat(64))
    tmp.newFile("spec.signed.json").apply { writeText(AuthSpecSigning.toJson(spec)) }
  }

  private val auth: LeadAuth by lazy { loadLeadAuth(specFile.path, ROOT_PUB) }

  private fun status(dir: String, component: String = "lead", root: String = ROOT_PUB) =
    run("--journal", dir, "--component", component, "--spec", specFile.path, "--root", root)

  private fun SqliteStore.openGate(gateId: String, specHash: String = auth.specHash) =
    append(
      HostKinds.GATE_OPENED,
      buildJsonObject {
        put("gateId", gateId)
        put("gateKind", GateKinds.PLAN_APPROVAL)
        put("payloadDigest", "d1")
        put("authSpecHash", specHash)
      },
      ORIGIN_SUBSTRATE,
    )

  @Test
  fun theStatusIsFoldedUnderTheLoadedSpecAndJournalTextIsShownInert() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { s ->
      s.openGate("plan-approval:t1")
      s.append(
        HostKinds.APPROVAL_RECORDED,
        buildJsonObject {
          put("gateId", "plan-approval:t1")
          put("principalId", LeadAuth.UNLISTED_PRINCIPAL_ID)
          put("nonce", "n1")
          put("payloadDigest", "d1")
          put("evidence", JsonObject(emptyMap()))
          put("rejectedReason", "bad\u001b[2J" + Char(0x202e) + "signature")
        },
        ORIGIN_AUTH_LAYER,
      )
    }
    val r = status(dir)
    assertEquals(r.err, 0, r.code)
    assertTrue(r.out, r.out.contains("folded under spec ${auth.specHash}"))
    assertTrue(r.out, r.out.contains("plan-approval:t1 (plan-approval) opened at seq 2 on d1: not released"))
    assertTrue(r.out, r.out.contains("seq 3 on plan-approval:t1 nonce n1: bad\\u001b[2J\\u202esignature"))
    assertFalse("no raw control or bidi character", r.out.contains('\u001b') || r.out.contains(Char(0x202e)))
    assertFalse(r.out, r.out.contains("WARNING"))
  }

  @Test
  fun aGateOpenedUnderAnotherSpecIsWarnedOf() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { it.openGate("plan-approval:t1", specHash = "f".repeat(64)) }
    val r = status(dir)
    assertEquals(r.err, 0, r.code)
    assertTrue(r.out, r.out.contains("WARNING: plan-approval:t1 was opened under spec ${"f".repeat(64)}"))
  }

  @Test
  fun aSpecTheRootDidNotSignIsARefusal() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { it.openGate("plan-approval:t1") }
    val r = status(dir, root = Bip340.xonlyPubkeyHex(OPERATOR_SECRET))
    assertEquals(1, r.code)
    assertTrue(r.err, r.err.contains("the spec did not load"))
    assertEquals("", r.out)
  }

  @Test
  fun noJournalThereIsARefusal() {
    val r = status(File(tmp.root, "absent").path)
    assertEquals(1, r.code)
    assertTrue(r.err, r.err.contains("FileNotFoundException"))
  }

  @Test
  fun aJournalWhoseStoredEntryWasChangedExitsThree() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { it.openGate("plan-approval:t1") }
    DriverManager.getConnection("jdbc:sqlite:$dir/journal.db").use {
      it.createStatement().use { st -> st.executeUpdate("UPDATE journal SET payload = '{}' WHERE seq = 2") }
    }
    val r = status(dir)
    assertEquals(r.err, 3, r.code)
    assertTrue(r.err, r.err.contains("ChainBrokenException") && r.err.contains("does not match"))
  }

  @Test
  fun aJournalThatBreaksTheKeyEpochRuleExitsThree() {
    val dir = tmp.newFolder().path
    // Every entry signed, in epoch 0, the unsigned era.
    SqliteStore(dir, "lead", signer = object : EntrySigner { override fun sign(hashHex: String) = "sig" }).use {}
    val r = status(dir)
    assertEquals(r.err, 3, r.code)
    assertTrue(r.err, r.err.contains("EpochRuleException"))
  }

  @Test
  fun aJournalOfASchemaVersionThisBuildDoesNotReadExitsThree() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { s ->
      val genesis = s.readRaw().single()
      val next = genesis.copy(seq = 2, schemaVersion = SUPPORTED_SCHEMA_VERSION + 1, prevHash = genesis.hash)
      s.appendRaw(next.copy(hash = entryHashFor(next)))
    }
    val r = status(dir)
    assertEquals(r.err, 3, r.code)
    assertTrue(r.err, r.err.contains("JournalVersionException"))
  }

  @Test
  fun aWrongComponentReadsAsAJournalThatDoesNotVerifyAndItsTextIsShownInert() {
    // The fault names the context the journal holds, which its writer chose.
    val dir = tmp.newFolder().path
    SqliteStore(dir, "pod\u001b[2J").use { it.openGate("plan-approval:t1") }
    val r = status(dir, component = "lead")
    assertEquals(r.err, 3, r.code)
    assertTrue(r.err, r.err.contains("ChainBrokenException") && r.err.contains("agency/pod\\u001b[2J/main"))
    assertFalse("no raw escape reaches the terminal", r.err.contains('\u001b'))
  }

  @Test
  fun aPinnedRootThatIsNotAKeyIsARefusal() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { it.openGate("plan-approval:t1") }
    val r = status(dir, root = "not-a-key")
    assertEquals(1, r.code)
    assertTrue(r.err, r.err.contains("could never verify"))
  }

  @Test
  fun anEntryTheFoldRefusesExitsFour() {
    val dir = tmp.newFolder().path
    SqliteStore(dir, "lead").use { it.append(HostKinds.GATE_OPENED, buildJsonObject { put("gateId", "plan-approval:t1") }, ORIGIN_SUBSTRATE) }
    val r = status(dir)
    assertEquals(r.err, 4, r.code)
    assertTrue(r.err, r.err.contains("LeadFoldException"))
  }

  @Test
  fun usageErrorsExitTwoBeforeAnyFileIsRead() {
    // The spec path does not exist: reading it would be a refusal, exit 1.
    val absent = File(tmp.root, "absent").path
    assertEquals(2, run().code)
    assertEquals("missing --root", 2, run("--journal", absent, "--component", "lead", "--spec", absent).code)
    assertEquals("an unknown flag", 2, run("--journal", absent, "--component", "lead", "--spec", absent, "--root", "x", "--follow", "y").code)
    assertEquals("a flag given twice", 2, run("--journal", absent, "--journal", absent, "--component", "lead", "--spec", absent, "--root", "x").code)
  }

  private companion object {
    const val ROOT_SECRET = "000000000000000000000000000000000000000000000000000000000000000b"
    const val OPERATOR_SECRET = "0000000000000000000000000000000000000000000000000000000000000003"
    val ROOT_PUB: String = Bip340.xonlyPubkeyHex(ROOT_SECRET)

    fun bytes(hex: String) = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
  }
}
