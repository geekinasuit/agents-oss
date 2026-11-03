package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.nostr.AuthSpecSigning
import com.geekinasuit.agency.nostr.Bip340
import com.geekinasuit.agency.nostr.Bip340ApprovalVerifier
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.SpecLoadResult
import com.geekinasuit.agency.shared.auth.loadAuthorizationSpec
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** The operator's spec tool, run in-process: the pubkey it prints is the one the signed file loads
 * under, and a refusal or a usage error exits non-zero with a reason and writes nothing. */
class AuthSpecToolTest {

  @get:Rule val tmp = TemporaryFolder()

  private val rootSecret = "000000000000000000000000000000000000000000000000000000000000000b"
  private val operatorPub = Bip340.xonlyPubkeyHex("0000000000000000000000000000000000000000000000000000000000000003")

  private class Run(val code: Int, val out: String, val err: String)

  private fun run(vararg args: String): Run {
    val out = ByteArrayOutputStream()
    val err = ByteArrayOutputStream()
    val code = AuthSpecTool.run(args.toList(), PrintStream(out, true), PrintStream(err, true))
    return Run(code, out.toString().trim(), err.toString().trim())
  }

  private fun keyFile() = tmp.newFile("root.key").apply { writeText("$rootSecret\n") }

  private fun specFile(pub: String = operatorPub) =
    tmp.newFile().apply {
      writeText(
        """{"principals":[{"principalId":"operator","role":"approver","keys":[{"schemeId":"bip340","publicKey":"$pub"}]}],
           |"quorum":{"type":"signer","principalId":"operator"}}"""
          .trimMargin()
      )
    }

  @Test
  fun theSignedFileLoadsUnderThePubkeyTheToolPrints() {
    val key = keyFile()
    val pubkey = run("pubkey", "--root-key-file", key.path)
    assertEquals(0, pubkey.code)
    val out = File(tmp.root, "spec.signed.json")
    val signed = run("sign", "--spec", specFile().path, "--root-key-file", key.path, "--out", out.path)
    assertEquals(signed.err, 0, signed.code)
    val spec = checkNotNull(AuthSpecSigning.fromJson(out.readText()))
    val loaded = loadAuthorizationSpec(spec, SchemeKey("bip340", pubkey.out), Bip340ApprovalVerifier)
    assertTrue("$loaded", loaded is SpecLoadResult.Loaded)
    assertFalse("the key is never printed", (signed.out + signed.err + pubkey.err).contains(rootSecret))
  }

  @Test
  fun aSpecThatWouldNotLoadIsRefusedAndNothingIsWritten() {
    val out = File(tmp.root, "spec.signed.json")
    val r = run("sign", "--spec", specFile(pub = operatorPub.uppercase()).path, "--root-key-file", keyFile().path, "--out", out.path)
    assertEquals(1, r.code)
    assertTrue(r.err, r.err.contains("could never verify"))
    assertFalse(out.exists())
  }

  @Test
  fun anExistingOutputIsNotOverwritten() {
    val out = tmp.newFile("spec.signed.json").apply { writeText("keep") }
    val r = run("sign", "--spec", specFile().path, "--root-key-file", keyFile().path, "--out", out.path)
    assertEquals(1, r.code)
    assertEquals("keep", out.readText())
  }

  @Test
  fun usageErrorsExitTwo() {
    assertEquals(2, run().code)
    assertEquals(2, run("sign", "--spec").code)
    assertEquals(2, run("sign", "--bogus", "x").code)
    assertEquals(2, run("delete").code)
    assertEquals("a flag the command does not take", 2, run("pubkey", "--root-key-file", "a", "--spec", "b").code)
    assertEquals("a flag given twice", 2, run("pubkey", "--root-key-file", "a", "--root-key-file", "b").code)
  }

  @Test
  fun aMissingOrMalformedKeyFileIsARefusal() {
    assertEquals(1, run("pubkey", "--root-key-file", File(tmp.root, "absent").path).code)
    for (text in listOf("not a key", "0".repeat(32) + " " + "0".repeat(31) + "b", "﻿$rootSecret")) {
      val bad = tmp.newFile().apply { writeText(text) }
      assertEquals(text, 1, run("pubkey", "--root-key-file", bad.path).code)
    }
  }

  @Test
  fun aKeyOutsideTheCurvesRangeIsARefusalNotACrash() {
    // 64 hex digits, but zero, and then the all-ones value above the curve order: the native would
    // throw for either. The tool refuses both with a reason.
    for (text in listOf("0".repeat(64), "f".repeat(64))) {
      val key = tmp.newFile().apply { writeText(text) }
      val pubkey = run("pubkey", "--root-key-file", key.path)
      assertEquals(1, pubkey.code)
      assertTrue(pubkey.err, pubkey.err.contains("not a secp256k1 secret key"))
      val out = File(tmp.root, "out-${text.first()}.json")
      assertEquals(1, run("sign", "--spec", specFile().path, "--root-key-file", key.path, "--out", out.path).code)
      assertFalse(out.exists())
    }
  }
}
