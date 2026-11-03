package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.nostr.Bip340
import com.geekinasuit.agency.nostr.Bip340ApprovalVerifier
import com.geekinasuit.agency.nostr.FakeRelay
import com.geekinasuit.agency.nostr.GateOpenNotice
import com.geekinasuit.agency.nostr.Nip59
import com.geekinasuit.agency.nostr.NoticeEncoding
import com.geekinasuit.agency.nostr.NostrEvent
import com.geekinasuit.agency.nostr.RecipientKey
import com.geekinasuit.agency.nostr.RelayConfig
import com.geekinasuit.agency.nostr.RelayConnection
import com.geekinasuit.agency.nostr.decodeApproval
import com.geekinasuit.agency.nostr.encodeGateOpenNotice
import com.geekinasuit.agency.nostr.serialize
import com.geekinasuit.agency.shared.auth.ApprovalEvidence
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.io.StringReader
import java.security.MessageDigest
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The approver's tool over scripted relays: the inbox shows each notice the lead sent once, and only
 * the lead's; approve signs only after the digest is typed back, and what it publishes is an approval
 * the lead can open, decode and verify.
 */
class ApprovalToolTest {

  @get:Rule val tmp = TemporaryFolder()

  private class Run(val code: Int, val out: String, val err: String)

  private fun run(relays: List<FakeRelay>, input: String, vararg args: String): Run {
    var next = 0
    return runWith({ keyFile -> RelayConnection(RelayConfig(relays[next++].url, readSecretKeyFile(keyFile))) }, input, *args)
  }

  private fun runWith(connect: (keyFile: String) -> RelayConnection, input: String, vararg args: String): Run {
    val out = ByteArrayOutputStream()
    val err = ByteArrayOutputStream()
    val code =
      ApprovalTool.run(args.toList(), BufferedReader(StringReader(input)), PrintStream(out, true), PrintStream(err, true)) { _, keyFile ->
        connect(keyFile)
      }
    return Run(code, out.toString(), err.toString())
  }

  private fun keyFile() = tmp.newFile().apply { writeText(OPERATOR_SECRET) }

  private fun flags(vararg extra: String) =
    arrayOf("--relay", "ws://unused", "--key-file", keyFile().path, "--lead", LEAD_PUB, "--auth", "none", "--wait", "5") + extra

  /** Serve the REQ with [events] then EOSE. */
  private fun FakeRelay.replays(vararg events: NostrEvent) = serve { session ->
    session.nextClientText(5_000) ?: error("no REQ")
    for (e in events) session.sendText("[\"EVENT\",\"notices\"," + e.serialize() + "]")
    session.sendText("[\"EOSE\",\"notices\"]")
    session.nextClientText(5_000)
  }

  /** Accept one EVENT, hand it to [published], and answer OK. */
  private fun FakeRelay.accepts(published: LinkedBlockingQueue<String>) = serve { session ->
    val frame = session.nextClientText(5_000) ?: error("no EVENT")
    published.put(frame)
    val id = Json.parseToJsonElement(frame).jsonArray[1].jsonObject.getValue("id").jsonPrimitive.content
    session.sendText("[\"OK\",\"$id\",true,\"\"]")
  }

  @Test
  fun theInboxShowsEachOfTheLeadsNoticesOnceAndNoOneElses() =
    FakeRelay().use { relay ->
      // Another author's notice under a nonce of its own, so only the author check can drop it.
      val forged = GateOpenNotice("plan-approval:t2", sha256Hex("forged"), "f".repeat(64), "forged")
      relay.replays(noticeWrap(NOTICE), noticeWrap(NOTICE), noticeWrap(forged, from = OTHER_SECRET))
      val r = run(listOf(relay), "", "inbox", *flags())
      assertEquals(r.err, 0, r.code)
      assertEquals("one notice, though the lead's came twice", 1, Regex("gate:").findAll(r.out).count())
      assertTrue(r.out.contains(NOTICE.artifact))
      assertFalse("another author's notice is not shown", r.out.contains(forged.nonce))
    }

  @Test
  fun aRelayThatNeverFinishesItsReplayIsARefusalNotAnEmptyInbox() =
    FakeRelay().use { relay ->
      relay.serve { session ->
        session.nextClientText(5_000) ?: error("no REQ")
        session.nextClientText(5_000)
      }
      val r = run(listOf(relay), "", "inbox", *flags().also { it[it.indexOf("--wait") + 1] = "1" })
      assertEquals(1, r.code)
      assertTrue(r.err, r.err.contains("did not finish sending its stored notices"))
      assertFalse(r.out.contains("no gate-open notices"))
    }

  @Test
  fun anUnreachableRelayIsARefusalThatSaysWhy() {
    val r = runWith({ throw java.net.ConnectException("refused") }, "", "inbox", *flags().also { it[it.indexOf("--wait") + 1] = "1" })
    assertEquals(1, r.code)
    assertTrue(r.err, r.err.contains("did not finish") && r.err.contains("ConnectException"))
    assertFalse(r.out.contains("no gate-open notices"))
  }

  @Test
  fun theRestatedCountsMatchWhatIsShown() =
    FakeRelay().use { inbox ->
      val artifact = "A\rB\n" + String(Character.toChars(0xE0041))
      inbox.replays(noticeWrap(GateOpenNotice("plan-approval:t1", sha256Hex(artifact), "c".repeat(64), artifact)))
      val r = run(listOf(inbox), "no\n", "approve", *flags("--nonce", "c".repeat(64)))
      assertEquals(1, r.code)
      assertTrue(r.out, r.out.contains("artifact of 2 line(s), 5 character(s)"))
    }

  @Test
  fun approveSignsOnlyAfterTheDigestIsTypedAndTheLeadCanVerifyWhatItSent() =
    FakeRelay().use { inbox ->
      FakeRelay().use { outbox ->
        inbox.replays(noticeWrap(NOTICE))
        val published = LinkedBlockingQueue<String>()
        outbox.accepts(published)
        val r = run(listOf(inbox, outbox), NOTICE.payloadDigest.take(8) + "\n", "approve", *flags("--nonce", NOTICE.nonce))
        assertEquals(r.err, 0, r.code)
        assertTrue(r.out, r.out.contains("the relay accepted it"))
        val wrap = eventOf(checkNotNull(published.poll(5, TimeUnit.SECONDS)))
        // What the lead's ingress subscribes on: a gift wrap tagged to the lead.
        assertEquals(Nip59.GIFT_WRAP_KIND, wrap.kind)
        assertTrue(wrap.tags.toString(), wrap.tags.contains(listOf("p", LEAD_PUB)))
        val carrier = checkNotNull(decodeApproval(checkNotNull(Nip59.unwrap(bytes(LEAD_SECRET), wrap))))
        assertEquals(NOTICE.nonce, carrier.nonce)
        val evidence = ApprovalEvidence.fromJson(carrier.evidence)
        assertEquals(Bip340.xonlyPubkeyHex(OPERATOR_SECRET), evidence.publicKey)
        assertTrue(Bip340ApprovalVerifier.verifies(evidence.schemeId, evidence.publicKey, evidence.signature, evidence.signedPreimage!!))
      }
    }

  @Test
  fun aWrongConfirmationSignsAndSendsNothing() =
    FakeRelay().use { inbox ->
      inbox.replays(noticeWrap(NOTICE))
      // Only the inbox's relay is given: a publish would need a second connection and fail the run.
      val r = run(listOf(inbox), "deadbeef\n", "approve", *flags("--nonce", NOTICE.nonce))
      assertEquals(1, r.code)
      assertTrue(r.err, r.err.contains("not approved"))
      assertFalse(r.out.contains("accepted"))
    }

  @Test
  fun aRelaysRejectionReasonIsShownEscaped() =
    FakeRelay().use { inbox ->
      FakeRelay().use { outbox ->
        inbox.replays(noticeWrap(NOTICE))
        outbox.serve { session ->
          val frame = session.nextClientText(5_000) ?: error("no EVENT")
          val id = Json.parseToJsonElement(frame).jsonArray[1].jsonObject.getValue("id").jsonPrimitive.content
          session.sendText("[\"OK\",\"$id\",false,\"blocked: \\u001b[2K\\rapproved: the relay accepted it\"]")
        }
        val r = run(listOf(inbox, outbox), NOTICE.payloadDigest.take(8) + "\n", "approve", *flags("--nonce", NOTICE.nonce))
        assertEquals(1, r.code)
        assertTrue(r.err, r.err.contains("rejected"))
        assertFalse("no raw escape reaches the terminal", r.err.contains('\u001b') || r.err.contains('\r'))
      }
    }

  @Test
  fun aNonceWithNoNoticeIsARefusal() =
    FakeRelay().use { inbox ->
      inbox.replays(noticeWrap(NOTICE))
      val r = run(listOf(inbox), "", "approve", *flags("--nonce", "m".repeat(64)))
      assertEquals(1, r.code)
      assertTrue(r.err, r.err.contains("no notice for nonce"))
    }

  @Test
  fun aControlCharacterInTheArtifactIsShownEscaped() =
    FakeRelay().use { relay ->
      val hostile = "line one\u001b[2Jcleared?"
      relay.replays(noticeWrap(GateOpenNotice("plan-approval:t1", sha256Hex(hostile), "h".repeat(64), hostile)))
      val r = run(listOf(relay), "", "inbox", *flags())
      assertEquals(r.err, 0, r.code)
      assertFalse("no raw escape reaches the terminal", r.out.contains('\u001b'))
      assertTrue(r.out, r.out.contains("\\u001b[2Jcleared?"))
    }

  @Test
  fun aBidiOverrideOrLineSeparatorInTheArtifactIsShownEscaped() =
    FakeRelay().use { relay ->
      val hostile = "approve " + Char(0x202e) + "evil" + Char(0x2066) + "x" + Char(0x2028) + "y" + Char(0x200b)
      relay.replays(noticeWrap(GateOpenNotice("plan-approval:t1", sha256Hex(hostile), "h".repeat(64), hostile)))
      val r = run(listOf(relay), "", "inbox", *flags())
      assertEquals(r.err, 0, r.code)
      for (cp in listOf(0x202e, 0x2066, 0x2028, 0x200b)) assertFalse("U+%04x is escaped".format(cp), r.out.contains(Char(cp)))
      assertTrue(r.out, r.out.contains("approve \\u202eevil\\u2066x\\u2028y\\u200b"))
    }

  @Test
  fun formatCharactersAboveTheBmpAreShownEscaped() =
    FakeRelay().use { relay ->
      // Unicode tag characters (U+E0041 'A', U+E0042 'B') render as nothing; U+1D173 is a musical
      // format control. Each is two UTF-16 chars, and must be judged as one code point.
      val hidden = String(Character.toChars(0xE0041)) + String(Character.toChars(0xE0042)) + String(Character.toChars(0x1D173))
      val artifact = "visible$hidden."
      relay.replays(noticeWrap(GateOpenNotice("plan-approval:t1", sha256Hex(artifact), "h".repeat(64), artifact)))
      val r = run(listOf(relay), "", "inbox", *flags())
      assertEquals(r.err, 0, r.code)
      assertFalse("no raw tag or format code point reaches the terminal", r.out.codePoints().anyMatch { it > 0xFFFF })
      assertTrue(r.out, r.out.contains("visible\\u{e0041}\\u{e0042}\\u{1d173}."))
    }

  @Test
  fun variationSelectorsAndUnassignedIgnorablesCannotHideText() =
    FakeRelay().use { relay ->
      // "hi" smuggled as one variation selector per byte, plus reserved default-ignorables and a
      // blank braille cell.
      val smuggled = "hi".map { String(Character.toChars(0xE0100 + it.code - 0x10)) }.joinToString("") +
        Char(0xFE0F) + String(Character.toChars(0xE0080)) + Char(0x2065) + Char(0xFFF0) + Char(0x3164) + Char(0x2800)
      val artifact = "plan$smuggled."
      relay.replays(noticeWrap(GateOpenNotice("plan-approval:t1", sha256Hex(artifact), "h".repeat(64), artifact)))
      val r = run(listOf(relay), "", "inbox", *flags())
      assertEquals(r.err, 0, r.code)
      val shownArtifact = r.out.substringAfter("----- artifact -----\n").substringBefore("\n----- end -----")
      assertTrue(shownArtifact, shownArtifact.startsWith("plan\\u{e0158}\\u{e0159}\\ufe0f\\u{e0080}\\u2065\\ufff0\\u3164\\u2800."))
    }

  @Test
  fun usageErrorsExitTwoBeforeAnyConnection() {
    assertEquals(2, run(emptyList(), "").code)
    assertEquals(2, run(emptyList(), "", "approve", "--nonce").code)
    assertEquals(2, run(emptyList(), "", "inbox", "--nonce", "x").code)
    // With no relays given, any connection attempt would fail the run some other way.
    assertEquals("approve without --nonce", 2, run(emptyList(), "", "approve", *flags()).code)
    val noRelay = flags().toMutableList().apply { subList(0, 2).clear() }.toTypedArray()
    assertEquals("missing --relay", 2, run(emptyList(), "", "inbox", *noRelay).code)
    assertEquals("not ws or wss", 2, run(emptyList(), "", "inbox", *flags().also { it[1] = "https://relay.invalid" }).code)
    for (w in listOf("0", "601", "ten")) {
      assertEquals("--wait $w", 2, run(emptyList(), "", "inbox", *flags().also { it[it.indexOf("--wait") + 1] = w }).code)
    }
    assertEquals("bad --lead", 2, run(emptyList(), "", "inbox", *flags().also { it[it.indexOf("--lead") + 1] = "x" }).code)
    assertEquals("unknown --auth", 2, run(emptyList(), "", "inbox", *flags().also { it[it.indexOf("--auth") + 1] = "nip-42" }).code)
    for (flag in listOf("--key-file", "--lead")) {
      val without = flags().toMutableList().apply { val i = indexOf(flag); subList(i, i + 2).clear() }.toTypedArray()
      assertEquals("missing $flag", 2, run(emptyList(), "", "inbox", *without).code)
    }
  }

  private fun noticeWrap(notice: GateOpenNotice, from: String = LEAD_SECRET): NostrEvent {
    val encoding =
      encodeGateOpenNotice(bytes(from), RecipientKey.of(Bip340.xonlyPubkeyHex(OPERATOR_SECRET)), notice, 1_700_000_000, 1_699_999_000, AUX, AUX)
    return (encoding as NoticeEncoding.Encoded).event
  }

  private fun eventOf(frame: String): NostrEvent {
    val o = Json.parseToJsonElement(frame).jsonArray[1].jsonObject
    return NostrEvent(
      id = o.getValue("id").jsonPrimitive.content,
      pubkey = o.getValue("pubkey").jsonPrimitive.content,
      createdAt = o.getValue("created_at").jsonPrimitive.long,
      kind = o.getValue("kind").jsonPrimitive.int,
      tags = o.getValue("tags").jsonArray.map { t -> t.jsonArray.map { it.jsonPrimitive.content } },
      content = o.getValue("content").jsonPrimitive.content,
      sig = o.getValue("sig").jsonPrimitive.content,
    )
  }

  private companion object {
    const val OPERATOR_SECRET = "0000000000000000000000000000000000000000000000000000000000000003"
    const val LEAD_SECRET = "0000000000000000000000000000000000000000000000000000000000000005"
    const val OTHER_SECRET = "0000000000000000000000000000000000000000000000000000000000000007"
    val LEAD_PUB: String = Bip340.xonlyPubkeyHex(LEAD_SECRET)
    val AUX = "0".repeat(64)
    const val ARTIFACT = "Plan: wire the reader.\nThen stop."
    val NOTICE = GateOpenNotice("plan-approval:t1", sha256Hex(ARTIFACT), "n".repeat(64), ARTIFACT)

    fun bytes(hex: String) = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    fun sha256Hex(s: String): String =
      MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
  }
}
