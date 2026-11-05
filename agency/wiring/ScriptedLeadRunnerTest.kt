package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.lead.HostKinds
import com.geekinasuit.agency.lead.LeadKinds
import com.geekinasuit.agency.nostr.ApprovalSigning
import com.geekinasuit.agency.nostr.AuthSpecSigning
import com.geekinasuit.agency.nostr.Bip340
import com.geekinasuit.agency.nostr.FakeRelay
import com.geekinasuit.agency.nostr.GateOpenNotice
import com.geekinasuit.agency.nostr.GiftWrapEncoding
import com.geekinasuit.agency.nostr.Nip59
import com.geekinasuit.agency.nostr.NostrEvent
import com.geekinasuit.agency.nostr.RecipientKey
import com.geekinasuit.agency.nostr.RelayConfig
import com.geekinasuit.agency.nostr.RelayConnection
import com.geekinasuit.agency.nostr.SecretKeyHex
import com.geekinasuit.agency.nostr.encodeApproval
import com.geekinasuit.agency.nostr.parseEvent
import com.geekinasuit.agency.nostr.serialize
import com.geekinasuit.agency.nostr.waitUntil
import com.geekinasuit.agency.lead.LeadAuth
import com.geekinasuit.agency.nostr.Bip340ApprovalVerifier
import com.geekinasuit.agency.shared.auth.AllowList
import com.geekinasuit.agency.shared.auth.Principal
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.oneOfOne
import com.geekinasuit.agency.shared.journal.JournalEntry
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
import com.geekinasuit.agency.shared.journal.SqliteJournalReader
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The scripted runner in-process: what it refuses before it starts, and one ticket taken through both
 * of its gates over scripted relays, the approver's side signed as the approval tool signs it, with a
 * restart between the gates whose replayed approval adds nothing.
 */
class ScriptedLeadRunnerTest {

  @get:Rule val tmp = TemporaryFolder()

  private val specFile: File by lazy { signedSpec(ROOT_SECRET) }

  private fun signedSpec(rootSecret: String): File {
    val principals = listOf(Principal("operator", "approver", listOf(SchemeKey("bip340", APPROVER_PUB))))
    val spec = AuthSpecSigning.sign(principals, oneOfOne("operator"), bytes(rootSecret), "0".repeat(64))
    return tmp.newFile().apply { writeText(AuthSpecSigning.toJson(spec)) }
  }

  private val leadKeyFile: File by lazy { tmp.newFile("lead.key").apply { writeText("$LEAD_SECRET\n") } }

  private fun args(dir: File, spec: File = specFile, vararg extra: String): List<String> =
    listOf(
      "--journal", dir.path,
      "--component", "lead",
      "--ticket-file", File(dir, "tickets.txt").path,
      "--spec", spec.path,
      "--relay", "ws://127.0.0.1:1",
      "--lead-key-file", leadKeyFile.path,
      "--auth", "none",
    ) + extra

  private class Started(val code: Int, val err: String)

  /** Run the runner to its end on this thread, with no relay expected and a stop it never needs. */
  private fun runToEnd(pinnedRoot: String, args: List<String>): Started {
    val err = ByteArrayOutputStream()
    val code =
      ScriptedLeadRunner.run(pinnedRoot, args, PrintStream(err, true), { _, _, _ -> error("no relay expected") }) {
        error("the lead was not to start")
      }
    return Started(code, err.toString())
  }

  @Test
  fun theDefaultBuildCarriesNoPinnedRoot() {
    val pin = javaClass.classLoader.getResourceAsStream(ScriptedLeadRunner.PINNED_ROOT_RESOURCE)
    assertTrue("the resource is on the classpath", pin != null)
    assertEquals("", pin!!.use { it.readBytes().toString(Charsets.UTF_8) })
  }

  @Test
  fun aBinaryWithoutAPinnedRootRefusesBeforeItOpensAnything() {
    val dir = File(tmp.root, "journal")
    val r = runToEnd("", args(dir))
    assertEquals(r.err, 1, r.code)
    assertTrue(r.err, r.err.contains("built without a pinned root"))
    assertFalse("no journal was created", dir.exists())
  }

  @Test
  fun aPinnedRootThatIsNotAKeyRefuses() {
    val r = runToEnd("not-a-key", args(tmp.newFolder()))
    assertEquals(r.err, 1, r.code)
  }

  @Test
  fun aSpecAnotherRootSignedRefuses() {
    val r = runToEnd(ROOT_PUB, args(tmp.newFolder(), spec = signedSpec(OTHER_SECRET)))
    assertEquals(r.err, 1, r.code)
    assertTrue(r.err, r.err.contains("the spec did not load"))
  }

  @Test
  fun gatesAreAnnouncedToTheAllowListsBip340KeysOnly() {
    fun authOf(vararg keys: SchemeKey) =
      LeadAuth(AllowList(listOf(Principal("operator", "approver", keys.toList()))), Bip340ApprovalVerifier, oneOfOne("operator"))
    val other = Bip340.xonlyPubkeyHex(OTHER_SECRET)
    assertEquals(
      setOf(RecipientKey.of(APPROVER_PUB)),
      ScriptedLeadRunner.approversOf(authOf(SchemeKey("bip340", APPROVER_PUB), SchemeKey("ed25519", other))),
    )
    val none = assertThrows(IllegalArgumentException::class.java) { ScriptedLeadRunner.approversOf(authOf(SchemeKey("ed25519", other))) }
    assertTrue(none.message, none.message!!.contains("names no bip340 key"))
  }

  @Test
  fun aLeadKeyFileThatDoesNotReadRefusesBeforeTheJournalOpens() {
    val dir = File(tmp.root, "journal")
    val missingKey = File(tmp.root, "absent.key").path
    val r = runToEnd(ROOT_PUB, args(dir).map { if (it == leadKeyFile.path) missingKey else it })
    assertEquals(r.err, 1, r.code)
    assertFalse("no journal was created", dir.exists())
  }

  @Test
  fun aCognitionCannotBeChosen() {
    val r = runToEnd(ROOT_PUB, args(tmp.newFolder(), specFile, "--cognition", "claude"))
    assertEquals(r.err, 2, r.code)
    assertTrue(r.err, r.err.contains("'--cognition' is not a flag"))
  }

  @Test
  fun anIngressThatEndsStopsTheLeadWithExitFour() {
    val dir = tmp.newFolder()
    File(dir, "tickets.txt").writeText("t1\n")
    val err = ByteArrayOutputStream()
    FakeRelay().use { noticeRelay ->
      noticeRelay.serve { session -> while (session.nextClientText(30_000) != null) Unit }
      val connect = { use: ScriptedLeadRunner.RelayUse, _: String, _: String ->
        if (use == ScriptedLeadRunner.RelayUse.APPROVALS) throw AssertionError("the approvals connection broke")
        RelayConnection(RelayConfig(noticeRelay.url, SecretKeyHex.ofHexString(LEAD_SECRET)))
      }
      var code: Int? = null
      val runner = thread { code = ScriptedLeadRunner.run(ROOT_PUB, args(dir), PrintStream(err, true), connect) {} }
      runner.join(20_000)
      assertFalse("the lead stopped on its own", runner.isAlive)
      assertEquals(err.toString(), 4, code)
      assertTrue(err.toString(), err.toString().contains("the approvals connection broke"))
    }
  }

  @Test
  fun aRelayThatRefusesEverySubscriptionLeavesTheLeadUpAndSaysSoOnStderrAndInTheJournal() {
    val dir = tmp.newFolder()
    File(dir, "tickets.txt").writeText("t1\n")
    val err = ByteArrayOutputStream()
    val refusing = List(ApprovalIngress.REPORT_AFTER_FAILURES + 3) { FakeRelay() }
    FakeRelay().use { noticeRelay ->
      noticeRelay.serve { session -> while (session.nextClientText(30_000) != null) Unit }
      for (relay in refusing) {
        relay.serve { session ->
          session.nextClientText(30_000) ?: error("no REQ")
          session.sendText("[\"CLOSED\",\"${ApprovalIngress.SUBSCRIPTION_ID}\",\"restricted: members only\"]")
          session.nextClientText(30_000)
        }
      }
      val attempts = AtomicInteger()
      val connect = { use: ScriptedLeadRunner.RelayUse, _: String, _: String ->
        val url = if (use == ScriptedLeadRunner.RelayUse.APPROVALS) refusing[attempts.getAndIncrement()].url else noticeRelay.url
        RelayConnection(RelayConfig(url, SecretKeyHex.ofHexString(LEAD_SECRET)))
      }
      val stop = LinkedBlockingQueue<() -> Unit>()
      var code: Int? = null
      val runner = thread { code = ScriptedLeadRunner.run(ROOT_PUB, args(dir), PrintStream(err, true), connect) { stop.put(it) } }
      assertTrue(err.toString(), waitUntil(30_000) { err.toString().contains("approvals are not arriving") })
      assertTrue("the lead stays up", runner.isAlive)
      assertTrue(err.toString(), err.toString().contains("restricted"))
      fun journaled() = entries(dir).count { it.kind == HostKinds.ESCALATED && "approvals are not arriving" in it.payloadJson }
      assertTrue("the outage reaches the journal", waitUntil(5_000) { journaled() == 1 })
      stop.poll(5, TimeUnit.SECONDS)!!.invoke()
      runner.join(20_000)
      assertFalse("the lead stopped when told to", runner.isAlive)
      assertEquals(err.toString(), 0, code)
    }
    refusing.forEach { it.close() }
  }

  @Test
  fun aLeadStoppedBySigtermExitsWithItsStatusAndLeavesNothingInTmp() {
    val dir = tmp.newFolder()
    File(dir, "tickets.txt").writeText("t1\n")
    // The test's classpath carries the default build's empty pin, so a directory ahead of it carries
    // this test's: the same shadowing the runner's KDoc warns a launch command can do.
    val pinDir = tmp.newFolder()
    File(pinDir, ScriptedLeadRunner.PINNED_ROOT_RESOURCE).apply { parentFile.mkdirs() }.writeText(ROOT_PUB)
    val java = File(System.getProperty("java.home"), "bin/java").path
    val classpath = pinDir.path + File.pathSeparator + System.getProperty("java.class.path")
    val log = File(tmp.root, "runner.log")
    // Its own tmp, where the JDBC and secp256k1 jars extract their native libraries, to be deleted at
    // the JVM's exit.
    val processTmp = tmp.newFolder()
    val process =
      ProcessBuilder(
          listOf(java, "-Djava.io.tmpdir=${processTmp.path}", "-cp", classpath, ScriptedLeadRunner::class.java.name) +
            args(dir)
        )
        .redirectErrorStream(true)
        .redirectOutput(log)
        .start()
    try {
      val deadline = System.nanoTime() + 30_000_000_000L
      // A journal the runner is still creating does not read yet; that is "not started", not a fault.
      fun started() = try {
        entries(dir).any { it.kind == HostKinds.RUN_STARTED }
      } catch (_: Exception) {
        false
      }
      while (process.isAlive && !started() && System.nanoTime() < deadline) Thread.sleep(100)
      assertTrue("the lead started; log: ${log.readText()}", started())
      assertTrue("the lead is running; log: ${log.readText()}", process.isAlive)
      process.destroy() // SIGTERM
      assertTrue("the lead stopped", process.waitFor(30, TimeUnit.SECONDS))
      assertEquals("log: ${log.readText()}", 143, process.exitValue())
      // 143 is the JVM's own status on SIGTERM, hook or none. What the hook adds is the close: the
      // journal runs in WAL mode, and SQLite removes the -wal file only when its last connection
      // closes, so a store the hook did not close leaves it behind.
      assertFalse("the hook closed the journal", File(dir, "journal.db-wal").exists())
      assertEquals("the JVM's exit work ran", emptyList<String>(), processTmp.list()!!.toList())
      assertFalse("no stack trace; log: ${log.readText()}", log.readText().contains("Exception"))
    } finally {
      process.destroyForcibly()
    }
  }

  /** One run of the runner on its own thread, over its own pair of scripted relays. */
  private inner class Running(dir: File, replay: List<NostrEvent> = emptyList()) : AutoCloseable {
    val notices = LinkedBlockingQueue<NostrEvent>()
    val approvals = LinkedBlockingQueue<NostrEvent>()
    private val noticeRelay = FakeRelay()
    private val approvalRelay = FakeRelay()
    private val err = ByteArrayOutputStream()
    private val stop = LinkedBlockingQueue<() -> Unit>()
    @Volatile private var code: Int? = null
    private val runner: Thread

    init {
      // Answer each published event with an OK, and hand it to the test.
      noticeRelay.serve { session ->
        while (true) {
          val frame = session.nextClientText(60_000) ?: return@serve
          val element = Json.parseToJsonElement(frame).jsonArray
          if (element[0].jsonPrimitive.content != "EVENT") continue
          val event = checkNotNull(parseEvent(element[1].toString())) { "not an event: $frame" }
          session.sendText("[\"OK\",\"${event.id}\",true,\"\"]")
          notices.put(event)
        }
      }
      // Replay [replay] as stored events, then EOSE, then send each approval the test queues.
      approvalRelay.serve { session ->
        val req = session.nextClientText(10_000) ?: error("no REQ")
        check(req.startsWith("[\"REQ\",\"${ApprovalIngress.SUBSCRIPTION_ID}\",")) { "unexpected first frame $req" }
        for (e in replay) session.sendText(eventFrame(e))
        session.sendText("[\"EOSE\",\"${ApprovalIngress.SUBSCRIPTION_ID}\"]")
        while (true) {
          val e = approvals.poll(60, TimeUnit.SECONDS) ?: return@serve
          session.sendText(eventFrame(e))
        }
      }
      val connect = { use: ScriptedLeadRunner.RelayUse, _: String, _: String ->
        val url = if (use == ScriptedLeadRunner.RelayUse.NOTICES) noticeRelay.url else approvalRelay.url
        RelayConnection(RelayConfig(url, SecretKeyHex.ofHexString(LEAD_SECRET)))
      }
      runner = thread(name = "scripted-lead-under-test") {
        code = ScriptedLeadRunner.run(ROOT_PUB, args(dir), PrintStream(err, true), connect) { stop.put(it) }
      }
    }

    /** The next gate-open notice, opened and decoded as the approver's tool does. */
    fun nextNotice(): GateOpenNotice {
      val wrap = checkNotNull(notices.poll(20, TimeUnit.SECONDS)) { "no notice; stderr: $err" }
      val rumor = checkNotNull(Nip59.unwrap(bytes(APPROVER_SECRET), wrap)) { "the notice is not wrapped to the approver" }
      return checkNotNull(ApprovalSigning.decodeNotice(rumor, LEAD_PUB)) { "not a notice from the lead" }
    }

    /** Stop the runner and return its exit code. */
    fun stopAndWait(): Int {
      checkNotNull(stop.poll(10, TimeUnit.SECONDS)) { "the runner never started; stderr: $err" }()
      runner.join(20_000)
      assertFalse("the runner ended", runner.isAlive)
      return checkNotNull(code) { "the runner set no exit code; stderr: $err" }
    }

    override fun close() {
      noticeRelay.close()
      approvalRelay.close()
    }
  }

  @Test
  fun aTicketPassesBothGatesOverTheRelayAcrossARestartAndTheReplayedApprovalAddsNothing() {
    val dir = tmp.newFolder()
    File(dir, "tickets.txt").writeText("t1\n")

    val planApproval: NostrEvent
    val commitNotice: GateOpenNotice
    Running(dir).use { first ->
      val planNotice = first.nextNotice()
      assertEquals("plan-approval:t1", planNotice.gateId)
      planApproval = approve(planNotice)
      first.approvals.put(planApproval)
      commitNotice = first.nextNotice()
      assertEquals("commit-approval:t1", commitNotice.gateId)
      assertEquals(0, first.stopAndWait())
    }
    assertEquals("not done before the commit approval", 0, entries(dir).count { it.kind == LeadKinds.TICKET_DONE })

    // The restarted lead's relay replays the plan approval first, as a relay does on a new
    // subscription; one subscription delivers in order, so the ticket is done only after it is handled.
    Running(dir, replay = listOf(planApproval)).use { second ->
      second.approvals.put(approve(commitNotice))
      val deadline = System.nanoTime() + 20_000_000_000L
      while (entries(dir).none { it.kind == LeadKinds.TICKET_DONE } && System.nanoTime() < deadline) Thread.sleep(100)
      assertEquals(0, second.stopAndWait())
      assertTrue("no further notice: both gates were announced before", second.notices.isEmpty())
    }

    assertTrue(
      "the ingress was closed with the run",
      Thread.getAllStackTraces().keys.none { it.name == "approval-ingress" && it.isAlive },
    )
    val rows = entries(dir)
    assertEquals("done", 1, rows.count { it.kind == LeadKinds.TICKET_DONE })
    assertEquals("one approval per gate: the replay adds none", 2, rows.count { it.kind == HostKinds.APPROVAL_RECORDED })
    assertEquals("one release per gate", 2, rows.count { it.kind == KIND_GATE_RELEASED })
    val runs = rows.filter { it.kind == HostKinds.RUN_STARTED }.map { Json.parseToJsonElement(it.payloadJson).jsonObject }
    assertEquals(2, runs.size)
    for (run in runs) {
      assertEquals("no model ran", "scripted", run.getValue("cognition").jsonPrimitive.content)
      assertEquals("scripted/none", run.getValue("capabilityDesc").jsonPrimitive.content)
    }
    val pods = rows.filter { it.kind == HostKinds.POD_SPAWNED }.map { Json.parseToJsonElement(it.payloadJson).jsonObject }
    assertTrue(pods.isNotEmpty())
    assertTrue(pods.all { it.getValue("model").jsonPrimitive.content == "scripted" })
  }

  private fun entries(dir: File): List<JournalEntry> = SqliteJournalReader(dir.path, "lead").use { it.readAll() }

  /** The approver's approval of [notice], signed and wrapped to the lead as the approval tool does. */
  private fun approve(notice: GateOpenNotice): NostrEvent {
    val carrier = ApprovalSigning.sign(notice, bytes(APPROVER_SECRET), AUX)
    val encoding = encodeApproval(bytes(APPROVER_SECRET), RecipientKey.of(LEAD_PUB), carrier, 1_700_000_000, 1_699_999_000, AUX, AUX)
    return (encoding as GiftWrapEncoding.Wrapped).event
  }

  private fun eventFrame(e: NostrEvent) = "[\"EVENT\",\"${ApprovalIngress.SUBSCRIPTION_ID}\"," + e.serialize() + "]"

  private companion object {
    const val ROOT_SECRET = "0000000000000000000000000000000000000000000000000000000000000002"
    const val APPROVER_SECRET = "0000000000000000000000000000000000000000000000000000000000000003"
    const val LEAD_SECRET = "0000000000000000000000000000000000000000000000000000000000000005"
    const val OTHER_SECRET = "0000000000000000000000000000000000000000000000000000000000000007"
    val ROOT_PUB: String = Bip340.xonlyPubkeyHex(ROOT_SECRET)
    val APPROVER_PUB: String = Bip340.xonlyPubkeyHex(APPROVER_SECRET)
    val LEAD_PUB: String = Bip340.xonlyPubkeyHex(LEAD_SECRET)
    val AUX = "0".repeat(64)

    fun bytes(hex: String) = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
  }
}
