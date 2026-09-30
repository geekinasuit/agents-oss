package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodCompletion
import com.geekinasuit.agency.pod.PodSpawned
import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.pod.sha256HexBytes
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The bound copy of a finished pod's artifact, read back before the plan or commit record binds to
 * it. The lead writes that copy once, as a regular file, then records the pod's result, and a normal
 * wake reads the copy back straight away. A crash between the result record and the plan record
 * makes every restart read it again, so a copy disturbed in that window must not stop the lead:
 * whatever sits at the bound path, the read neither blocks nor throws, and it reads at most
 * [LeadDaemon.MAX_BOUND_ARTIFACT_BYTES] plus one byte. The pod is abandoned, a disturbed copy is
 * escalated, and the playbook proposes the plan again. A completion whose snapshot is larger than
 * that is refused before its copy is written.
 *
 * Every daemon here runs under a non-ceremony auth, which mints no nonce, so no gate-open announce
 * reads a bound copy: the only read is the one before the plan record.
 */
class BoundArtifactTest {

  @get:Rule val tmp = TemporaryFolder()

  private val limit = LeadDaemon.MAX_BOUND_ARTIFACT_BYTES

  /** The deadline the cells that leave a read blocked pass, so each waits it out in well under a
   * second. */
  private val shortDeadlineMs = 200L

  private fun daemon(
    dir: File,
    store: SqliteStore,
    faults: FaultInjector = FaultInjector.NONE,
    podRunner: PodRunner = FakePodRunner(),
    boundReadDeadlineMs: Long = LeadDaemon.DEFAULT_BOUND_READ_DEADLINE_MS,
    maxParkedBoundReads: Int = LeadDaemon.DEFAULT_MAX_PARKED_BOUND_READS,
  ): LeadDaemon {
    File(dir, "ticket.txt").also { if (!it.exists()) it.writeText("t1\n") }
    return LeadDaemon(
      store = store,
      cognition = ScriptedCognition(),
      podRunner = podRunner,
      podSpec = PodSpec.fixture(),
      ticketSource = FileTicketSource(File(dir, "ticket.txt")),
      workdir = dir,
      effects = EffectReceiver(dir.absolutePath),
      leadAuth = LeadAuth.DENY_ALL,
      timers = TimerService.NOOP,
      faults = faults,
      boundReadDeadlineMs = boundReadDeadlineMs,
      maxParkedBoundReads = maxParkedBoundReads,
    )
  }

  /** A pod's result record: the pod, the lead's bound copy of its artifact, and the digest bound. */
  private data class Result(val podId: String, val boundPath: String, val digest: String)

  private fun results(store: SqliteStore): List<Result> =
    store
      .readAll()
      .filter { it.kind == LeadKinds.POD_RESULT_RECORDED }
      .map {
        val payload = Json.parseToJsonElement(it.payloadJson).jsonObject
        Result(
          payload["podId"]!!.jsonPrimitive.content,
          payload["boundPath"]!!.jsonPrimitive.content,
          payload["resultDigest"]!!.jsonPrimitive.content,
        )
      }

  private fun escalations(store: SqliteStore): List<String> =
    store.readAll().filter { it.kind == LeadKinds.ESCALATED }.map { it.payloadJson }

  private fun spawns(store: SqliteStore): Int =
    store.readAll().count { it.kind == LeadKinds.POD_SPAWNED }

  /** Runs the lead until its planner pod's result is recorded, and crashes it there, before the
   * plan record: the window in which every restart reads the bound copy again. Returns that result. */
  private fun crashAfterThePlannerResult(dir: File, store: SqliteStore): Result {
    val crash =
      FaultInjector {
        if (it == "after-pod-result") throw RuntimeException("crash after the pod result, before the plan")
      }
    assertThrows(RuntimeException::class.java) { daemon(dir, store, faults = crash).driveUntilQuiescent() }
    assertTrue(
      "no plan was recorded before the crash",
      store.readAll().none { it.kind == LeadKinds.PLAN_ARTIFACT_RECORDED },
    )
    return results(store).single()
  }

  /** Asserts that [abandoned]'s pod was abandoned for [reason], that the playbook then proposed the
   * plan again, and that the plan is recorded from the new pod's own bound copy. */
  private fun assertThePlanWasProposedAgain(f: LeadDaemon.Folded, store: SqliteStore, abandoned: Result, reason: String) {
    assertEquals("the pod was abandoned", reason, f.lead.pods[abandoned.podId]?.abandonedReason)
    assertEquals("the playbook proposed the plan again", 2, spawns(store))
    val next = results(store).single { it.podId != abandoned.podId }
    assertEquals("the plan is the new pod's bound copy", next.boundPath, f.lead.planArtifactPath)
    assertEquals("bound to the new pod's digest", next.digest, f.lead.planArtifactSha)
    assertEquals(TicketPhase.PLAN_GATED, f.lead.phase)
  }

  /** Restarts the lead over the disturbed copy of [abandoned] and asserts that it recovered: the
   * copy was escalated once, naming [detail] and the bound path, the pod was abandoned and the plan
   * proposed again, and a further restart runs without a fault and escalates nothing more. */
  private fun assertARestartAbandonsTheDisturbedCopy(
    dir: File,
    store: SqliteStore,
    abandoned: Result,
    detail: String,
    faults: FaultInjector = FaultInjector.NONE,
    boundReadDeadlineMs: Long = LeadDaemon.DEFAULT_BOUND_READ_DEADLINE_MS,
  ) {
    val f = daemon(dir, store, faults = faults, boundReadDeadlineMs = boundReadDeadlineMs).driveUntilQuiescent()
    val escalation = escalations(store).single()
    assertTrue("the escalation names the pod: $escalation", escalation.contains(abandoned.podId))
    assertTrue("the escalation says what is wrong: $escalation", escalation.contains("$detail at ${abandoned.boundPath}"))
    assertThePlanWasProposedAgain(f, store, abandoned, "bound-artifact-disturbed: $detail")

    daemon(dir, store).driveUntilQuiescent()
    assertEquals("a further restart escalated nothing more", 1, escalations(store).size)
  }

  @Test
  fun aMissingBoundCopyAbandonsThePodWithoutAnEscalation() {
    // The copy can be lost without anyone disturbing it, as when the host crashes before its page
    // reaches the disk, so a missing copy only sends the work round again.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val result = crashAfterThePlannerResult(dir, store)
    assertTrue("the bound copy was removed", File(result.boundPath).delete())

    val f = daemon(dir, store).driveUntilQuiescent()
    assertTrue("nothing was escalated", escalations(store).isEmpty())
    assertThePlanWasProposedAgain(f, store, result, "bound-artifact-missing at ${result.boundPath}")
    store.close()
  }

  @Test
  fun aBoundCopyWhoseBytesChangedAbandonsThePodAndIsEscalated() {
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val result = crashAfterThePlannerResult(dir, store)
    File(result.boundPath).writeText("not the plan the pod wrote\n")

    val f = daemon(dir, store).driveUntilQuiescent()
    val escalation = escalations(store).single()
    assertTrue("the escalation names the mismatch: $escalation", escalation.contains("integrity failure pod=${result.podId}"))
    assertTrue("the escalation names the bound path: $escalation", escalation.contains(result.boundPath))
    assertThePlanWasProposedAgain(f, store, result, "bound-artifact-integrity-failure")
    store.close()
  }

  @Test
  fun aDirectoryAtTheBoundPathAbandonsThePodInsteadOfThrowing() {
    // Reading a directory throws, and a throw would leave the pod as it was, so every restart would
    // throw again. The lead wrote a regular file there, so anything else is a disturbed store.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val result = crashAfterThePlannerResult(dir, store)
    assertTrue("the bound copy was removed", File(result.boundPath).delete())
    assertTrue("a directory now sits at the bound path", File(result.boundPath).mkdir())

    assertARestartAbandonsTheDisturbedCopy(dir, store, result, "not a regular file")
    store.close()
  }

  // The timeout is well inside the target's own, so a read that blocks fails this cell alone
  // rather than stopping every cell after it.
  @Test(timeout = 20_000)
  fun aFifoAtTheBoundPathAbandonsThePodWithoutBlocking() {
    // Opening a FIFO blocks until something opens its other end, and nothing will, so a read that
    // opened it would hold the loop thread for good.
    assumeTrue("mkfifo required", File("/usr/bin/mkfifo").canExecute())
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val result = crashAfterThePlannerResult(dir, store)
    assertTrue("the bound copy was removed", File(result.boundPath).delete())
    assertEquals(
      "a FIFO now sits at the bound path",
      0,
      ProcessBuilder("/usr/bin/mkfifo", result.boundPath).start().waitFor(),
    )

    assertARestartAbandonsTheDisturbedCopy(dir, store, result, "not a regular file")
    store.close()
  }

  @Test
  fun aLinkAtTheBoundPathAbandonsThePodUnfollowed() {
    // The link names a file with the very same bytes, so the digest would match. The lead reads only
    // the regular file it wrote: a link can name a FIFO or a device as easily as a file.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val result = crashAfterThePlannerResult(dir, store)
    val bound = File(result.boundPath)
    val elsewhere = File(dir, "elsewhere").also { it.writeBytes(bound.readBytes()) }
    assertTrue("the bound copy was removed", bound.delete())
    Files.createSymbolicLink(bound.toPath(), elsewhere.toPath())

    assertARestartAbandonsTheDisturbedCopy(dir, store, result, "not a regular file")
    store.close()
  }

  @Test
  fun aLinkToNothingAtTheBoundPathIsADisturbedCopyNotAMissingOne() {
    // Something put the link there, so the store was disturbed: the copy did not just fail to reach
    // the disk.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val result = crashAfterThePlannerResult(dir, store)
    val bound = File(result.boundPath)
    assertTrue("the bound copy was removed", bound.delete())
    Files.createSymbolicLink(bound.toPath(), File(dir, "nothing-here").toPath())

    assertARestartAbandonsTheDisturbedCopy(dir, store, result, "not a regular file")
    store.close()
  }

  @Test
  fun aBoundCopyThatCannotBeReadAbandonsThePodAndIsEscalated() {
    // A regular file the lead cannot open is a fault of the read, not a missing copy: the lead wrote
    // the copy readable, so something disturbed the store.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val result = crashAfterThePlannerResult(dir, store)
    val bound = File(result.boundPath)
    assertTrue("read permission was removed", bound.setReadable(false, false))
    // A process running as root reads the file anyway, and then there is no fault to test.
    assumeTrue("the copy is unreadable to this process", !bound.canRead())

    val f = daemon(dir, store).driveUntilQuiescent()
    val escalation = escalations(store).single()
    assertTrue("the escalation names the pod: $escalation", escalation.contains(result.podId))
    assertTrue("the escalation names a read fault: $escalation", escalation.contains(": read fault: "))
    assertTrue("the escalation names the bound path: $escalation", escalation.contains("at ${result.boundPath}"))
    assertTrue(
      "the pod was abandoned for the fault",
      f.lead.pods[result.podId]?.abandonedReason.orEmpty().startsWith("bound-artifact-disturbed: read fault: "),
    )
    assertEquals("the playbook proposed the plan again", 2, spawns(store))
    assertEquals(TicketPhase.PLAN_GATED, f.lead.phase)
    store.close()
  }

  @Test
  fun aDirectoryAtTheExecutePodsBoundPathAbandonsThatPodInsteadOfThrowing() {
    // The commit proposal reads the execute pod's bound copy back as the plan record reads the
    // planner's, and a crash after the execute pod's result makes every restart read it again.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val planned = daemon(dir, store).driveUntilQuiescent()
    val planner = results(store).single()
    AuthStub.appendRelease(store, gateIdFor(GateKinds.PLAN_APPROVAL, "t1"), planned.lead.planArtifactSha!!)
    val crash =
      FaultInjector {
        if (it == "after-pod-result") throw RuntimeException("crash after the execute pod's result")
      }
    assertThrows(RuntimeException::class.java) { daemon(dir, store, faults = crash).driveUntilQuiescent() }
    assertTrue(
      "no commit was proposed before the crash",
      store.readAll().none { it.kind == LeadKinds.COMMIT_PROPOSED },
    )
    val executed = results(store).single { it.podId != planner.podId }
    assertTrue("the bound copy was removed", File(executed.boundPath).delete())
    assertTrue("a directory now sits at the bound path", File(executed.boundPath).mkdir())

    val f = daemon(dir, store).driveUntilQuiescent()
    val escalation = escalations(store).single()
    assertTrue("the escalation names the pod: $escalation", escalation.contains(executed.podId))
    assertTrue(
      "the escalation says what is wrong: $escalation",
      escalation.contains("not a regular file at ${executed.boundPath}"),
    )
    assertEquals(
      "the execute pod was abandoned",
      "bound-artifact-disturbed: not a regular file",
      f.lead.pods[executed.podId]?.abandonedReason,
    )
    val next = results(store).single { it.podId != planner.podId && it.podId != executed.podId }
    assertEquals("the commit is the new execute pod's bound copy", next.boundPath, f.lead.commitManifestPath)
    assertEquals("bound to the new pod's digest", next.digest, f.lead.commitManifestDigest)
    assertEquals(TicketPhase.COMMIT_GATED, f.lead.phase)
    store.close()
  }

  @Test
  fun aBoundCopyLargerThanTheLeadReadsIsAbandonedUnread() {
    // Extended with a hole, not data, one byte past the limit. The lead never writes a copy that
    // large, so the size alone shows the store was disturbed, and the copy is not read.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val result = crashAfterThePlannerResult(dir, store)
    val size = limit.toLong() + 1
    RandomAccessFile(result.boundPath, "rw").use { it.setLength(size) }

    assertARestartAbandonsTheDisturbedCopy(
      dir,
      store,
      result,
      "$size bytes, over the $limit the lead reads back",
    )
    store.close()
  }

  @Test
  fun aBoundCopyThatGrowsWhileItIsReadIsAbandoned() {
    // The size check and the read are two steps, and the copy can grow between them. The read takes
    // at most one byte past the limit, so a copy that grew past it is refused, not read whole. The
    // fault point just before the read stands in for whatever grew it; it grows only the first copy
    // read, the disturbed one, and not the copy of the pod that replaces it.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val result = crashAfterThePlannerResult(dir, store)
    var grown = false
    val grow =
      FaultInjector {
        if (it == "before-bound-artifact-read" && !grown) {
          grown = true
          RandomAccessFile(result.boundPath, "rw").use { f -> f.setLength(limit.toLong() + 1) }
        }
      }

    assertARestartAbandonsTheDisturbedCopy(
      dir,
      store,
      result,
      "grew past the $limit bytes the lead reads back while it was read",
      faults = grow,
    )
    assertTrue("the copy grew at the read", grown)
    store.close()
  }

  /** Swaps the copy at [path] for a FIFO at the fault point just before its read, once, standing in
   * for whatever swapped it between the check and the open. [swapped] counts down when it has. */
  private fun swapForAFifoOnce(path: String, swapped: CountDownLatch): FaultInjector =
    FaultInjector {
      if (it == "before-bound-artifact-read" && swapped.count > 0) {
        replaceWithAFifo(path)
        swapped.countDown()
      }
    }

  // The timeout is well inside the target's own, so a read that blocks fails this cell alone
  // rather than stopping every cell after it.
  @Test(timeout = 20_000)
  fun aBoundCopySwappedForAFifoAfterItsCheckIsAbandonedWithoutBlocking() {
    // The check and the open are two steps, and the copy can be swapped for a FIFO between them.
    // Opening a FIFO blocks until something opens its other end, and an open cannot be interrupted,
    // so the open and the read run on a thread of their own, which the loop waits on for a deadline.
    // A read unfinished by then is a disturbed copy, and the read stays blocked on its own thread.
    assumeTrue("mkfifo required", canMakeAFifo())
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val result = crashAfterThePlannerResult(dir, store)
    val swapped = CountDownLatch(1)
    try {
      assertARestartAbandonsTheDisturbedCopy(
        dir,
        store,
        result,
        "read did not finish within $shortDeadlineMs ms",
        faults = swapForAFifoOnce(result.boundPath, swapped),
        boundReadDeadlineMs = shortDeadlineMs,
      )
      assertEquals("the copy was swapped at the read", 0, swapped.count)
      assertEquals("the read is still blocked, on a thread of its own", 1, boundReadThreads().size)
    } finally {
      if (swapped.count == 0L) releaseFifo(result.boundPath)
    }
    assertTrue("the read returned once the FIFO had a writer", awaitNoBoundReadThreads())
    store.close()
  }

  @Test(timeout = 20_000)
  fun aShutdownIsTakenWhileTheReadOfASwappedCopyIsBlocked() {
    // A read that blocked the loop thread would hold every wake behind it, a queued shutdown
    // included. The blocked read holds only its own thread, a daemon one, which does not keep the
    // process running once the loop has stopped.
    assumeTrue("mkfifo required", canMakeAFifo())
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val result = crashAfterThePlannerResult(dir, store)
    val swapped = CountDownLatch(1)
    val d =
      daemon(
        dir,
        store,
        faults = swapForAFifoOnce(result.boundPath, swapped),
        boundReadDeadlineMs = shortDeadlineMs,
      )
    val loop = Thread { d.runLoop() }
    loop.isDaemon = true
    loop.start()
    try {
      assertTrue("the copy was swapped at the read", swapped.await(10, TimeUnit.SECONDS))
      d.shutdown()
      loop.join(10_000)
      assertFalse("the loop took the shutdown", loop.isAlive)
      val readers = boundReadThreads()
      assertEquals("the read is still blocked, on a thread of its own", 1, readers.size)
      assertTrue("the blocked read's thread does not keep the process running", readers.single().isDaemon)
    } finally {
      if (swapped.count == 0L) releaseFifo(result.boundPath)
    }
    assertTrue("the read returned once the FIFO had a writer", awaitNoBoundReadThreads())
    store.close()
  }

  @Test(timeout = 20_000)
  fun blockedReadsAreBoundedAndThePodsReadPastTheBoundAreRefusedUnopened() {
    // Each read left blocked holds a thread until its FIFO gets a writer, so a store that kept being
    // swapped would grow the lead's threads without end. Past the bound, the lead opens no bound copy
    // at all, and abandons each pod whose copy it did not read. Those copies may well be intact, as
    // the replacement pods' copies are here, so the refusal says the lead's reads are blocked, not
    // that the copy was disturbed. Each abandon counts against the task's attempts, so the task stops
    // being proposed once they run out. A restart holds no blocked reads, and reads a copy again.
    assumeTrue("mkfifo required", canMakeAFifo())
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val result = crashAfterThePlannerResult(dir, store)
    val swapped = CountDownLatch(1)
    try {
      val f =
        daemon(
            dir,
            store,
            faults = swapForAFifoOnce(result.boundPath, swapped),
            boundReadDeadlineMs = shortDeadlineMs,
            maxParkedBoundReads = 1,
          )
          .driveUntilQuiescent()
      assertEquals(
        "the swapped copy's pod was abandoned when its read did not finish",
        "bound-artifact-disturbed: read did not finish within $shortDeadlineMs ms",
        f.lead.pods[result.podId]?.abandonedReason,
      )
      val replacements = results(store).filter { it.podId != result.podId }
      assertTrue("a replacement pod's result was recorded", replacements.isNotEmpty())
      for (r in replacements) {
        assertEquals(
          "a replacement pod's copy was not read",
          "bound-artifact-unread: blocked reads of the bound store are at the bound of 1",
          f.lead.pods[r.podId]?.abandonedReason,
        )
      }
      assertTrue(
        "each unread copy was escalated as unread",
        escalations(store).count { it.contains("bound-artifact unread pod=") } == replacements.size,
      )
      assertNull("no plan was recorded", f.lead.planArtifactPath)
      assertEquals("one thread holds the one blocked read", 1, boundReadThreads().size)
    } finally {
      if (swapped.count == 0L) releaseFifo(result.boundPath)
    }
    assertTrue("the read returned once the FIFO had a writer", awaitNoBoundReadThreads())

    val g = daemon(dir, store).driveUntilQuiescent()
    assertEquals("a restart reads a copy and records the plan", TicketPhase.PLAN_GATED, g.lead.phase)
    store.close()
  }

  /** A pod runner whose first pod, "pod-first", completes with [snapshot]; every later pod is
   * [FakePodRunner]'s, with an id of its own. */
  private fun firstPodWith(snapshot: ByteArray): PodRunner =
    object : PodRunner {
      private val later = FakePodRunner()
      private var spawned = 0

      override fun spawn(
        spec: PodSpec,
        taskRef: String,
        workdir: File,
        artifactPath: String,
        onComplete: (PodCompletion) -> Unit,
      ): PodSpawned {
        spawned += 1
        if (spawned > 1) return later.spawn(spec, taskRef, workdir, artifactPath, onComplete)
        onComplete(PodCompletion("pod-first", artifactPath, sha256HexBytes(snapshot), 0.0, snapshot))
        return PodSpawned("pod-first", "sess-first")
      }
    }

  @Test
  fun aSnapshotLargerThanTheLeadReadsBackIsRefusedBeforeItIsWritten() {
    // A copy the lead could not read back whole would only be refused later, as a disturbed store.
    // So a runner's snapshot over the limit is refused when its result would be recorded, and the
    // work goes round again.
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val size = limit + 1
    val f = daemon(dir, store, podRunner = firstPodWith(ByteArray(size))).driveUntilQuiescent()

    // A copy written and then refused as too large when it is read back would be escalated with
    // the same size, so the escalation must be the completion's.
    val escalation = escalations(store).single()
    assertTrue(
      "the escalation refuses the completion's snapshot: $escalation",
      escalation.contains("pod-completion snapshot too large for pod 'pod-first'"),
    )
    assertTrue(
      "the escalation names the size and the limit: $escalation",
      escalation.contains("$size bytes, over the $limit the lead reads back"),
    )
    assertTrue("no result names the pod", results(store).none { it.podId == "pod-first" })
    assertFalse("its copy was never written", File(dir, "artifacts-bound/pod-first").exists())
    assertEquals("the pod was abandoned", "snapshot-too-large", f.lead.pods["pod-first"]?.abandonedReason)
    assertEquals("the playbook proposed the plan again", 2, spawns(store))
    assertEquals("the plan is the new pod's bound copy", results(store).single().boundPath, f.lead.planArtifactPath)
    store.close()
  }

  @Test
  fun aSnapshotOfExactlyTheLimitIsRecordedAndReadBackWhole() {
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val bytes = ByteArray(limit) { 'x'.code.toByte() }
    val f = daemon(dir, store, podRunner = firstPodWith(bytes)).driveUntilQuiescent()

    assertTrue("nothing was escalated", escalations(store).isEmpty())
    assertEquals("one pod did the work", 1, spawns(store))
    assertEquals(
      "the plan is the pod's bound copy",
      File(dir, "artifacts-bound/pod-first").path,
      f.lead.planArtifactPath,
    )
    assertEquals("bound to the digest of the whole snapshot", sha256HexBytes(bytes), f.lead.planArtifactSha)
    store.close()
  }
}
