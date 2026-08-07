package com.geekinasuit.agency.pod

import com.geekinasuit.agency.shared.harness.Subprocess
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** Engine clocks and caps — REQUIRED, no defaults: every deadline here decides
 * fail-open-vs-fail-closed for some path, and a silently-inherited default is a
 * third party deciding that question for us. Tests pass tight values; the wiring
 * passes the lead-owned config. */
data class EngineTimings(
  val initializeMs: Long,
  val newSessionMs: Long,
  val turnMs: Long,
  val askDeadlineMs: Long,
  /** How long to wait for the launched agent to appear as a child of the group wrapper —
   * i.e. for the pod to become GROUP-KILLABLE. No default for the same reason as the rest:
   * this value decides whether a tree kill or a child-only kill is what the engine can do. */
  val groupReportMs: Long,
  /** Whole-pod wall clock: armed at spawn, spans every restart attempt, enforced by
   * the process-group kill on OUR clock — never the vendor's accounting. */
  val podWallClockMs: Long,
  /** Max TOTAL process attempts (first launch + restarts). */
  val restartCap: Int,
  /** Backoff before attempt N is backoffBaseMs * (N-1) — linear, deterministic. */
  val backoffBaseMs: Long,
)

/** Cap on artifact bytes read into memory by the disciplined read. */
private const val ARTIFACT_BYTE_CAP = 32L shl 20

/** Bounds on the UNTRUSTED agent-stderr tail kept for failure diagnosis. */
private const val STDERR_TAIL_LINES = 20
private const val STDERR_LINE_CHARS = 500

/**
 * The ACP pod engine: fills the [PodEngine] seam with
 * a REAL launcher — an agent subprocess in its OWN PROCESS GROUP, spoken to over stdio by
 * [AcpClient], supervised by an engine-owned thread, killable on clocks the engine owns.
 *
 * Contract with the lead (all callbacks ENQUEUE-ONLY, [PodEngine] discipline):
 *  - [onComplete][PodEngine.spawn] fires AT MOST ONCE per pod — completion has a SINGLE
 *    OWNER: a terminal disposition (deadline kill, preflight refusal, artifact
 *    refusal, restart exhaustion, engine close) claims the pod atomically, and a
 *    completion losing that race is reported as [PodEvent.CompletionDiscarded], never
 *    delivered as a second advance.
 *  - Supervisory facts flow through the [events] callback as [PodEvent]s for the lead to
 *    journal: asks/decisions (via [PermissionBridge]), preflight refusals, artifact
 *    refusals, restart attempts/exhaustion, deadline kills. The seam MUST NOT throw; the
 *    engine defends anyway and counts refusals ([eventReportFailures]) — killing an
 *    untrusted process is never downstream of a journal write succeeding.
 *  - [spawn] has exactly ONE throwing contract: the spec fence (a configuration fault the
 *    lead is right to die on). Everything a POD can cause — a directory at the artifact
 *    path, an undeletable file, a dead executor — resolves to a terminal claim plus an
 *    event, because the lead's wake-loop handler treats any throw as fatal and pod-authored
 *    disk state is durable enough to make that a permanent crash loop.
 *
 * PROCESS-GROUP SPAWN CONTRACT: the agent is launched through a bash wrapper that
 * enables job control and backgrounds the agent — POSIX job control puts the backgrounded
 * job in its OWN process group (pgid == its pid). Group-kill is then `kill -KILL -pgid`,
 * covering the agent's WHOLE tree including reparented orphans that kept the pgid — not just
 * the direct child. The deep-tree battery asserts the GROUP EXISTS (ps -o pgid on the agent
 * and its children), not merely that a kill call was issued.
 *
 * The group id is read from the OS (the wrapper's only child), never from anything the pod
 * writes. An earlier draft had the wrapper echo `PODGROUP:<pid>` onto the agent's own stderr
 * and parsed it back — which handed the untrusted pod the argument to `kill -KILL -- -N`.
 * `PODGROUP:1` is then a SIGKILL of every process the user owns, the lead included: a
 * control plane and an untrusted data plane sharing one fd. See [Launch].
 *
 * RESTART: a crashed process/handshake is re-attempted with backoff up to
 * [EngineTimings.restartCap] TOTAL attempts, each attempt a FRESH process + session —
 * asks are re-asked (no decision cache anywhere, see [PermissionBridge]), the preflight
 * re-runs, and the stale artifact from the killed attempt is CLEARED before the re-spawned
 * pod writes (the lead must never bind a digest over a previous attempt's
 * truncated file). Exhaustion is a VISIBLE escalation event, never a silent loop.
 *
 * PREFLIGHT (time-of-check-only — stated limit): the FIRST turn of every session
 * is the profile's execute-kind sentinel; a session that routes NO ask for it is refused
 * ([PodEvent.PreflightRefused], terminal). This defeats the STATICALLY non-asking agent
 * only — a delayed-bypass agent passes it by construction and must still be unable to
 * release any gate (that property lives in the lead's provenance folds, and the battery
 * pins it there).
 *
 * DISCIPLINED ARTIFACT READ: one NOFOLLOW-stat + NOFOLLOW-open
 * read of the lead-assigned path — symlink, HARD LINK (nlink > 1), non-regular file
 * (FIFO/dir/device), resolved path outside the workspace, oversize, or missing → REFUSED
 * ([PodEvent.ArtifactRefused], terminal, no completion). The stat-first order refuses a
 * persisted FIFO without ever opening it (a FIFO open blocks forever = DoS); the stat→open
 * swap race is closed for symlinks by NOFOLLOW on the open itself. Identity and containment
 * are asked under OPPOSITE link policies on purpose: NOFOLLOW for "is this the pod's own
 * regular file", full resolution for "is it inside the workspace" (a symlinked PARENT
 * directory escapes the workspace while NOFOLLOW sees nothing wrong). RESIDUAL, stated
 * plainly: a regular→FIFO swap
 * inside the stat→open window parks that pod's supervisor thread PERMANENTLY — the wall
 * clock kills the pod's PROCESS, which does not unpark a blocking `open(2)` — so the thread
 * leaks for the JVM's life and [closedCleanly] then reports false. Bounded (one thread per
 * pod that wins that race, lead loop never affected), not covered. Closing it needs an
 * open-with-timeout the JDK does not offer on regular paths; the real fix is the pod
 * filesystem boundary (AGENCY-005 container floor). The BIND-ONCE snapshot
 * hand-off rides on top of this read.
 *
 * HOST DEPENDENCIES: `/bin/bash` (the group wrapper) and `/bin/kill` (group kill) — POSIX
 * paths present on the macOS CI runner and every Linux host we target. A host missing them
 * degrades LOUDLY, not silently: spawn fails outright without bash, and an unusable
 * `/bin/kill` surfaces as [PodEvent.GroupKillDegraded].
 */
class AcpPodEngine(
  private val profile: EngineProfile,
  private val bridge: PermissionBridge,
  private val events: (PodEvent) -> Unit,
  private val timings: EngineTimings,
  private val artifactByteCap: Long = ARTIFACT_BYTE_CAP,
) : PodEngine, AutoCloseable {

  private val scheduler =
    Executors.newSingleThreadScheduledExecutor { r ->
      Thread(r, "acp-engine-clock").also { it.isDaemon = true }
    }
  private val supervisors =
    Executors.newCachedThreadPool { r -> Thread(r, "acp-engine-supervisor").also { it.isDaemon = true } }

  private val livePods = ConcurrentHashMap<String, PodRun>()

  /** Reports the [events] seam REFUSED. The seam's contract is that it does not
   * throw — the lead's real implementation appends to SQLite, whose documented convention is
   * "accept means durable, so failure is refusal" — but the engine must not inherit that
   * contract by accident. Every report is defended, and a refused report is COUNTED rather
   * than swallowed: killing an untrusted process must never be downstream of a journal write
   * succeeding, and a record with holes in it must not look like a clean one. The wiring
   * owns the durable answer (a bounded queue whose own failure is a journalable fact) —
   * AGENCY-028. */
  private val eventReportFailures = AtomicInteger(0)

  /** Count of engine facts that could not be reported. Non-zero means the journal is missing
   * events the engine observed — for the wiring to alarm on, never to ignore. */
  fun eventReportFailures(): Int = eventReportFailures.get()

  private fun report(e: PodEvent) {
    try {
      events(e)
    } catch (_: Throwable) {
      eventReportFailures.incrementAndGet()
    }
  }

  override fun spawn(
    spec: PodSpec,
    taskRef: String,
    workdir: File,
    artifactPath: String,
    onComplete: (PodCompletion) -> Unit,
  ): PodSpawned {
    // Fence FIRST, before any side effect (defense in depth under the daemon's own check),
    // then the profile's argv construction — a deferred profile (grokNative) throws AT
    // SPAWN, in this call, before a process exists. Session meta and the protocol pin are
    // captured HERE, once, beside argv/env: every attempt the restart ladder establishes
    // reuses the same lead-owned config (a restart re-derives nothing).
    spec.requireSpawnable()
    val argv = profile.argv(spec, workdir)
    val env = profile.env(spec)
    val sessionMeta = profile.sessionMeta(spec)
    val expectedProtocol = profile.expectedProtocolVersion()

    val podId = "pod-" + UUID.randomUUID().toString().take(8)
    val run =
      PodRun(podId, argv, env, sessionMeta, expectedProtocol, taskRef, workdir, artifactPath, onComplete)
    livePods[podId] = run
    return run.start()
  }

  /**
   * Explicit engine shutdown: claim + kill every live pod, stop the executors. Each
   * pod's termination is INDEPENDENTLY defended — one pod failing to die must not skip the
   * others or the `shutdownNow` calls below it, which would leak both untrusted OS processes
   * and the engine's own threads.
   */
  override fun close() {
    for (run in livePods.values) runCatching { run.terminate("engine-closed") }
    scheduler.shutdownNow()
    supervisors.shutdownNow()
    scheduler.awaitTermination(2, TimeUnit.SECONDS)
    supervisors.awaitTermination(2, TimeUnit.SECONDS)
  }

  /** True when every spawned pod reached a terminal state, released its process and client,
   * and the executors are down. Pods RETIRE from [livePods] as they finish, so
   * this is "nothing outstanding", not "nothing was ever launched". */
  fun closedCleanly(): Boolean =
    scheduler.isTerminated && supervisors.isTerminated && livePods.values.all { it.terminal.get() != null }

  // ---- one pod's lifecycle ----

  private inner class PodRun(
    val podId: String,
    val argv: List<String>,
    val env: Map<String, String>,
    /** Lead-owned session/new `_meta`, captured once at spawn. */
    val sessionMeta: kotlinx.serialization.json.JsonElement?,
    /** The profile's pinned acp protocol version, or null to skip the check. */
    val expectedProtocol: String?,
    val taskRef: String,
    val workdir: File,
    val artifactPath: String,
    val onComplete: (PodCompletion) -> Unit,
  ) {
    /** Single completion owner: first CAS wins the pod; everyone else stands down. */
    val terminal = AtomicReference<String?>(null)

    val attempts = AtomicInteger(0)

    /** Bounded tail of the agent's stderr, attached to restart/exhaustion causes so a
     * failing pod's diagnosis reaches the journal. UNTRUSTED text: bounded in both line
     * count and line length, and never interpreted — only quoted. */
    private val stderrTail = java.util.concurrent.ConcurrentLinkedDeque<String>()

    fun rememberStderr(line: String) {
      stderrTail.addLast(line.take(STDERR_LINE_CHARS))
      while (stderrTail.size > STDERR_TAIL_LINES) stderrTail.pollFirst()
    }

    fun stderrTailText(): String =
      stderrTail.toList().takeIf { it.isNotEmpty() }?.joinToString(" | ") ?: "(no agent stderr)"

    /** One degradation report per pod: the kill runs on several paths (turn failure,
     * terminal claim, engine close) and the fact worth recording is "this pod's tree was
     * never group-killable", not each call. */
    private val groupKillDegraded = java.util.concurrent.atomic.AtomicBoolean(false)

    @Volatile var lastCause: String = "never-launched"

    /**
     * The pod's CURRENT OS process, published the instant it exists — BEFORE the handshake,
     * which is the whole point. It used to be set only after `establish()`
     * returned, so a wall clock landing during the group-report + initialize + newSession
     * window killed nothing at all and `DeadlineKilled` was journaled about a pod that was
     * still running. Anything that kills this pod kills whatever is here.
     */
    val live = AtomicReference<Launch?>(null)

    @Volatile var current: Handle? = null
    @Volatile var deadline: ScheduledFuture<*>? = null

    fun start(): PodSpawned {
      clearStaleArtifact()?.let { refusal ->
        // A hostile or unusable object at the lead-assigned path is POD WORK, not a
        // configuration fault: refusing terminally is what every other hostile
        // shape at this path gets. Throwing here would reach LeadDaemon.handleWake, whose
        // handler is deliberately fatal — and since the object is durable on disk, the next
        // process would do it again. spawn() keeps exactly ONE throwing contract: the spec
        // fence.
        if (terminal.compareAndSet(null, "artifact-refused")) {
          report(PodEvent.ArtifactRefused(podId, artifactPath, refusal))
        }
        retire()
        return PodSpawned(podId, "unestablished")
      }
      // Wall clock armed BEFORE the first launch: it covers handshakes, restarts,
      // backoffs, turns — the whole pod, on our clock. A close() racing us leaves the
      // scheduler shut down; that is a dead pod, not a fatal fault for the caller.
      deadline =
        try {
          scheduler.schedule(
            {
              if (terminal.compareAndSet(null, "deadline-killed")) {
                // KILL FIRST, report second: the report is a journal append that
                // can refuse, and a claimed-but-unkilled pod is a live untrusted process the
                // engine believes is dead.
                killLive()
                report(PodEvent.DeadlineKilled(podId, timings.podWallClockMs))
                retire()
              }
            },
            timings.podWallClockMs,
            TimeUnit.MILLISECONDS,
          )
        } catch (_: RejectedExecutionException) {
          terminal.compareAndSet(null, "engine-closed")
          retire()
          return PodSpawned(podId, "unestablished")
        }
      // Exactly ONE launch attempt on the caller's thread. The first handshake must be
      // synchronous — the lead journals POD_SPAWNED with the session id this returns — but
      // the RETRY LADDER must not be: restartCap × backoff plus handshake timeouts on the
      // lead's single loop thread would stall every other pod, timer and mail behind one
      // deterministically-failing agent (the restart loop is not free). So a failed
      // first launch hands the ladder to the supervisor pool and returns "unestablished";
      // any session a later attempt establishes reaches the record as
      // [PodEvent.SessionEstablished], which is where re-attach reads it from anyway (the
      // spawn-time id is stale the moment a restart mints a new session).
      val first =
        try {
          establish(attempts.incrementAndGet())
        } catch (t: Throwable) {
          recordCause(1, t)
          null
        }
      if (first == null) {
        // Every remaining attempt (and the supervision that follows one) runs on the pool,
        // inside a guard: a throw escaping this Runnable would leave the pod non-terminal
        // with no event, no completion and no escalation.
        runOnPool { establishWithRetries()?.let { supervise(it) } }
        return PodSpawned(podId, "unestablished")
      }
      current = first
      // A terminal claim (a tight wall clock, an engine close) may have landed during the
      // handshake — reap rather than supervise a pod someone else already owns.
      if (terminal.get() != null) {
        killHandle(first)
        retire()
      } else {
        runOnPool { supervise(first) }
      }
      return PodSpawned(podId, first.sessionId)
    }

    /**
     * Run one supervision task on the pool, converting BOTH failure modes the pool has into
     * a terminal pod rather than silence: a rejected submission (close() raced us) and any
     * throw escaping the body. Without this the pod stays non-terminal forever and the only
     * fact the lead ever hears is a wall-clock kill that misdescribes why it died.
     */
    fun runOnPool(body: () -> Unit) {
      try {
        supervisors.execute {
          try {
            body()
          } catch (t: Throwable) {
            recordCause(attempts.get(), t)
            if (terminal.compareAndSet(null, "supervision-failed")) {
              killLive()
              report(PodEvent.RestartsExhausted(podId, attempts.get(), lastCause))
            }
            retire()
          }
        }
      } catch (_: RejectedExecutionException) {
        if (terminal.compareAndSet(null, "engine-closed")) killLive()
        retire()
      }
    }

    /** Claim the pod for [reason] (engine close). Quiet if a terminal owner already won. */
    fun terminate(reason: String) {
      if (terminal.compareAndSet(null, reason)) {
        killLive()
        retire()
      }
    }

    /** Kill whatever process this pod currently has — established or still handshaking. */
    fun killLive() {
      live.get()?.let { killLaunch(it) }
      current?.let { runCatching { it.client.close() } }
    }

    /**
     * Release the pod's retained state once it is terminal. Without this every
     * pod ever launched stays reachable through [livePods] → [Handle] → [AcpClient], whose
     * update log is deliberately never cleared: a per-pod wire cap becomes a cumulative,
     * unbounded one in a daemon that runs for weeks.
     */
    fun retire() {
      deadline?.cancel(false)
      current = null
      live.set(null)
      livePods.remove(podId)
    }

    /**
     * Launch attempts until a session is established, the cap is exhausted, or a terminal
     * claim (deadline kill / engine close) wins. Attempt N>1 emits RestartAttempted, backs
     * off, and RE-CLEARS the stale artifact before launching.
     */
    fun establishWithRetries(): Handle? {
      while (true) {
        if (terminal.get() != null) {
          retire()
          return null
        }
        val n = attempts.incrementAndGet()
        if (n > timings.restartCap) {
          if (terminal.compareAndSet(null, "restarts-exhausted")) {
            killLive()
            report(PodEvent.RestartsExhausted(podId, n - 1, lastCause))
          }
          retire()
          return null
        }
        if (n > 1) {
          val backoff = timings.backoffBaseMs * (n - 1)
          report(PodEvent.RestartAttempted(podId, n, backoff, lastCause))
          try {
            Thread.sleep(backoff)
          } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            retire()
            return null
          }
          clearStaleArtifact()?.let { refusal ->
            if (terminal.compareAndSet(null, "artifact-refused")) {
              report(PodEvent.ArtifactRefused(podId, artifactPath, refusal))
            }
            retire()
            return null
          }
        }
        try {
          val h = establish(n)
          current = h
          // A terminal claim may have landed while we were establishing — hand the corpse
          // back rather than supervising a pod someone already owns.
          if (terminal.get() != null) {
            killHandle(h)
            retire()
            return null
          }
          return h
        } catch (t: Throwable) {
          recordCause(n, t)
        }
      }
    }

    /** Record why an attempt failed and reap its corpse. The cause carries the agent's own
     * stderr tail: without it every failure reads "attempt N: failed" whether the binary was
     * missing, the flag was wrong, or the protocol broke. */
    fun recordCause(attempt: Int, t: Throwable) {
      lastCause =
        "attempt $attempt: ${t.message ?: t::class.simpleName ?: "failed"} — agent stderr: ${stderrTailText()}"
      killLive()
      current = null
      live.set(null)
    }

    /** One launch: process (published immediately, own group), client, handshake, session. */
    fun establish(attempt: Int): Handle {
      val wrapped = groupWrapperArgv(argv)
      // cleanEnv ALWAYS true for pods: ambient env is a credential/taint channel;
      // the profile's explicit env map rides on top of the constructed allowlist.
      val proc = Subprocess.processBuilder(wrapped, workdir, env, cleanEnv = true).start()
      val launch = Launch(proc)
      // Publish BEFORE anything can block, so the wall clock can kill during the handshake.
      live.set(launch)
      val stderrThread =
        Thread {
          proc.errorStream.bufferedReader().useLines { lines ->
            for (line in lines) {
              // The agent's stderr is UNTRUSTED text and nothing more. It used to be a
              // control channel too — the wrapper echoed the group id onto the same fd the
              // agent writes to, and the engine parsed it — which handed the pod a
              // same-uid SIGKILL primitive aimed at its own supervisor (`PODGROUP:1` →
              // `kill -KILL -- -1`). The group id now comes from the OS (see
              // [Launch.resolvePgid]); a dying pod's last words are kept only as diagnosis,
              // bounded in line count and length, and never interpreted.
              rememberStderr(line)
            }
          }
        }
      stderrThread.isDaemon = true
      stderrThread.name = "acp-$podId-stderr"
      stderrThread.start()

      var client: AcpClient? = null
      try {
        launch.resolvePgid(timings.groupReportMs)
        val c =
          AcpClient(
            agentStdout = proc.inputStream,
            agentStdin = proc.outputStream,
            decider = bridge.deciderFor(podId),
            askDeadlineMs = timings.askDeadlineMs,
            name = "acp-$podId-a$attempt",
          )
        client = c
        val handshake = c.initialize(timings.initializeMs)
        // The protocol pin: a skewed agent fails HERE, at launch, with both versions
        // named — the throw burns a restart attempt and exhausts into a visible escalation
        // rather than letting a version-moved agent misbehave mid-task.
        if (expectedProtocol != null && handshake.protocolVersion != expectedProtocol) {
          throw AcpCallFailed(
            "protocol-version skew: agent '${handshake.agentName}' negotiated acp v" +
              "${handshake.protocolVersion}, but the profile pins v$expectedProtocol",
            null,
          )
        }
        val sessionId = c.newSession(workdir, timings.newSessionMs, sessionMeta)
        val h = Handle(launch, c, sessionId)
        // Reported OUTSIDE the try: a refused report after a SUCCESSFUL handshake
        // must not be misclassified as a launch failure and burn a restart attempt.
        report(PodEvent.SessionEstablished(podId, sessionId, attempt))
        return h
      } catch (t: Throwable) {
        // Kill first (forces EOF), then close — per AcpClient's close caveat.
        killLaunch(launch)
        runCatching { client?.close() }
        throw t
      }
    }

    /** The supervising task: preflight, task turn, disciplined read, completion —
     * with the crash-restart loop around all of it. */
    fun supervise(first: Handle) {
      var h = first
      while (true) {
        if (terminal.get() != null) {
          killHandle(h)
          retire()
          return
        }
        try {
          // Preflight: the sentinel turn must route at least one ask.
          val asksBefore = h.client.askCount.get()
          h.client.prompt(h.sessionId, profile.preflightPrompt(), timings.turnMs)
          if (h.client.askCount.get() == asksBefore) {
            // Kill before reporting, everywhere below too: a refused report must
            // never leave a claimed pod running.
            if (terminal.compareAndSet(null, "preflight-refused")) {
              killHandle(h)
              report(
                PodEvent.PreflightRefused(
                  podId,
                  h.sessionId,
                  "sentinel turn routed no permission ask (statically non-asking agent)",
                )
              )
            } else {
              killHandle(h)
            }
            retire()
            return
          }
          // The real task turn. Attempt >1 declares possibly-interrupted work.
          val result = h.client.prompt(h.sessionId, taskPrompt(), timings.turnMs)
          when (val read = readArtifactDisciplined()) {
            is ArtifactRead.Refused -> {
              if (terminal.compareAndSet(null, "artifact-refused")) {
                killHandle(h)
                report(PodEvent.ArtifactRefused(podId, artifactPath, read.reason))
              } else {
                killHandle(h)
              }
              retire()
              return
            }
            is ArtifactRead.Bytes -> {
              val digest = sha256HexBytes(read.bytes)
              if (terminal.compareAndSet(null, "completed")) {
                deadline?.cancel(false)
                killHandle(h) // the pod's work is done; reap the process before reporting
                retire()
                // LAST, and outside every guard: the completion is the one thing the lead
                // must hear. Reporting it after the kill means no journal refusal can leave
                // a live process behind, and no kill failure can swallow the result.
                onComplete(
                  PodCompletion(
                    podId = podId,
                    artifactPath = artifactPath,
                    resultDigest = digest,
                    costUsd = profile.costUsdFrom(result.updates),
                    // Bind-once: the disciplined read's own bytes ride the
                    // completion — the lead binds THESE, and the pod's path is never
                    // read again.
                    snapshot = read.bytes,
                  )
                )
              } else {
                killHandle(h)
                retire()
                report(
                  PodEvent.CompletionDiscarded(
                    podId,
                    "terminal state '${terminal.get()}' already owns this pod",
                  )
                )
              }
              return
            }
          }
        } catch (t: Throwable) {
          // Turn deadline (a stalled agent) or transport death (a crashed one): kill this
          // attempt and let the restart loop decide — a terminal claim (wall-clock kill,
          // engine close) shows up as terminal.get() != null at the loop top.
          lastCause =
            "${t.message ?: t::class.simpleName ?: "turn failed"} — agent stderr: ${stderrTailText()}"
          killHandle(h)
        }
        val next = establishWithRetries() ?: return
        h = next
      }
    }

    fun taskPrompt(): String {
      val n = attempts.get()
      val notice =
        if (n > 1) "\nnotice: workspace may contain interrupted work from a previous attempt"
        else ""
      return "task: $taskRef\nartifact-path: $artifactPath\nattempt: $n$notice"
    }

    /**
     * Never let the lead bind a digest over a previous attempt's file. The
     * delete is NOFOLLOW by nature (unlink removes the link, never the target).
     *
     * Returns a refusal REASON instead of throwing. Everything at this path is
     * pod-controlled — the pod's cwd is the workspace and its prompt carries the path — so a
     * directory (one `mkdir`) or an undeletable entry (one `chmod`) is POD WORK, exactly as
     * [readArtifactDisciplined] already classifies it. Throwing here reached the lead's wake
     * loop, whose handler is deliberately fatal, and the on-disk state is durable: one
     * `mkdir` was a permanent crash loop.
     */
    fun clearStaleArtifact(): String? {
      val p = Path.of(artifactPath)
      try {
        Files.readAttributes(p, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
      } catch (_: IOException) {
        return null // nothing there
      }
      return try {
        Files.deleteIfExists(p)
        null
      } catch (e: IOException) {
        // DirectoryNotEmptyException, AccessDeniedException, anything else the pod arranged.
        "unclearable: ${e::class.simpleName} at the lead-assigned path — ${e.message}"
      }
    }

    fun readArtifactDisciplined(): ArtifactRead {
      val p = Path.of(artifactPath)
      val attrs =
        try {
          Files.readAttributes(p, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (_: IOException) {
          return ArtifactRead.Refused("missing: no artifact at the lead-assigned path")
        }
      if (attrs.isSymbolicLink) {
        return ArtifactRead.Refused("symlink: the pod does not choose the inode the lead reads")
      }
      if (!attrs.isRegularFile) {
        return ArtifactRead.Refused("not-a-regular-file: FIFO/device/dir at the artifact path")
      }
      // HARD LINK: a link to a file outside the workspace is a regular file, is
      // not a symlink, and has no target path to resolve — it passes every other check here
      // while handing the lead someone else's inode to read and digest. `link(2)` needs no
      // privilege the pod lacks. nlink is the observable; an unavailable nlink is refused,
      // because a security check that cannot run has not passed.
      val nlink =
        try {
          Files.getAttribute(p, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as? Int
        } catch (_: Exception) {
          null
        }
      if (nlink == null) {
        return ArtifactRead.Refused("nlink-unavailable: cannot establish the artifact is singly linked")
      }
      if (nlink > 1) {
        return ArtifactRead.Refused("multiply-linked: the pod does not choose the inode the lead reads")
      }
      // CONTAINMENT is a different question from IDENTITY, and needs the opposite policy.
      // Identity — "is the object at this path the pod's own regular file" — is
      // answered above by the NOFOLLOW stat and below by the NOFOLLOW open. Containment must
      // resolve links FULLY on both sides: NOFOLLOW here resolved nothing at all, so a
      // symlinked PARENT directory (which the pod may create, and which NOFOLLOW on the final
      // component does nothing about) compared as if it were inside the workspace — and,
      // symmetrically, an honest workspace under a symlinked prefix (macOS /var → /private/var,
      // which is exactly what createTempDirectory returns) was refused as an attack.
      val real =
        try {
          p.toRealPath()
        } catch (e: IOException) {
          return ArtifactRead.Refused("unresolvable: ${e.message}")
        }
      val workRoot = workdir.toPath().toRealPath()
      if (!real.startsWith(workRoot)) {
        return ArtifactRead.Refused("outside-workspace: resolved path escapes the pod workdir")
      }
      if (attrs.size() > artifactByteCap) {
        return ArtifactRead.Refused("oversize: ${attrs.size()} bytes exceeds the $artifactByteCap cap")
      }
      return try {
        Files.newInputStream(p, LinkOption.NOFOLLOW_LINKS).use { input ->
          val bytes = input.readNBytes((artifactByteCap + 1).toInt())
          if (bytes.size > artifactByteCap) {
            ArtifactRead.Refused("oversize: grew past the $artifactByteCap cap during read")
          } else {
            ArtifactRead.Bytes(bytes)
          }
        }
      } catch (e: IOException) {
        ArtifactRead.Refused("unreadable: ${e.message}")
      }
    }

    /**
     * Kill the pod's whole process group, and SAY SO when we cannot. Falling back to
     * the direct child tree is precisely the failure the group contract exists to prevent —
     * a backgrounded grandchild survives — so it is reported once per pod rather than
     * swallowed by a `runCatching`, which would make a degraded kill indistinguishable from
     * a clean one in the record.
     */
    fun killLaunch(l: Launch) {
      val pgid = l.pgid
      val degradation =
        when {
          pgid == null -> "no-pgid" to l.pgidFailure
          !killPgid(pgid) ->
            "kill-uninvokable" to "/bin/kill could not be run for group $pgid on this host"
          else -> null
        }
      if (degradation != null && groupKillDegraded.compareAndSet(false, true)) {
        report(PodEvent.GroupKillDegraded(podId, degradation.first, degradation.second))
      }
      runCatching { Subprocess.killTree(l.process) } // wrapper + anything outside the group
      runCatching { l.process.waitFor(5, TimeUnit.SECONDS) }
    }

    fun killHandle(h: Handle) {
      killLaunch(h.launch)
      runCatching { h.client.close() } // after the kill: EOF has unparked the reader
    }
  }

  /**
   * One launched process and the group id the ENGINE established for it. The pgid is
   * deliberately not taken from anything the pod can write: the wrapper used to
   * echo it onto the agent's own stderr, so a pod that printed `PODGROUP:1` got the engine to
   * run `kill -KILL -- -1` — a same-uid SIGKILL of every process the lead owns, the lead
   * included. It now comes from the OS parent/child relation, which the pod cannot forge.
   */
  private class Launch(val process: Process) {
    @Volatile var pgid: Long? = null
      private set

    @Volatile var pgidFailure: String = "not resolved"
      private set

    /**
     * The group leader is the wrapper's own child: `set -m` puts the backgrounded job in a
     * fresh group whose id IS its pid, and that pid is the only child bash has. Poll for it —
     * the fork has not necessarily happened when `start()` returns — and validate: a pid of 0
     * means "the sender's own group" and 1 means "everything", so both are refused rather
     * than passed to kill.
     */
    fun resolvePgid(waitMs: Long) {
      val deadline = System.nanoTime() + waitMs * 1_000_000
      while (System.nanoTime() < deadline) {
        val child = process.toHandle().children().findFirst()
        if (child.isPresent) {
          val pid = child.get().pid()
          if (pid > 1) {
            pgid = pid
            return
          }
          pgidFailure = "the wrapper's child reported an unusable pid ($pid)"
          return
        }
        if (!process.isAlive) {
          pgidFailure = "the group wrapper died before it started the agent"
          return
        }
        Thread.sleep(10)
      }
      pgidFailure = "no agent process appeared under the group wrapper within ${waitMs}ms"
    }
  }

  private class Handle(val launch: Launch, val client: AcpClient, val sessionId: String)

  private sealed interface ArtifactRead {
    data class Bytes(val bytes: ByteArray) : ArtifactRead

    data class Refused(val reason: String) : ArtifactRead
  }

  /**
   * SIGKILL a whole process group — /bin/kill accepts a negative pid as "the group". Returns
   * whether the kill was INVOKABLE (the binary ran to completion), not whether it found a
   * group: killing an already-exited group exits non-zero and is an ordinary race, while a
   * host where `/bin/kill` cannot be run at all means every pod's tree is only
   * child-killable — a real degradation the caller reports.
   *
   * [pgid] is engine-derived and > 1 by construction ([Launch.resolvePgid]); the guard below
   * is a second lock on the same door, because the cost of being wrong here is a same-uid
   * SIGKILL storm rather than a failed kill.
   */
  private fun killPgid(pgid: Long): Boolean {
    if (pgid <= 1) return false
    return runCatching {
        ProcessBuilder("/bin/kill", "-KILL", "--", "-$pgid").start().waitFor(2, TimeUnit.SECONDS)
      }
      .getOrDefault(false)
  }

  companion object {
    /**
     * The spawn-side process-group contract, in one place: bash with job control ON
     * (`set -m`) backgrounds the agent — POSIX job control gives the backgrounded job its
     * OWN process group (pgid == pid) — then waits, forwarding the agent's exit status. The
     * agent's stdio stays on the wrapper's pipes (stdin is NOT the job-control /dev/null
     * case — that applies only when job control is off), so the ACP wire flows through
     * unchanged. The wrapper deliberately reports NOTHING: the engine reads the group id
     * from the OS, so the agent's stderr carries no control plane.
     */
    private const val GROUP_WRAPPER = "set -m\n\"\$@\" &\nwait \$!\n"

    fun groupWrapperArgv(argv: List<String>): List<String> =
      listOf("/bin/bash", "-c", GROUP_WRAPPER, "pod-group-wrap") + argv
  }
}
