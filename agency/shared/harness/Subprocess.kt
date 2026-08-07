/**
 * Hardened subprocess runtime for wrapped agent harnesses: process-tree kill, daemon
 * reader threads, timeout, plus the non-optional wrapper duties — a constructed env
 * allowlist (ambient env leaks the controlling harness's session vars → 401s) and
 * explicit reader-executor reaping (a leaked executor pins the wrapper JVM).
 * Model-agnostic — no claude specifics live here.
 */
package com.geekinasuit.agency.shared.harness

import java.io.File
import java.nio.file.Files
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

/** Terminal outcome of a subprocess: captured streams + exit + wall time. */
data class ProcResult(
    val stdout: String,
    val stderr: String,
    val exit: Int,
    val timedOut: Boolean,
    val wallMs: Long,
)

/**
 * A started process with DAEMON reader threads draining stdout/stderr. The daemon flag
 * is what actually lets the wrapper JVM exit: a reader can block in a native read() that
 * neither shutdownNow's interrupt nor stream-close reliably unblocks, so a non-daemon
 * reader would pin the JVM forever. shutdownNow is still called on every
 * exit path to release the pool promptly once the readers DO finish.
 */
class RunningProc(val process: Process, val startedAtMs: Long) {
  private val executor =
      Executors.newFixedThreadPool(2) { r -> Thread(r).also { it.isDaemon = true } }
  val stdoutF: Future<String> =
      executor.submit<String> { process.inputStream.bufferedReader().readText() }
  val stderrF: Future<String> =
      executor.submit<String> { process.errorStream.bufferedReader().readText() }

  /**
   * SIGKILL the whole tree NOW; returns kill latency ms (signal → snapshot dead OR the
   * reap deadline elapsed — see below). Snapshot semantics, stated honestly: descendants
   * are captured BEFORE the root dies (after root death `descendants()` is empty —
   * survivors get reparented and invisible), and the wait covers exactly that snapshot;
   * processes spawned between snapshot and kill are inherently uncovered. Fine for
   * shallow trees; pods that shell out deep trees want a process-group kill.
   * The descendant reap is BOUNDED (a 10s deadline): a wedged (e.g. uninterruptible-sleep)
   * descendant must not hang the abort path forever — past the deadline the returned
   * latency reflects the deadline, not observed death.
   */
  fun killTreeNow(): Long {
    val t0 = System.nanoTime()
    val snapshot = process.toHandle().descendants().toList()
    snapshot.forEach { it.destroyForcibly() }
    process.destroyForcibly()
    process.waitFor(10, TimeUnit.SECONDS)
    // Bound the descendant reap: a wedged (uninterruptible-sleep) descendant must not
    // hang the abort path forever. Past the deadline we return latency regardless.
    val reapDeadlineNs = System.nanoTime() + 10_000_000_000L
    while (snapshot.any { it.isAlive } && System.nanoTime() < reapDeadlineNs) Thread.sleep(5)
    executor.shutdownNow()
    return (System.nanoTime() - t0) / 1_000_000
  }

  fun await(timeoutSec: Int): ProcResult {
    val finished = process.waitFor(timeoutSec.toLong(), TimeUnit.SECONDS)
    if (!finished) Subprocess.killTree(process)
    val out = try { stdoutF.get(5, TimeUnit.SECONDS) } catch (_: Exception) { "" }
    val err = try { stderrF.get(5, TimeUnit.SECONDS) } catch (_: Exception) { "" }
    executor.shutdownNow()
    val exit = if (finished) process.exitValue() else 124
    return ProcResult(out, err, exit, !finished, System.currentTimeMillis() - startedAtMs)
  }
}

object Subprocess {
  /**
   * Env allowlist for wrapped-pod processes. A pod
   * spawned with the ambient env inherits the controlling harness's own session
   * variables (ANTHROPIC_BASE_URL + CLAUDE_CODE_* / CLAUDECODE nested-session state)
   * and tries to authenticate as a child of that session — "401 OAuth access token
   * has been revoked". Pods therefore get a CONSTRUCTED env: this allowlist from the
   * parent, plus whatever the wrapper adds explicitly. (Also the right AGENCY-008
   * taint posture — ambient env is an unaudited channel.)
   *
   * DEPLOY NOTE (AGENCY-010): this list suffices for a plain local deployment of
   * live claude. A proxied / custom-CA deployment additionally needs the
   * child to see HTTP(S)_PROXY / NO_PROXY / NODE_EXTRA_CA_CERTS / SSL_CERT_* — pass
   * those through the explicit [start] `env` map (applied on top of this allowlist) or
   * extend the list. Deny-by-default stays: session/secret vars (ANTHROPIC_*,
   * CLAUDE_CODE_*) are never allowlisted.
   */
  val POD_ENV_ALLOWLIST =
      listOf("HOME", "PATH", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL", "TERM")

  /** Kill a process and all its descendants (grandchildren etc.), then the root. */
  fun killTree(process: Process) {
    process.toHandle().descendants().toList().forEach { it.destroyForcibly() }
    process.destroyForcibly()
  }

  /**
   * The shared ProcessBuilder construction behind [start] and the piped engines
   * (AcpPodEngine spawns through this too — one copy of the env posture, not two): work
   * dir + the [cleanEnv]/[env] rules exactly as [start] documents them. Stdin is NOT
   * redirected here — [start] adds its /dev/null redirect; a protocol engine keeps the
   * pipe (the child's stdin IS the wire).
   */
  fun processBuilder(
      cmd: List<String>,
      workDir: File,
      env: Map<String, String> = emptyMap(),
      cleanEnv: Boolean,
  ): ProcessBuilder {
    val pb = ProcessBuilder(cmd)
    pb.directory(workDir)
    if (cleanEnv) {
      pb.environment().clear()
      POD_ENV_ALLOWLIST.forEach { k -> System.getenv(k)?.let { pb.environment()[k] = it } }
    }
    env.forEach { (k, v) -> pb.environment()[k] = v }
    return pb
  }

  /**
   * Start [cmd] under the hardened runtime. [cleanEnv] has NO default and MUST be set — the
   * env posture is a security decision the caller makes consciously, not one it inherits:
   * `true` = constructed env (clear the child env, re-add only [POD_ENV_ALLOWLIST] + [env];
   * the pod posture — ambient env leaks the controlling harness's session vars → 401s, and
   * the AGENCY-008 taint channel); `false` = inherit the full ambient env (a trusted local
   * tool only, never a wrapped agent). [env] is applied on top either way.
   */
  fun start(
      cmd: List<String>,
      workDir: File,
      env: Map<String, String> = emptyMap(),
      cleanEnv: Boolean,
  ): RunningProc {
    val pb = processBuilder(cmd, workDir, env, cleanEnv)
    // A child that reads stdin (claude -p stalls ~3s waiting on a pipe) gets EOF, not a hang.
    pb.redirectInput(File("/dev/null"))
    return RunningProc(pb.start(), System.currentTimeMillis())
  }

  /** [start] the process then [RunningProc.await] it. [cleanEnv] is required — see [start]. */
  fun run(
      cmd: List<String>,
      workDir: File,
      env: Map<String, String> = emptyMap(),
      timeoutSec: Int = 180,
      cleanEnv: Boolean,
  ): ProcResult = start(cmd, workDir, env, cleanEnv).await(timeoutSec)

  /**
   * A throwaway temp dir for a harness working directory. Cleanup is BEST-EFFORT:
   * `deleteOnExit()` only fires at JVM exit and no-ops on a non-empty dir, so a
   * long-lived wrapper that spawns many turns must delete its own workdirs (a managed
   * cleanup handle is tracked in AGENCY-010). Fine for short-lived / test callers.
   */
  fun tempDir(prefix: String): File =
      Files.createTempDirectory("$prefix-").toFile().also { it.deleteOnExit() }
}
