package com.geekinasuit.agency.pod

import com.geekinasuit.agency.shared.harness.Subprocess
import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The scheduled real-adapter canary (testing honesty): the
 * deterministic battery covers OUR MODEL of acp (FakeAcpAgent shares the SDK with the
 * client), so the WIRE itself — the pinned `@agentclientprotocol/claude-agent-acp` build
 * that production pods launch — is validated here, post-merge and NON-GATING, on a
 * schedule. What it validates:
 *
 *  1. PIN COHERENCE: [ClaudeAdapterPin.VERSION] (the code const) == package.json ==
 *     package-lock.json == the INSTALLED package's own version — a drifted install or a
 *     half-updated pin fails loudly instead of running skewed.
 *  2. THE PINNED HANDSHAKE: launches the real adapter under node through the REAL
 *     [ClaudeAdapterProfile] (same argv/env construction production uses, constructed
 *     allowlist env, phone-home lanes denied) and asserts the initialize handshake
 *     negotiates [ClaudeAdapterPin.PROTOCOL_VERSION] and self-reports the pinned version.
 *
 * COLD-START DISCIPLINE (binding): the canary COLD-STARTS every run — fresh temp
 * CLAUDE_CONFIG_DIR seeded only
 * from the checked-in fixture (agency/pod/canary-fixture), fresh temp workdir, nothing
 * carried between runs, and its output is TELEMETRY ONLY (a pass/fail report for CI);
 * nothing it produces is hydrated into any agent's context. It runs no session and no
 * prompt — initialize is pure protocol — so no model is invoked at all.
 *
 * Exit codes: 0 = all gates pass · 1 = a gate failed · 2 = usage/environment error.
 */
object PodCanary {

  /** Handshake gate, pure so the core test drives it against [FakeAcpAgent]: the
   * failures list is empty on a faithful handshake. The agent NAME is deliberately
   * reported-not-gated: the pin is package+version (what the lockfile governs); the
   * name string is the adapter's own label and free to vary across releases. */
  fun handshakeGate(
    handshake: AcpClient.Handshake,
    expectedProtocol: String,
    expectedVersion: String,
  ): List<String> {
    val failures = mutableListOf<String>()
    if (handshake.protocolVersion != expectedProtocol) {
      failures +=
        "protocol-version skew: agent negotiated acp v${handshake.protocolVersion}, " +
          "pin expects v$expectedProtocol"
    }
    when (handshake.agentVersion) {
      null -> failures += "agent reported no version in its initialize handshake"
      expectedVersion -> Unit
      else ->
        failures +=
          "adapter-version skew: agent self-reports ${handshake.agentVersion}, " +
            "pin expects $expectedVersion"
    }
    return failures
  }

  /**
   * Pin coherence over the four authorities: code const, package.json, package-lock.json,
   * installed package. Returns (failures, notes) — notes are the passing evidence lines
   * the report prints, so a green run still SHOWS what it checked.
   */
  fun pinGate(adapterDir: File, expectedVersion: String): Pair<List<String>, List<String>> {
    val failures = mutableListOf<String>()
    val notes = mutableListOf<String>()
    val pkg = ClaudeAdapterPin.PACKAGE

    fun jsonField(file: File, extract: (kotlinx.serialization.json.JsonElement) -> String?): String? =
      try {
        if (!file.isFile) null else extract(Json.parseToJsonElement(file.readText()))
      } catch (_: Exception) {
        null
      }

    val declared =
      jsonField(File(adapterDir, "package.json")) {
        it.jsonObject["dependencies"]?.jsonObject?.get(pkg)?.jsonPrimitive?.content
      }
    if (declared == null) {
      failures += "package.json missing or does not declare $pkg (${File(adapterDir, "package.json")})"
    } else if (declared != expectedVersion) {
      failures += "package.json declares $pkg@$declared, code pins $expectedVersion"
    } else {
      notes += "package.json declares $pkg@$declared"
    }

    val locked =
      jsonField(File(adapterDir, "package-lock.json")) {
        it.jsonObject["packages"]?.jsonObject?.get("node_modules/$pkg")?.jsonObject
          ?.get("version")?.jsonPrimitive?.content
      }
    if (locked == null) {
      failures += "package-lock.json missing or does not lock $pkg (${File(adapterDir, "package-lock.json")})"
    } else if (locked != expectedVersion) {
      failures += "package-lock.json locks $pkg@$locked, code pins $expectedVersion"
    } else {
      notes += "package-lock.json locks $pkg@$locked"
    }

    val installedPkgJson = File(adapterDir, "node_modules/$pkg/package.json")
    val installed = jsonField(installedPkgJson) { it.jsonObject["version"]?.jsonPrimitive?.content }
    if (installed == null) {
      failures +=
        "adapter not installed at $installedPkgJson — run `npm ci --ignore-scripts` in ${adapterDir.path}"
    } else if (installed != expectedVersion) {
      failures += "installed adapter is $pkg@$installed, code pins $expectedVersion"
    } else {
      notes += "installed tree carries $pkg@$installed"
    }
    return failures to notes
  }

  /** The adapter's entry file under a lockfile-governed install of [adapterDir]. */
  fun adapterEntry(adapterDir: File): File =
    File(adapterDir, "node_modules/${ClaudeAdapterPin.PACKAGE}/dist/index.js")

  @JvmStatic
  fun main(args: Array<String>) {
    val opts = args.toList().windowed(2, 2, partialWindows = true).associate {
      it[0] to it.getOrNull(1)
    }
    val adapterDir = opts["--adapter-dir"]?.let(::File)
    val node = opts["--node"]?.let(::File)
    val fixtureDir = opts["--fixture-dir"]?.let(::File)
    val timeoutMs = opts["--timeout-ms"]?.toLongOrNull() ?: 30_000L
    if (adapterDir == null || !adapterDir.isAbsolute || node == null || !node.isAbsolute) {
      System.err.println(
        "usage: pod_canary --adapter-dir <abs path to agency/pod/adapter> --node <abs node binary> " +
          "[--fixture-dir <abs cold-start seed>] [--timeout-ms N]"
      )
      exitProcess(2)
    }

    val failures = mutableListOf<String>()
    val notes = mutableListOf<String>()

    // Gate 1: pin coherence (no process needed — file evidence only).
    val (pinFailures, pinNotes) = pinGate(adapterDir, ClaudeAdapterPin.VERSION)
    failures += pinFailures
    notes += pinNotes

    // Gate 2: the pinned handshake, through the REAL profile — only worth attempting when
    // the install is present and coherent (a skewed install would fail the handshake gate
    // with a confusing version message the pin gate already states plainly).
    if (pinFailures.isEmpty()) {
      failures += runHandshake(node, adapterDir, fixtureDir, timeoutMs, notes)
    } else {
      notes += "handshake skipped: pin gate failed first"
    }

    for (n in notes) println("POD-CANARY note: $n")
    if (failures.isEmpty()) {
      println("POD-CANARY OK: pin ${ClaudeAdapterPin.PACKAGE}@${ClaudeAdapterPin.VERSION}, acp v${ClaudeAdapterPin.PROTOCOL_VERSION}")
      exitProcess(0)
    }
    for (f in failures) println("POD-CANARY FAIL: $f")
    exitProcess(1)
  }

  /** Launch the adapter, run initialize, gate the handshake, kill the process. Returns
   * gate failures (launch/handshake trouble is a failure too — the canary's job is to
   * notice, not to survive). */
  private fun runHandshake(
    node: File,
    adapterDir: File,
    fixtureDir: File?,
    timeoutMs: Long,
    notes: MutableList<String>,
  ): List<String> {
    // Cold start (the binding discipline above): fresh temp config + workdir every run; the
    // ONLY seed is the checked-in fixture. README.md is the fixture's own documentation,
    // not seed data.
    val configDir = Files.createTempDirectory("pod-canary-config").toFile()
    val workdir = Files.createTempDirectory("pod-canary-work").toFile()
    fixtureDir?.listFiles()?.filter { it.isFile && it.name != "README.md" }?.forEach {
      it.copyTo(File(configDir, it.name))
    }

    val profile =
      ClaudeAdapterProfile(
        nodeBinary = node,
        adapterEntry = adapterEntry(adapterDir),
        configDir = configDir,
      )
    val spec = PodSpec.claudeAdapter(model = "pod-canary-unused", maxTurns = 1, maxBudgetUsd = 0.01)
    return handshakeWithProcess(
      argv = profile.argv(spec, workdir),
      workdir = workdir,
      env = profile.env(spec),
      expectedProtocol = ClaudeAdapterPin.PROTOCOL_VERSION,
      expectedVersion = ClaudeAdapterPin.VERSION,
      timeoutMs = timeoutMs,
      notes = notes,
    )
  }

  /**
   * The handshake lifecycle against a REAL agent process: launch [argv] in [workdir] under
   * the constructed allowlist env (cleanEnv, [env] on top), run initialize, gate the
   * handshake, and ALWAYS reap on the way out — in this order:
   *
   *   1. KILL the process tree (forces EOF on its stdio),
   *   2. THEN close the client.
   *
   * The order is load-bearing, not tidiness (the client's own close caveat): a live agent
   * holds its stdout open, the client's transport reader blocks inside a stream read
   * HOLDING the stream lock, and close() must take that same lock — so a close attempted
   * while the agent lives parks forever, and cleanup placed after it never runs. The kill
   * delivers the EOF that unparks the reader; close then completes.
   *
   * Public, like [handshakeGate], so the core test can drive the WHOLE lifecycle against
   * the fake-agent subprocess — which, exactly like the real adapter, completes initialize
   * and then stays alive serving until killed.
   */
  fun handshakeWithProcess(
    argv: List<String>,
    workdir: File,
    env: Map<String, String>,
    expectedProtocol: String,
    expectedVersion: String,
    timeoutMs: Long,
    notes: MutableList<String>,
  ): List<String> {
    val proc =
      try {
        Subprocess.processBuilder(argv, workdir, env, cleanEnv = true).start()
      } catch (e: Exception) {
        return listOf("adapter process failed to launch: ${e.message}")
      }
    // The adapter's stderr is untrusted diagnosis text. Drain it to EOF — closing the read
    // end mid-run would turn the adapter's own stderr writes into EPIPE, i.e. the canary
    // could CAUSE the handshake failure it exists to observe — and mirror only a bounded
    // head to our own stderr, so a red run carries the adapter's startup diagnosis without
    // an unbounded echo. Same drain-everything, bound-what-you-keep shape as the engine's
    // stderr thread.
    val stderrThread =
      Thread {
        proc.errorStream.bufferedReader().useLines { lines ->
          var mirrored = 0
          for (line in lines) {
            if (mirrored < 50) {
              System.err.println("adapter-stderr: ${line.take(500)}")
              mirrored++
            }
          }
        }
      }
    stderrThread.isDaemon = true
    stderrThread.start()

    // Nullable-var shape, as in the engine's establish: constructing the client is itself
    // fallible (its init starts the transport jobs on its owned executors), so it happens
    // INSIDE the reaped try, and the finally closes whatever was actually constructed.
    var client: AcpClient? = null
    return try {
      val c =
        AcpClient(
          agentStdout = proc.inputStream,
          agentStdin = proc.outputStream,
          decider = { PermissionDecision.RejectOnce }, // no session runs; nothing should ask
          askDeadlineMs = 1_000,
          name = "pod-canary",
        )
      client = c
      val handshake =
        try {
          c.initialize(timeoutMs)
        } catch (e: Exception) {
          return listOf("initialize handshake failed: ${e.message}")
        }
      notes +=
        "handshake: agent '${handshake.agentName}' v${handshake.agentVersion}, " +
          "acp v${handshake.protocolVersion}, loadSession=${handshake.loadSession}"
      handshakeGate(handshake, expectedProtocol, expectedVersion)
    } catch (e: Exception) {
      // Any other lifecycle throw is a failures line like launch trouble above — the
      // canary's job is to notice, not to propagate a raw exception.
      listOf("adapter handshake lifecycle failed: ${e.message}")
    } finally {
      // Kill FIRST (EOF unparks the client's blocked readers), close SECOND — see KDoc.
      proc.toHandle().descendants().forEach { runCatching { it.destroyForcibly() } }
      proc.destroyForcibly()
      runCatching { proc.waitFor(5, TimeUnit.SECONDS) }
      runCatching { client?.close() }
    }
  }
}
