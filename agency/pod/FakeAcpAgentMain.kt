@file:JvmName("FakeAcpAgentMain")

package com.geekinasuit.agency.pod

import java.io.File
import java.util.concurrent.CountDownLatch

/**
 * Subprocess entry point for [FakeAcpAgent]: the engine's process red paths
 * — kill/restart, process-group kill of a deep tree, wall-clock deadline, executor reaping
 * — need a REAL OS process on the other end of the pipes, not an in-process pipe pair. The
 * client-level battery keeps using the in-process form; this binary is what
 * [FixtureAgentProfile] launches.
 *
 * testonly by construction (its BUILD target is testonly): it exists for the deterministic
 * battery and the engine fixture, never for production wiring.
 *
 * Usage: fake-acp-agent --variant HONEST [--artifact-action WRITE_FILE]
 *                       [--artifact-content TEXT] [--symlink-target PATH] [--marker ID]
 */
fun main(args: Array<String>) {
  var variant = FakeAgentVariant.HONEST
  var action = FakeArtifactAction.NOTHING
  var content = "fake artifact\n"
  var symlinkTarget = "/etc/hosts"
  var i = 0
  while (i < args.size) {
    val flag = args[i]
    val value = args.getOrNull(i + 1) ?: error("flag '$flag' needs a value")
    when (flag) {
      "--variant" -> variant = FakeAgentVariant.valueOf(value)
      "--artifact-action" -> action = FakeArtifactAction.valueOf(value)
      "--artifact-content" -> content = value
      "--symlink-target" -> symlinkTarget = value
      // Behavior-free: it exists to make THIS process identifiable in the host process
      // table. A test that finds its agent by scanning for the main class alone matches a
      // stale agent from an earlier failed run, or a sibling under a sharded/parallel run,
      // and then asserts process-group facts about the WRONG process.
      "--marker" -> Unit
      // An arbitrary line the agent writes to its OWN stderr before speaking protocol. The
      // engine treats agent stderr as untrusted diagnosis and nothing else; the battery uses
      // this to pin that — a pod emitting `PODGROUP:1` must not steer any kill.
      "--stderr-line" -> System.err.println(value)
      else -> error("unknown flag '$flag'")
    }
    i += 2
  }

  val agent =
    FakeAcpAgent(
      variant = variant,
      input = System.`in`,
      output = System.out,
      name = "fake-acp-agent-proc",
      artifactAction = action,
      artifactContent = content,
      symlinkTarget = symlinkTarget,
    )
  // The agent's protocol jobs run on its own daemon executors; hold the main thread until
  // the process is killed (the engine owns this process's lifetime) or stdin reaches EOF.
  Runtime.getRuntime().addShutdownHook(Thread { runCatching { agent.close() } })
  CountDownLatch(1).await()
}

/** Builds the argv that launches [main] as a subprocess — the one shared way every battery
 * that needs a real killable OS agent on the other end of the pipes constructs it. */
object FakeAgentLauncher {

  /**
   * The fake agent's launch command: THIS JVM's own `java`, the calling test's classpath
   * ABSOLUTIZED, and FakeAcpAgentMain. Deliberately NOT a bazel launcher script — that
   * script derives its embedded JDK from the working directory, and a pod's working
   * directory is the WORKSPACE, so it looks for `java` under a temp workspace and dies
   * 127. Absolutizing matters for the same reason: bazel hands a test a classpath of
   * runfiles-RELATIVE entries, which mean nothing once the child's cwd is the pod
   * workspace. A pod launch has to be cwd- and env-independent; this is what that costs.
   *
   * Null when no usable `java` exists (running outside bazel) — the caller skips.
   */
  fun agentCommand(vararg args: String): List<String>? {
    val java = File(File(System.getProperty("java.home"), "bin"), "java")
    if (!java.canExecute()) return null
    val cwd = File(System.getProperty("user.dir"))
    val classpath =
      System.getProperty("java.class.path")
        .split(File.pathSeparator)
        .filter { it.isNotBlank() }
        .joinToString(File.pathSeparator) { entry ->
          val f = File(entry)
          if (f.isAbsolute) f.path else File(cwd, entry).absolutePath
        }
    return listOf(
      java.absolutePath,
      // The same args again, ahead of the classpath, as an inert system property: on
      // Linux the JDK reads /proc/<pid>/cmdline into a bounded buffer for
      // ProcessHandle.info().commandLine(), and the absolutized bazel classpath alone
      // overflows it — so any argv token AFTER the classpath (a battery's --marker) is
      // invisible to a process-table scan there. Stamped ahead of the classpath, the
      // marker precedes the token that overflows the buffer. macOS reads full argv
      // either way.
      "-Dagency.fake.agent.args=" + args.joinToString(" "),
      "-cp",
      classpath,
      "com.geekinasuit.agency.pod.FakeAcpAgentMain",
    ) + args
  }
}
