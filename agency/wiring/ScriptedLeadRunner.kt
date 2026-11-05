package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.lead.ApprovalBoundaryStoppedException
import com.geekinasuit.agency.lead.FakePodRunner
import com.geekinasuit.agency.lead.FileTicketSource
import com.geekinasuit.agency.lead.LeadAuth
import com.geekinasuit.agency.lead.ScriptedCognition
import com.geekinasuit.agency.lead.ThreadTimerService
import com.geekinasuit.agency.lead.ticketLead
import com.geekinasuit.agency.nostr.AuthSpecSigning
import com.geekinasuit.agency.nostr.ReconnectingPublisher
import com.geekinasuit.agency.nostr.ReconnectingSubscription
import com.geekinasuit.agency.nostr.RecipientKey
import com.geekinasuit.agency.nostr.RelayAuth
import com.geekinasuit.agency.nostr.RelayConfig
import com.geekinasuit.agency.nostr.RelayConnection
import com.geekinasuit.agency.nostr.RelayNotifier
import com.geekinasuit.agency.nostr.SecretKeyHex
import com.geekinasuit.agency.pod.PodAuthMode
import com.geekinasuit.agency.pod.PodProvider
import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.pod.PodTransport
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.SqliteStore
import com.geekinasuit.agency.shared.text.inert
import java.io.File
import java.io.PrintStream
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.system.exitProcess

/**
 * A ticket lead with no model in it, run against a relay:
 *
 *  `scripted_lead --journal DIR --component ID --ticket-file F --spec F --relay URL --lead-key-file F
 *  [--auth none|nip42]`
 *
 * It runs the ticket workflow with [ScriptedCognition] and [FakePodRunner], and takes no flag that
 * chooses either: there is no model and no real pod anywhere in it. Its gates are real. Each gate it
 * opens is announced over the relay, gift-wrapped to every bip340 key the spec's allow-list names,
 * and approvals arrive over the relay into the host's accept boundary ([ApprovalIngress]).
 *
 * The root the spec must verify against is fixed in the built binary
 * (`--//agency/wiring:pinned_root=PUB`): no flag, file or setting of the runner's chooses it. A binary
 * built without one refuses to start. What the JVM runs is the launch command's to say, though: a
 * command that puts its own classpath ahead of the binary's can shadow the pin, as it can shadow
 * this class. So the pin holds only where the command that starts the lead is not the invoker's to
 * edit, as under a supervisor whose unit the operator owns.
 *
 * DIR is the lead's journal directory and ID its component; the ticket file lists ticket refs, one
 * per line. The lead key file holds the lead's secret key as 64 hex
 * characters: the key it signs notices with and that approvals are wrapped to. `--auth` (default
 * nip42) is whether the relay needs NIP-42.
 *
 * It runs until it is stopped (SIGTERM or SIGINT) or the lead's loop ends. Stopped by a signal, it
 * closes what it opened and exits with the signal's status, as the JVM does (143 for SIGTERM, 130
 * for SIGINT). Those are exit statuses, not deaths by signal, so a systemd unit must list them in
 * `SuccessExitStatus=` for a stop to read as clean. Otherwise: exit 0 when stopped from within; 1 on
 * a refusal at start (no pinned root, a spec that does not load, a key file that does not read);
 * 2 on a usage error, checked before any file is read; 3 when the lead's loop ends on a fault (its
 * approval boundary stopped, or a wake that failed), which a supervisor answers by starting it
 * again; 4 when the approval ingress ends, likewise. Each failure prints one line on stderr saying
 * why, inert ([inert]).
 */
object ScriptedLeadRunner {
  /** Where the build puts the pinned root, on the binary's classpath. */
  const val PINNED_ROOT_RESOURCE = "agency/wiring/pinned-root.txt"

  /** Which of the runner's two relay connections a [run] `connect` call opens. */
  enum class RelayUse {
    /** The notice publisher's connection. */
    NOTICES,

    /** The approval ingress's connection, used for nothing else ([ApprovalIngress]). */
    APPROVALS,
  }

  @JvmStatic
  fun main(args: Array<String>) {
    val pinnedRoot =
      ScriptedLeadRunner::class.java.classLoader.getResourceAsStream(PINNED_ROOT_RESOURCE)?.use {
        it.readBytes().toString(Charsets.UTF_8).trim()
      } ?: ""
    val done = CountDownLatch(1)
    val code =
      try {
        run(pinnedRoot, args.toList(), System.err) { stop ->
          // The hook stops the lead and waits for run to close what it opened, so the journal and the
          // relay connections end cleanly. It does not halt: halting would skip the JVM's own exit
          // work, the deletion of the native libraries the JDBC and secp256k1 jars extract to tmp.
          Runtime.getRuntime().addShutdownHook(
            thread(start = false, name = "scripted-lead-stop") {
              stop()
              done.await(SHUTDOWN_WAIT_SECONDS, TimeUnit.SECONDS)
            }
          )
        }
      } finally {
        done.countDown()
      }
    exitProcess(code)
  }

  /**
   * Run the lead under [pinnedRoot] (the root the build fixed, or empty for none) until it stops,
   * and return the exit code. [started] is handed, once the lead is built and before its loop
   * starts, a function that stops it; [run] returns once the loop has ended and everything it opened
   * is closed. [connect] opens a relay connection for a use, authenticating with a fresh holder of
   * the key file at the given path; a test replaces it.
   */
  fun run(
    pinnedRoot: String,
    args: List<String>,
    err: PrintStream,
    connect: (use: RelayUse, url: String, keyFile: String) -> RelayConnection = ::defaultConnect,
    started: (stop: () -> Unit) -> Unit,
  ): Int {
    val options =
      try {
        Options.of(flagsOf(args, FLAGS))
      } catch (x: IllegalArgumentException) {
        return usage(err, x.message ?: "bad arguments")
      }
    if (pinnedRoot.isEmpty()) {
      return refuse(err, 1, "this binary was built without a pinned root (--//agency/wiring:pinned_root=PUB)")
    }
    val auth: LeadAuth
    val recipients: Set<RecipientKey>
    try {
      RecipientKey.of(pinnedRoot)
      auth = loadLeadAuth(options.spec, pinnedRoot)
      recipients = approversOf(auth)
      readSecretKeyFile(options.leadKeyFile).clear()
    } catch (x: IllegalArgumentException) {
      return refuse(err, 1, x.message.orEmpty())
    } catch (x: java.io.IOException) {
      return refuse(err, 1, "${x.javaClass.simpleName}: ${x.message.orEmpty()}")
    }

    var store: SqliteStore? = null
    var publisher: ReconnectingPublisher? = null
    var notifier: RelayNotifier? = null
    var ingress: ApprovalIngress? = null
    val ingressEnded = AtomicReference<String?>(null)
    try {
      store =
        try {
          SqliteStore(options.journal, componentId = options.component)
        } catch (x: Exception) {
          return refuse(err, 1, "the journal did not open: ${x.javaClass.simpleName}: ${x.message.orEmpty()}")
        }
      val noticePublisher =
        ReconnectingPublisher({ connect(RelayUse.NOTICES, options.relay, options.leadKeyFile) }, TIMEOUT, options.auth)
          .also { publisher = it }
      notifier = holding(readSecretKeyFile(options.leadKeyFile)) { RelayNotifier(it, noticePublisher) }
      val host =
        ticketLead(
          store = store,
          cognition = ScriptedCognition(),
          podRunner = FakePodRunner(),
          podSpec = SCRIPTED_POD_SPEC,
          ticketSource = FileTicketSource(File(options.ticketFile)),
          workdir = File(options.journal),
          effects = EffectReceiver(options.journal),
          leadAuth = auth,
          timers = ThreadTimerService(),
          gateOpenSink = NostrGateOpenSink(notifier, recipients, TIMEOUT),
        )
      ingress =
        holding(readSecretKeyFile(options.leadKeyFile)) { key ->
          ApprovalIngress(
            newConnection = { connect(RelayUse.APPROVALS, options.relay, options.leadKeyFile) },
            connectTimeout = TIMEOUT,
            auth = options.auth,
            backoff = BACKOFF,
            liveness = LIVENESS,
            resubscribeBackoff = RESUBSCRIBE_BACKOFF,
            leadKey = key,
            approvalsAwaited = host::approvalsAwaited,
            // Stderr first, so a journal that fails to take the report still leaves the line.
            reporter = { problem ->
              err.println("scripted_lead: ${inert(problem)}")
              host.reportProblem(problem)
            },
            sink = host::injectApproval,
          )
        }
      ingress.start { reason ->
        ingressEnded.set(reason)
        host.shutdown()
      }
      started { host.shutdown() }
      try {
        host.runLoop()
      } catch (x: ApprovalBoundaryStoppedException) {
        return refuse(err, 3, x.message.orEmpty())
      } catch (x: Throwable) {
        // The loop rethrows whatever ended a wake, an Error included; each is a fault to restart on.
        return refuse(err, 3, "the lead's loop ended on ${x.javaClass.simpleName}: ${x.message.orEmpty()}")
      }
      return ingressEnded.get()?.let { refuse(err, 4, it) } ?: 0
    } catch (x: Exception) {
      // Anything the setup throws before the loop starts; the loop's own end is classified above.
      return refuse(err, 1, "the lead did not start: ${x.javaClass.simpleName}: ${x.message.orEmpty()}")
    } finally {
      ingress?.close()
      publisher?.close()
      notifier?.close()
      store?.close()
    }
  }

  /** [build] something that takes over [key], clearing [key] if it throws first. */
  private fun <T> holding(key: SecretKeyHex, build: (SecretKeyHex) -> T): T =
    try {
      build(key)
    } catch (x: Throwable) {
      key.clear()
      throw x
    }

  /** The bip340 keys the spec's allow-list names: the approvers a gate-open is announced to. The
   * spec signer refuses a principal with none, but the auth is checked as it is loaded, not as it was
   * signed. */
  internal fun approversOf(auth: LeadAuth): Set<RecipientKey> {
    val keys =
      auth.allowList.principals
        .flatMap { it.keys }
        .filter { it.schemeId == AuthSpecSigning.ROOT_SCHEME }
        .map { RecipientKey.of(it.publicKey) }
        .toSet()
    require(keys.isNotEmpty()) { "the spec names no bip340 key to announce a gate to" }
    return keys
  }

  private class Options(
    val journal: String,
    val component: String,
    val ticketFile: String,
    val spec: String,
    val relay: String,
    val leadKeyFile: String,
    val auth: RelayAuth,
  ) {
    companion object {
      fun of(flags: Map<String, String>): Options {
        val relay = flags.required("--relay")
        require(relay.startsWith("ws://") || relay.startsWith("wss://")) { "--relay must be a ws:// or wss:// URL" }
        val auth =
          when (flags["--auth"] ?: "nip42") {
            "nip42" -> RelayAuth.Nip42(TIMEOUT)
            "none" -> RelayAuth.None
            else -> throw IllegalArgumentException("--auth is none or nip42")
          }
        return Options(
          flags.required("--journal"),
          flags.required("--component"),
          flags.required("--ticket-file"),
          flags.required("--spec"),
          relay,
          flags.required("--lead-key-file"),
          auth,
        )
      }
    }
  }

  // A fresh holder per connection, cleared here if the connection cannot even be built around it.
  private fun defaultConnect(@Suppress("UNUSED_PARAMETER") use: RelayUse, url: String, keyFile: String): RelayConnection {
    val key = readSecretKeyFile(keyFile)
    try {
      return RelayConnection(RelayConfig(url, key))
    } catch (x: Throwable) {
      key.clear()
      throw x
    }
  }

  private fun refuse(err: PrintStream, code: Int, why: String): Int {
    err.println("scripted_lead: ${inert(why)}")
    return code
  }

  private fun usage(err: PrintStream, why: String): Int {
    err.println("scripted_lead: ${inert(why)}")
    err.println(
      "usage: scripted_lead --journal DIR --component ID --ticket-file F --spec F --relay URL " +
        "--lead-key-file F [--auth none|nip42]"
    )
    return 2
  }

  /**
   * The pod profile journaled for each pod the lead spawns. [FakePodRunner] reads none of it: it
   * names no provider that runs, so the journal does not claim a model ran.
   */
  private val SCRIPTED_POD_SPEC =
    PodSpec(
      provider = PodProvider.LOCAL,
      model = "scripted",
      authMode = PodAuthMode.NONE,
      transport = PodTransport.HTTP,
      pinnedVersion = "scripted",
    )

  private val TIMEOUT: Duration = Duration.ofSeconds(10)
  // A lead added to a relay can take this long to notice. A shorter maximum hammers a relay that is
  // struggling or refusing it. The maximum is also how long a relay must stay heard from past its
  // EOSE for a connection to count as healthy, so one that drops connections sooner keeps the delay
  // at the maximum.
  private val BACKOFF = ReconnectingSubscription.Backoff(Duration.ofMillis(500), Duration.ofSeconds(60), jitter = 0.25)
  // An idle connection is pinged every 20 seconds, which also keeps one alive past a peer's idle limit
  // if the limit is longer than that, and is replaced after 20 more with no answer.
  private val LIVENESS = ReconnectingSubscription.Liveness(Duration.ofSeconds(20), Duration.ofSeconds(20))
  private val RESUBSCRIBE_BACKOFF = ReconnectingSubscription.Backoff(Duration.ofSeconds(1), Duration.ofSeconds(30))
  private const val SHUTDOWN_WAIT_SECONDS = 15L

  private val FLAGS = setOf("--journal", "--component", "--ticket-file", "--spec", "--relay", "--lead-key-file", "--auth")
}
