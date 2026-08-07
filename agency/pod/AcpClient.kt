package com.geekinasuit.agency.pod

import com.agentclientprotocol.client.Client
import com.agentclientprotocol.client.ClientInfo
import com.agentclientprotocol.client.ClientOperationsFactory
import com.agentclientprotocol.client.ClientSession
import com.agentclientprotocol.common.ClientSessionOperations
import com.agentclientprotocol.common.Event
import com.agentclientprotocol.common.SessionCreationParameters
import com.agentclientprotocol.model.ContentBlock
import com.agentclientprotocol.model.Implementation
import com.agentclientprotocol.model.PermissionOption
import com.agentclientprotocol.model.PermissionOptionKind
import com.agentclientprotocol.model.RequestPermissionOutcome
import com.agentclientprotocol.model.RequestPermissionResponse
import com.agentclientprotocol.model.SessionUpdate
import com.agentclientprotocol.protocol.Protocol
import com.agentclientprotocol.protocol.ProtocolOptions
import com.agentclientprotocol.transport.StdioTransport
import com.agentclientprotocol.transport.Transport
import java.io.BufferedReader
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonElement

/**
 * The ask surfaced to the lead's permission decider — OUR model of an acp
 * session/request_permission, deliberately narrower than the wire type: the decider (the
 * PermissionBridge at the engine layer; a script in tests) sees identity + kind + the
 * offered option kinds and nothing else. SDK model types stop at this boundary.
 */
data class PermissionAsk(
  val sessionId: String,
  val toolCallId: String,
  val title: String,
  val toolKind: String,
  val optionKinds: List<String>,
)

/** The decider's answer. Anything other than an explicit [AllowOnce] — including a decider
 * that never answers (the ask deadline) — resolves as a rejection: fail-closed. */
sealed interface PermissionDecision {
  data object AllowOnce : PermissionDecision

  data object RejectOnce : PermissionDecision
}

/** Blocking decider seam. Called on an interruptible I/O thread, bounded by the client's
 * ask deadline — a decider may block on a human/gate without wedging the protocol.
 * CONTRACT: the decider must not perform authorization side effects itself (gate release
 * happens only AFTER an AllowOnce returns, at the engine's bridge), because an answer that
 * arrives after the deadline is DISCARDED — the fail-closed reject has already crossed the
 * wire. Deciders should honor thread interrupts, but the deadline does not depend on it:
 * the ask is answered on OUR clock either way and a stubborn decider thread is abandoned
 * to the shared pool. */
fun interface PermissionDecider {
  fun decide(ask: PermissionAsk): PermissionDecision
}

/** Outcome of one prompt turn: the agent's stop reason plus the session updates that
 * arrived during the turn (tool-call updates, message chunks — OUR audit surface).
 * [updates] deliberately carries the SDK's [SessionUpdate] payloads: agent-authored and
 * UNTRUSTED, evidence to be validated/translated at the engine's journal boundary — never
 * authorization input (a bypassing agent forges COMPLETED/"tool-effect:ran" for free;
 * the battery's NON_ASKING/DELAYED_BYPASS profiles prove it). */
data class TurnResult(val stopReason: String, val updates: List<SessionUpdate>)

/** A turn (or handshake) exceeded its caller-supplied deadline. On expiry the SDK sends a
 * cancel notification to the agent and waits a BOUNDED [GRACEFUL_CANCEL_MS] courtesy for
 * its acknowledgement, so the observed overshoot is deadline + ~[GRACEFUL_CANCEL_MS], never
 * open-ended. The real enforcement for a stalled pod is the process-group kill on a
 * clock the caller owns — this exception is the trigger, not the cleanup. */
class AcpDeadlineExceeded(message: String) : RuntimeException(message)

/** Any non-deadline failure of a client call (agent process died mid-call, protocol error,
 * malformed response). The lead-owned type the engine classifies on — SDK exception types
 * appear only in the [cause] chain, for forensics, never in the seam's contract. */
class AcpCallFailed(message: String, cause: Throwable?) : RuntimeException(message, cause)

/** Bound on the SDK's post-deadline cancellation courtesy (see [AcpDeadlineExceeded]).
 * Deliberately small: a pod that blew its deadline is about to be killed by the engine —
 * the courtesy exists so a HEALTHY agent hears the cancel, not to extend the wait. */
private const val GRACEFUL_CANCEL_MS = 100L

/** Caps on inbound wire text from the agent process.
 * The agent is UNTRUSTED and its stdout feeds the lead's heap: without caps a hostile pod
 * can OOM the SUBSTRATE — a blast-radius inversion no engine wall-clock prevents — with
 * one newline-free blob or an endless update flood. Breach = protocol abuse: the read
 * flow fails, the transport reaches CLOSING/CLOSED, in-flight calls fail fast as
 * [AcpCallFailed], and the engine's restart policy owns what happens next. Generous by
 * intent: no honest agent frames a 1 MiB NDJSON line or streams 256 MiB in one pod
 * lifetime — these bound damage, they do not tune throughput. */
private const val MAX_WIRE_LINE_CHARS = 1 shl 20
private const val MAX_WIRE_TOTAL_CHARS = 256L shl 20

/** Bounded readLine (plain blocking; runs inside runInterruptible on the I/O pool): stops
 * at '\n' (swallowing '\r'), null on clean EOF, throws once a single line exceeds
 * [maxChars] — the un-skippable case, since a partial giant line has no safe resync. */
private fun readLineBounded(reader: BufferedReader, maxChars: Int): String? {
  val buf = StringBuilder()
  while (true) {
    val c = reader.read()
    if (c < 0) return if (buf.isEmpty()) null else buf.toString()
    if (c == '\n'.code) return buf.toString()
    if (c == '\r'.code) continue
    buf.append(c.toChar())
    if (buf.length > maxChars) {
      throw AcpCallFailed("agent wire abuse: line exceeds $maxChars chars", null)
    }
  }
}

/**
 * ACP client: the lead-side half of the pod transport, wrapping the
 * pinned acp-jvm SDK ([com.agentclientprotocol.client.Client]) over an agent process's
 * stdio. This class is the SEAM where the wire's CONTROL types end and the lead's own
 * types begin: failures and permission surfaces are lead-owned ([PermissionAsk],
 * [AcpDeadlineExceeded]/[AcpCallFailed] — SDK exceptions only in cause chains). The
 * update PAYLOADS ([TurnResult.updates], [allUpdates]) deliberately remain SDK
 * [SessionUpdate] values: agent-authored, UNTRUSTED evidence for the engine's journal
 * boundary to validate/translate — never authorization input, and never to be folded raw
 * into journals/UI (the type system does not mark them trusted, so
 * the contract must). Testing honesty: this client + the SDK encode OUR MODEL of acp;
 * the deterministic battery covers our handling of that model, and the real-adapter
 * canary covers the wire.
 *
 * THREADING (a supervised task with explicit shutdown, not a bare daemon thread): the
 * client OWNS its executors — one supervisor thread hosting the protocol scope, two I/O
 * threads for the blocking stdio read/write — and [close] closes the protocol (transport +
 * cancellation of pending requests both ways), closes the streams, and shuts both
 * executors down with a bounded await. The blocking facade
 * ([initialize]/[newSession]/[prompt]) is single-caller, ENFORCED: an overlapping call is
 * refused fail-fast with [AcpCallFailed] rather than trusted away;
 * each call carries an explicit deadline ([AcpDeadlineExceeded], fail-closed,
 * never a third-party default) and a transport-death watcher ([AcpCallFailed], fast — a
 * corpse is distinguishable from a stall). Inbound wire text is capped per line and
 * cumulatively ([MAX_WIRE_LINE_CHARS]/[MAX_WIRE_TOTAL_CHARS]) so an untrusted pod cannot
 * OOM the lead.
 *
 * PERMISSIONS: every session/request_permission the agent routes lands in the
 * [PermissionDecider], bounded by [askDeadlineMs]. An unanswered ask is DENIED at the
 * deadline — fail-closed, decided by us, never by the agent's own timeout default. Only an
 * explicit [PermissionDecision.AllowOnce] selects an allow option; everything else selects
 * the agent's reject option (or answers Cancelled when the agent offered none). [askCount]
 * is the observable the rp-liveness preflight (engine layer) keys on.
 *
 * This class does NOT spawn or kill the agent process — the engine owns the process
 * lifecycle (spawn-side process-group contract, kill-tree, restart policy are
 * engine duties). It only speaks the wire over streams it is handed.
 */
class AcpClient(
  agentStdout: InputStream,
  agentStdin: OutputStream,
  private val decider: PermissionDecider,
  private val askDeadlineMs: Long,
  private val maxLineChars: Int = MAX_WIRE_LINE_CHARS,
  private val maxTotalChars: Long = MAX_WIRE_TOTAL_CHARS,
  name: String = "acp-client",
) : AutoCloseable {

  data class Handshake(
    val protocolVersion: String,
    val agentName: String?,
    /** The agent's self-reported build version (e.g. the adapter package version) — the
     * wire-level half of the pin check: the canary asserts it EQUALS the pinned
     * version, so a drifted install fails the handshake validation, not just a file diff. */
    val agentVersion: String?,
    val loadSession: Boolean,
  )

  private val supervisor =
    Executors.newSingleThreadExecutor { r -> Thread(r, "$name-supervisor").also { it.isDaemon = true } }
  private val io =
    Executors.newFixedThreadPool(2) { r -> Thread(r, "$name-io").also { it.isDaemon = true } }

  private val scope =
    CoroutineScope(SupervisorJob() + supervisor.asCoroutineDispatcher() + CoroutineName(name))

  private val reader = agentStdout.bufferedReader()
  private val rawOut = agentStdin

  /** Count of permission asks the agent actually routed — the preflight's observable. */
  val askCount = AtomicInteger(0)

  private val _allUpdates = CopyOnWriteArrayList<SessionUpdate>()

  /** Every session update the agent has sent, in arrival order, never cleared — the audit
   * surface (exposed as a CAST-PROOF unmodifiable view: the JVM erasure of a Kotlin List
   * is a MutableList, so the bare backing list could be cast and
   * cleared). Contents are agent-authored and UNTRUSTED (see [TurnResult]).
   * Two feeds, disjoint by SDK design: updates DURING a turn arrive through the prompt
   * flow (appended by [prompt]'s collector), updates OUTSIDE any turn (e.g. from a
   * session's postInitialize) arrive through [ClientSessionOperations.notify]. Growth in
   * COUNT is bounded by the deadlines every call carries plus the engine's pod
   * wall-clock; growth in SIZE is bounded by the wire caps — a hostile agent can flood
   * only for as long as the lead lets its process live, and never past the caps. */
  val allUpdates: List<SessionUpdate>
    get() = Collections.unmodifiableList(_allUpdates)

  private val transport =
    StdioTransport(
      scope,
      io.asCoroutineDispatcher(),
      input =
        flow {
          var total = 0L
          while (true) {
            val line = runInterruptible { readLineBounded(reader, maxLineChars) } ?: break
            total += line.length
            if (total > maxTotalChars) {
              throw AcpCallFailed("agent wire abuse: cumulative inbound exceeds $maxTotalChars chars", null)
            }
            emit(line)
          }
        },
      output = { line ->
        rawOut.write(line.toByteArray(Charsets.UTF_8))
        rawOut.write('\n'.code)
        rawOut.flush()
      },
      name = name,
    )

  private val protocol =
    Protocol(
      scope,
      transport,
      ProtocolOptions(
        gracefulRequestCancellationTimeout = GRACEFUL_CANCEL_MS.milliseconds,
        protocolDebugName = name,
      ),
    )
  private val client = Client(protocol)
  private val sessions = ConcurrentHashMap<String, ClientSession>()
  private val callLock = ReentrantLock()

  /** One operations object per session, closing over the REAL session id the SDK handed
   * the factory — so every [PermissionAsk] is attributable to its asking session. */
  private fun operationsFor(sessionId: String): ClientSessionOperations =
    object : ClientSessionOperations {
      override suspend fun requestPermissions(
        toolCall: SessionUpdate.ToolCallUpdate,
        permissions: List<PermissionOption>,
        _meta: JsonElement?,
      ): RequestPermissionResponse {
        askCount.incrementAndGet()
        val ask =
          PermissionAsk(
            sessionId = sessionId,
            toolCallId = toolCall.toolCallId.value,
            title = toolCall.title ?: "",
            toolKind = toolCall.kind?.name ?: "UNKNOWN",
            optionKinds = permissions.map { it.kind.name },
          )
        // The ONE round-trip with genuinely unbounded latency: bound it on OUR
        // clock, UNCONDITIONALLY. The decider runs DETACHED on Dispatchers.IO — the shared
        // elastic pool, deliberately NOT this client's 2-thread io pool (the transport's
        // read/write jobs occupy that; a parked decider there would wedge the wire) — and
        // the RPC awaits it cancellably: at the deadline the await resumes and the reject
        // crosses the wire even if the decider swallows interrupts (a plain
        // runInterruptible-in-withTimeout would inherit structured concurrency's wait on
        // the child — fail-closed held hostage by decider
        // interruptibility). The post-deadline cancel is a courtesy; a stubborn decider thread is
        // abandoned to the pool and its late answer discarded (see [PermissionDecider]).
        // Expiry or a decider crash resolves to null → fail-closed below.
        val pending =
          scope.async(Dispatchers.IO) {
            runInterruptible { runCatching { decider.decide(ask) }.getOrNull() }
          }
        val decision = withTimeoutOrNull(askDeadlineMs) { pending.await() }
        if (decision == null) pending.cancel()
        // Fail-closed, including on MENU AMBIGUITY: only an explicit AllowOnce selects an
        // allow option, and only when the agent offered exactly ONE ALLOW_ONCE — with
        // several, "which allow" is a semantic the agent steers by menu order
        // (broad-vs-narrow), so the client refuses to guess:
        // Cancelled. A deadline expiry, a decider crash, or an explicit reject all select
        // the agent's reject option — and an agent that offered NO reject option gets
        // Cancelled, never a defaulted allow.
        val chosen =
          when (decision) {
            PermissionDecision.AllowOnce ->
              permissions
                .filter { it.kind == PermissionOptionKind.ALLOW_ONCE }
                .takeIf { it.size == 1 }
                ?.single()
            else -> permissions.firstOrNull { it.kind == PermissionOptionKind.REJECT_ONCE }
          }
        return RequestPermissionResponse(
          chosen?.let { RequestPermissionOutcome.Selected(it.optionId) }
            ?: RequestPermissionOutcome.Cancelled
        )
      }

      override suspend fun notify(notification: SessionUpdate, _meta: JsonElement?) {
        _allUpdates += notification // out-of-turn updates only; in-turn ones ride the flow
      }
    }

  init {
    protocol.start() // starts the transport's read/write jobs on the owned executors
  }

  /** Run the initialize handshake; throws [AcpDeadlineExceeded] if the agent does not
   * answer in time (a dead-on-arrival or version-skewed agent must fail fast). */
  fun initialize(timeoutMs: Long): Handshake = blocking("initialize", timeoutMs) {
    val info =
      client.initialize(
        ClientInfo(implementation = Implementation(name = "agency-lead", version = "dev"))
      )
    Handshake(
      protocolVersion = info.protocolVersion.toString(),
      agentName = info.implementation?.name,
      agentVersion = info.implementation?.version,
      loadSession = info.capabilities.loadSession,
    )
  }

  /** Create a session rooted at [cwd] — CALLER-TRUSTED (the engine passes the pod's
   * sealed workdir; nothing here validates or canonicalizes the path — an untrusted
   * string must never reach this argument). [meta] rides session/new's `_meta` verbatim —
   * the lead-owned configuration channel: the Claude adapter reads its SDK
   * options (settingSources, bounds) from `_meta.claudeCode.options`. LEAD-AUTHORED only,
   * by the same trust rule as [cwd]. */
  fun newSession(cwd: File, timeoutMs: Long, meta: JsonElement? = null): String =
    blocking("session/new", timeoutMs) {
      val session =
        client.newSession(
          SessionCreationParameters(cwd.absolutePath, mcpServers = emptyList(), _meta = meta),
          ClientOperationsFactory { sessionId, _ -> operationsFor(sessionId.value) },
        )
      sessions[session.sessionId.value] = session
      session.sessionId.value
    }

  /**
   * Drive one prompt turn to completion. Updates arriving during the turn are captured in
   * the result IN ORDER, collected locally per call — one session's turn can never absorb
   * another session's out-of-turn notifications. On deadline expiry this throws
   * [AcpDeadlineExceeded] after the SDK's bounded [GRACEFUL_CANCEL_MS] cancel courtesy —
   * the caller owns the process and kills it (a stalled pod dies on a clock we own).
   * A turn whose flow completes with NO PromptResponse fails as [AcpCallFailed], never a
   * defaulted END_TURN (success is reported, not presumed).
   */
  fun prompt(sessionId: String, text: String, timeoutMs: Long): TurnResult =
    blocking("session/prompt", timeoutMs) {
      val session = sessions[sessionId] ?: error("unknown session '$sessionId'")
      val turnUpdates = mutableListOf<SessionUpdate>() // single collector — no races
      var stop: String? = null
      session.prompt(listOf(ContentBlock.Text(text = text))).collect { ev ->
        when (ev) {
          // In-turn updates arrive through the prompt flow (the SDK routes them to the
          // active prompt's channel, NOT to operations.notify — that path is out-of-turn
          // only), so this collector feeds both the turn result and the audit surface.
          is Event.SessionUpdateEvent -> {
            turnUpdates += ev.update
            _allUpdates += ev.update
          }
          is Event.PromptResponseEvent -> stop = ev.response.stopReason.name
        }
      }
      val stopReason =
        stop ?: throw AcpCallFailed("session/prompt flow completed without a PromptResponse", null)
      TurnResult(stopReason, turnUpdates.toList())
    }

  /** True once [close] has fully shut the owned executors down — the teardown observable. */
  fun supervisorTerminated(): Boolean = supervisor.isTerminated && io.isTerminated

  /** Explicit shutdown: close the protocol (which closes the transport and cancels
   * pending requests both ways), close the streams, shut both executors down bounded.
   * Idempotent. Never touches the process — and NOTE the unblocking caveat: closing an
   * in-process pipe unparks its reader, but a real agent process's stdout read is NOT
   * interruptible, so the ENGINE must kill the process (forcing EOF) before calling this;
   * [supervisorTerminated] is the observable for whether teardown fully completed. */
  override fun close() {
    runCatching { protocol.close() }
    runCatching { scope.cancel() }
    runCatching { reader.close() }
    runCatching { rawOut.close() }
    supervisor.shutdownNow()
    io.shutdownNow()
    supervisor.awaitTermination(2, TimeUnit.SECONDS)
    io.awaitTermination(2, TimeUnit.SECONDS)
  }

  /** Deadline → [AcpDeadlineExceeded]; everything else → [AcpCallFailed]. The seam's
   * contract: the engine classifies failures on lead-owned types only — SDK exception
   * types stay in the cause chain. Dead-agent coverage: the entry guard refuses a call on
   * an already-closed transport with a clear message, and the per-call WATCHER cancels the
   * CALL JOB ITSELF the moment the transport reaches CLOSING/CLOSED (after first settling
   * the SDK's pending map) — cancelling the job rather than only pending requests makes
   * the fast-fail independent of request-registration timing (a request not yet registered
   * when death is observed — e.g. prompt()'s flow still spinning up — is torn down all the
   * same), so death before, during, or after registration resolves fast as
   * [AcpCallFailed], never by burning the caller's deadline on a corpse. */
  private fun <T> blocking(what: String, timeoutMs: Long, op: suspend () -> T): T {
    // Single-caller ENFORCED: an overlapping call is an engine bug —
    // refuse it loudly and fast rather than interleave collectors/watchers on one wire.
    if (!callLock.tryLock()) {
      throw AcpCallFailed("$what refused: concurrent call on a single-caller client", null)
    }
    try {
      val st = transport.state.value
      if (st == Transport.State.CLOSED || st == Transport.State.CLOSING) {
        throw AcpCallFailed("$what refused: agent transport already ${st.name.lowercase()}", null)
      }
      return try {
        runBlocking {
          val callJob = coroutineContext[Job]!!
          val watcher = launch {
            transport.state.first { it == Transport.State.CLOSING || it == Transport.State.CLOSED }
            protocol.cancelPendingOutgoingRequests(CancellationException("agent transport closed"))
            callJob.cancel(CancellationException("agent transport closed"))
          }
          try {
            withTimeout(timeoutMs) { op() }
          } finally {
            watcher.cancel()
          }
        }
      } catch (e: TimeoutCancellationException) {
        throw AcpDeadlineExceeded(
          "$what exceeded its ${timeoutMs}ms deadline (+ up to ${GRACEFUL_CANCEL_MS}ms cancel courtesy)"
        )
      } catch (e: AcpDeadlineExceeded) {
        throw e
      } catch (e: AcpCallFailed) {
        throw e
      } catch (t: Throwable) {
        throw AcpCallFailed("$what failed (transport ${transport.state.value})", t)
      }
    } finally {
      callLock.unlock()
    }
  }
}
