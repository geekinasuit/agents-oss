package com.geekinasuit.agency.nostr

import java.net.ConnectException
import java.net.URI
import java.net.UnknownHostException
import java.net.http.HttpClient
import java.net.http.HttpConnectTimeoutException
import java.net.http.HttpTimeoutException
import java.net.http.WebSocket
import java.net.http.WebSocketHandshakeException
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletionStage
import java.util.concurrent.ExecutionException
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

// The transport (2a.4 step 3b): the socket that carries the wire format NostrWire defines. It
// dials a relay, receives its messages, and answers a NIP-42 challenge — the part of step 3 that
// binds and connects, kept OUT of :nostr so that module stays pure and hermetic. This class is
// still substrate MECHANISM: it takes the relay URL and the lead key as required configuration
// (§REPO_SEAM — which relay and which key are policy that lives in coach, never defaulted here),
// and it never makes an authorization decision. What arrives from the relay is DATA: it is parsed
// by NostrWire's TOTAL codec, never trusted, and never reaches the fold as a nostr type (A4-3).
//
// LISTENING NEVER AUTHORIZES. authenticate() proves WHO we are TO THE RELAY (a NIP-42 event signed
// with the lead key), which is a transport concern — it gates what the relay will carry, not what
// the lead will release. The release decision stays in auth's fold over an approval's own detached
// signature, which this class cannot reach and never sees.
//
// NEVER THROWS for a remote-side fault (matches OpenAiCompatHarness). A refused connection, a
// rejected handshake, a dropped socket, a relay that never answers — each comes back as a
// classified [ConnectResult] / [AuthResult], because the caller is a wake loop that journals a
// fact and carries on, not one that can catch an exception mid-ceremony. It fails CLOSED: any
// ambiguity in the auth handshake yields "not authenticated", never a hopeful "probably fine".
//
// THREE INGRESS BOUNDS, all defence against a hostile relay, none of them trusting it:
//   * SIZE (agents-oss #36): the ACCUMULATED inbound buffer, not a single frame. An unbounded
//     accumulator IS the DoS.
//   * DEPTH (agents-oss #38): the JSON nesting of a received message, bounded BEFORE the kotlinx
//     parser sees it — that parser StackOverflows on deep enough nesting, and a message well under
//     the size cap can nest far past that, so the size cap cannot close this.
//   * COUNT: the number of complete-but-unconsumed messages queued. The WebSocket demand model
//     delivers message FRAGMENTS and demand must be replenished per fragment (both verified
//     empirically), so the socket's read rate is decoupled from the caller's drain rate; without a
//     count bound a relay could flood valid small messages into an unbounded queue.

/**
 * Which relay to speak to, and the lead key material to authenticate with.
 *
 * A value object rather than constructor arguments, so a second relay is data. Both fields are
 * REQUIRED and carry NO default: §REPO_SEAM keeps the relay URL and the keypair in coach, and a
 * default here is exactly how this mechanism would quietly acquire a relay or a key it was never
 * configured with. The key is taken CONCRETELY as secret-key hex, not behind an injectable signer
 * interface: A4-7 forbids a daemon-side remote-signer seam, so there is deliberately no place to
 * slot a NIP-46 remote signer into this transport.
 *
 * Plaintext `ws://` is permitted alongside `wss://`, and that is a confidentiality/deployment
 * choice left to the caller, NOT a hole in this gate. Plaintext lets a network observer SEE the
 * events carried, but it cannot weaken authorization INTEGRITY: the lead's release decision is a
 * fold over each approval's own detached BIP-340 signature, re-verified after transport, so an
 * approval forged or tampered on the wire is rejected regardless of scheme; and NIP-42 only gates
 * what the relay agrees to serve back to us. `ws://` is what a loopback relay and the test doubles
 * speak, so refusing it here would buy no integrity and break legitimate local deployments. The
 * confidentiality call (must this link be encrypted in transit?) belongs with the relay URL in
 * coach, which is where the scheme is chosen.
 */
data class RelayConfig(
  val relayUrl: String,
  val leadSecretKeyHex: String,
) {
  init {
    require(relayUrl.startsWith("ws://") || relayUrl.startsWith("wss://")) {
      "relayUrl must be a ws:// or wss:// URL, was '$relayUrl'"
    }
    // Structural validation only: 32 bytes of hex. That the key derives a valid pubkey is proven
    // by the native at authenticate() time and classified there, so construction stays native-free.
    require(leadSecretKeyHex.length == 64 && leadSecretKeyHex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
      "leadSecretKeyHex must be 64 hex characters (a 32-byte secret key)"
    }
  }

  // The secret key must never reach a log line or an exception string. A data class prints every
  // property from its generated toString, so override to redact the key. equals/hashCode keep the
  // generated behaviour (both fields); redaction is a printing concern only.
  override fun toString(): String = "RelayConfig(relayUrl='$relayUrl', leadSecretKeyHex=<redacted>)"
}

/** Why a [RelayConnection.connect] attempt did not establish a socket. Distinct causes because a
 * caller deciding whether a relay is even present must not confuse "nothing is there" with "it was
 * there and refused the upgrade". */
enum class ConnectFailure {
  /** Nothing was listening (connection refused). */
  REFUSED,

  /** The connect deadline elapsed with no established socket. */
  TIMEOUT,

  /** The host did not resolve. */
  UNKNOWN_HOST,

  /** The endpoint was reachable but rejected the WebSocket upgrade (a non-101 response). */
  HANDSHAKE,

  /** Some other transport-level fault while establishing the socket. */
  TRANSPORT,
}

/** The outcome of [RelayConnection.connect]. Branch on [Connected]; never thrown. */
sealed interface ConnectResult {
  /** The socket is established and receiving. */
  object Connected : ConnectResult

  /** No socket was established. [failure] classifies why, [detail] is the substrate's words. */
  data class Failed(val failure: ConnectFailure, val detail: String) : ConnectResult
}

/** The outcome of [RelayConnection.authenticate]. Only [Authenticated] means the relay accepted
 * us; everything else is fail-closed and MUST be treated as "not authenticated". Never thrown. */
sealed interface AuthResult {
  /** The relay accepted our NIP-42 auth event (`OK ... true`). */
  object Authenticated : AuthResult

  /** The relay explicitly rejected our auth event (`OK ... false`). Fail-closed. */
  data class Refused(val message: String) : AuthResult

  /** The handshake could not complete: no challenge arrived, no matching OK arrived, the event
   * could not be signed or sent, or the connection failed mid-handshake. Fail-closed. */
  data class Failed(val detail: String) : AuthResult
}

/**
 * One connection to one relay. Construct it, [connect], [authenticate], then [receive] messages
 * (publish and subscribe arrive in 3b-2), and [close] when done. Single inbound consumer: one
 * caller drains [receive] (the auth handshake here; a subscription loop in 3b-2).
 *
 * Built on the JDK's [WebSocket]: no new dependency, matching the [HttpClient] the harness already
 * uses. The receive path is a callback [Listener] on the JDK's own executor thread; it hands typed
 * [RelayMessage]s to the caller through a bounded queue. It is deliberately NOT bridged into a
 * coroutine Channel/Flow: the WebSocket's demand model (one `request(1)` per delivery = exactly one
 * outstanding listener invocation) already IS the backpressure, and it is what lets the fragment
 * accumulator below be a plain [StringBuilder] with no lock — the listener is invoked serially. A
 * Channel would add a second backpressure system that can disagree with the first, and its full
 * state either blocks inside the callback (wedging that serialized thread) or drops. (AcpClient
 * uses Flow only because its acp-jvm SDK's Transport takes a CoroutineScope; nothing in
 * java.net.http.WebSocket does.)
 */
class RelayConnection(
  private val config: RelayConfig,
  // Injectable for tests; production uses the JDK default. The DEPTH guard's headroom (that
  // MAX_JSON_DEPTH parses below the parser's overflow depth, re-checked by the ceiling-depth test)
  // is scoped to the default executor's thread-stack size. A caller passing its own HttpClient backed
  // by a custom executor with smaller-stack threads lowers that overflow depth and owns that margin.
  private val httpClient: HttpClient = HttpClient.newHttpClient(),
) {
  // Complete, parsed messages awaiting the caller. Bounded (see COUNT bound above); offered to,
  // never put to — a blocking put on the listener thread would wedge the serialized callback.
  private val inbound = LinkedBlockingQueue<RelayMessage>(MAX_QUEUED_MESSAGES)

  // Set once, by whichever of onError / onClose / a bounds breach fires first. A non-null value
  // means the socket is dead; every wait checks it so a caller never blocks past the connection's
  // life. AtomicReference so the listener thread and the caller thread agree on the first cause.
  private val failure = AtomicReference<String?>(null)

  @Volatile private var webSocket: WebSocket? = null
  private val connectCalled = AtomicBoolean(false)
  private val closed = AtomicBoolean(false)
  private val secureRandom = SecureRandom()

  /** Dial the relay and start receiving, or return a classified failure. One-shot: a second call
   * returns [ConnectFailure.TRANSPORT]. [timeout] bounds the connect+handshake. Never throws. */
  fun connect(timeout: Duration): ConnectResult {
    if (!connectCalled.compareAndSet(false, true)) {
      return ConnectResult.Failed(ConnectFailure.TRANSPORT, "connect() already called")
    }
    val future =
      try {
        httpClient
          .newWebSocketBuilder()
          .connectTimeout(timeout)
          .buildAsync(URI(config.relayUrl), Listener())
      } catch (e: Exception) {
        // A malformed URI or builder misuse: a configuration fault, classified rather than thrown.
        return ConnectResult.Failed(
          ConnectFailure.TRANSPORT,
          "could not start connection: ${e.javaClass.simpleName}: ${e.message}",
        )
      }
    return try {
      webSocket = future.get(timeout.toMillis() + CONNECT_SLACK_MILLIS, TimeUnit.MILLISECONDS)
      ConnectResult.Connected
    } catch (e: ExecutionException) {
      future.cancel(true)
      classifyConnectFailure(e.cause ?: e)
    } catch (e: TimeoutException) {
      future.cancel(true)
      ConnectResult.Failed(ConnectFailure.TIMEOUT, "connect timed out after ${timeout.toMillis()}ms")
    } catch (e: InterruptedException) {
      Thread.currentThread().interrupt()
      future.cancel(true)
      ConnectResult.Failed(ConnectFailure.TRANSPORT, "connect interrupted")
    }
  }

  // The WebSocket client reports a connect failure as the future's cause, but may wrap it (an
  // IOException around a ConnectException, say), so walk the chain rather than match only the top.
  // HttpConnectTimeoutException is checked BEFORE HttpTimeoutException: it is a subclass, and though
  // both map to TIMEOUT here the ordering is the harness's and kept so a future split stays correct.
  private fun classifyConnectFailure(cause: Throwable): ConnectResult {
    var t: Throwable? = cause
    var depth = 0
    while (t != null && depth < CAUSE_CHAIN_LIMIT) {
      when (t) {
        is HttpConnectTimeoutException ->
          return ConnectResult.Failed(ConnectFailure.TIMEOUT, "connect timed out: ${t.message}")
        is HttpTimeoutException ->
          return ConnectResult.Failed(ConnectFailure.TIMEOUT, "connect timed out: ${t.message}")
        is ConnectException ->
          return ConnectResult.Failed(ConnectFailure.REFUSED, "connection refused: ${t.message}")
        is UnknownHostException ->
          return ConnectResult.Failed(ConnectFailure.UNKNOWN_HOST, "unknown host: ${t.message}")
        is WebSocketHandshakeException ->
          return ConnectResult.Failed(ConnectFailure.HANDSHAKE, "handshake rejected: ${t.message}")
      }
      t = t.cause
      depth++
    }
    return ConnectResult.Failed(
      ConnectFailure.TRANSPORT,
      "connect failed: ${cause.javaClass.simpleName}: ${cause.message}",
    )
  }

  /**
   * Answer the relay's NIP-42 challenge with a kind-22242 event signed by the lead key. Awaits the
   * `["AUTH", <challenge>]`, signs and sends `["AUTH", <event>]`, then awaits the relay's
   * `["OK", <our-event-id>, <accepted>, ...]`. [timeout] bounds each await.
   *
   * Fail-closed: a missing challenge, a missing OK, an OK for a DIFFERENT event id (a relay cannot
   * authenticate us by acknowledging someone else's event), a signing fault, or a dropped socket
   * all return a non-[Authenticated] result. Never throws.
   */
  fun authenticate(timeout: Duration): AuthResult {
    val ws = webSocket ?: return AuthResult.Failed("not connected")
    failure.get()?.let { return AuthResult.Failed("connection failed: $it") }
    val deadline = Instant.now().plus(timeout)

    val challenge =
      awaitMessage(deadline) { (it as? RelayMessage.Auth)?.challenge }
        ?: return AuthResult.Failed(failedDetail("no AUTH challenge within deadline"))

    val authEvent =
      try {
        buildAuthEvent(
          secretKeyHex = config.leadSecretKeyHex,
          relayUrl = config.relayUrl,
          challenge = challenge,
          createdAt = Instant.now().epochSecond,
          auxRandHex = freshAuxRandHex(),
        )
      } catch (e: Exception) {
        // No e.message: signing is the one exception path that handles the secret key, and its
        // message could echo key-derived material into a result string. The exception class is enough
        // to classify the fault; the detail stays out.
        return AuthResult.Failed("could not sign auth event: ${e.javaClass.simpleName}")
      }

    try {
      ws.sendText(authMessage(authEvent), true).get(timeout.toMillis(), TimeUnit.MILLISECONDS)
    } catch (e: Exception) {
      return AuthResult.Failed("could not send auth event: ${e.javaClass.simpleName}: ${e.message}")
    }

    val ok =
      awaitMessage(deadline) { msg -> (msg as? RelayMessage.Ok)?.takeIf { it.eventId == authEvent.id } }
        ?: return AuthResult.Failed(failedDetail("no OK for our auth event within deadline"))

    return if (ok.accepted) AuthResult.Authenticated else AuthResult.Refused(ok.message)
  }

  /**
   * Take the next relay message, or null if none arrives before [timeout] or the connection has
   * failed. Single-consumer. Never throws. (Publish/subscribe that produce messages to receive are
   * 3b-2; this exists now so the auth handshake and tests can drain the feed.)
   */
  fun receive(timeout: Duration): RelayMessage? {
    // Drain already-queued messages FIRST, even after the connection has ended: they were validly
    // received BEFORE the fault or close, and a subscription must not lose events it already got
    // just because the relay then hung up. Only once the queue is drained does a terminal condition
    // end the wait immediately, rather than blocking out the full timeout on a dead socket.
    // (The auth handshake's own awaits are the opposite — fail-fast on a fault — because auth needs
    // a LIVE socket to send its response; a receive only reads.)
    inbound.poll()?.let { return it }
    if (failure.get() != null) return null
    return try {
      inbound.poll(timeout.toMillis(), TimeUnit.MILLISECONDS)
    } catch (e: InterruptedException) {
      Thread.currentThread().interrupt()
      null
    }
  }

  /** Whether the connection has recorded a terminal fault (error, relay close, or a bounds breach).
   * Once true it stays true. */
  fun hasFailed(): Boolean = failure.get() != null

  /** The first terminal fault's classified reason, or null if the connection has not failed. The
   * substrate's words for what went wrong (a transport error, a relay close, or which bound). */
  fun failureReason(): String? = failure.get()

  /** Close the socket. Idempotent and bounded: a graceful close that does not complete in time is
   * dropped with an abort. Never throws. */
  fun close() {
    if (!closed.compareAndSet(false, true)) return
    val ws = webSocket ?: return
    try {
      ws.sendClose(WebSocket.NORMAL_CLOSURE, "").get(CLOSE_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
    } catch (e: Exception) {
      ws.abort()
    }
  }

  // Poll the inbound queue until [match] returns non-null, the deadline passes, or the connection
  // fails. Polls in slices so a fault recorded mid-wait is noticed promptly rather than only at the
  // deadline. A non-matching message (e.g. a NOTICE before the challenge) is discarded, not an
  // error: the caller is waiting for one specific message in a stream that may carry others.
  private fun <T : Any> awaitMessage(deadline: Instant, match: (RelayMessage) -> T?): T? {
    while (true) {
      if (failure.get() != null) return null
      val remaining = Duration.between(Instant.now(), deadline)
      if (remaining.isNegative || remaining.isZero) return null
      val sliceMillis = minOf(remaining.toMillis(), POLL_SLICE_MILLIS)
      val msg =
        try {
          inbound.poll(sliceMillis, TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
          Thread.currentThread().interrupt()
          return null
        } ?: continue
      match(msg)?.let { return it }
    }
  }

  private fun failedDetail(default: String): String =
    failure.get()?.let { "connection failed: $it" } ?: default

  private fun freshAuxRandHex(): String {
    val bytes = ByteArray(32)
    secureRandom.nextBytes(bytes)
    return bytes.joinToString("") { "%02x".format(it) }
  }

  private fun breach(ws: WebSocket, reason: String) {
    // Record the cause (first one wins) and drop the socket immediately. abort(), not sendClose():
    // a bounds breach is protocol abuse from a hostile relay, not a courteous shutdown to
    // handshake through.
    failure.compareAndSet(null, reason)
    ws.abort()
  }

  private inner class Listener : WebSocket.Listener {
    // The single logical message under assembly. onText delivers FRAGMENTS (empirically verified):
    // one message arrives across one or more onText calls, only the last with last==true. Without
    // accumulation a fragment would reach parseRelayMessage as if whole and a valid message would
    // be silently dropped. No lock: the WebSocket invokes the listener serially (its demand model),
    // so this is touched by one thread at a time.
    private val assembling = StringBuilder()

    override fun onOpen(webSocket: WebSocket) {
      webSocket.request(1)
    }

    override fun onText(webSocket: WebSocket, data: CharSequence, last: Boolean): CompletionStage<*>? {
      // SIZE bound on the ACCUMULATED buffer, checked on every fragment: the breach can arrive
      // mid-message (before last==true), at which point there is no message boundary to resync on,
      // so we abort rather than keep reading. Per-message; NO lifetime-total cap (unlike
      // AcpClient's MAX_WIRE_TOTAL_CHARS) — a relay connection is long-lived by design and a
      // lifetime cap would kill a healthy long-running feed.
      if (assembling.length.toLong() + data.length > MAX_MESSAGE_CHARS) {
        breach(webSocket, "inbound message exceeded $MAX_MESSAGE_CHARS characters")
        return null
      }
      assembling.append(data)
      val complete =
        if (last) {
          val text = assembling.toString()
          assembling.setLength(0)
          text
        } else {
          null
        }
      // Replenish demand on EVERY onText, per delivery (per fragment) — verified empirically: demand
      // is NOT auto-replenished for an overridden onText, and it is consumed per fragment, so a
      // multi-fragment message stalls mid-assembly without this. (onPing/onPong/onBinary are left
      // as JDK defaults, which replenish demand and auto-answer a ping — also verified.)
      webSocket.request(1)
      if (complete != null) deliver(webSocket, complete)
      return null
    }

    private fun deliver(webSocket: WebSocket, text: String) {
      // DEPTH bound, applied BEFORE the parser: scan the JSON nesting depth and breach the moment it
      // exceeds MAX_JSON_DEPTH. kotlinx's parser recurses once per structural container (`[` / `{`)
      // and StackOverflows on deep enough nesting, so a too-deep frame must be rejected before the
      // parse. The scan is STRING-AWARE: a bracket inside a JSON string literal is content the parser
      // scans without recursing, not nesting, so it tracks string state — with escape handling — and
      // counts only STRUCTURAL brackets. That string awareness is what lets it bound DEPTH rather than
      // a total-opener COUNT: a wide-but-shallow message (a kind-3 with thousands of sibling `p` tags)
      // nests only a few deep and is DELIVERED, where a total-opener count would have aborted the
      // connection on the sibling count alone (agents-oss #41). A `]` inside a string cannot make it
      // UNDER-count real nesting: the parser does not recurse on in-string brackets either, and a
      // malformed frame that desyncs the two can only make the scan OVER-count (the safe direction —
      // reject a frame the parser might have survived, never admit one it cannot). Iterative, so the
      // guard itself cannot overflow the stack it protects.
      var depth = 0
      var inString = false
      var escaped = false
      for (c in text) {
        when {
          escaped -> escaped = false
          inString ->
            when (c) {
              '\\' -> escaped = true
              '"' -> inString = false
            }
          c == '"' -> inString = true
          c == '[' || c == '{' -> {
            if (++depth > MAX_JSON_DEPTH) {
              breach(webSocket, "inbound message exceeded $MAX_JSON_DEPTH JSON nesting depth")
              return
            }
          }
          c == ']' || c == '}' -> if (depth > 0) depth--
        }
      }
      // TOTAL parse: null on any malformed input. Junk from a relay is noise the fold never trusts,
      // so drop it and keep the connection — only a bounds breach (an attack) closes the socket.
      // The opener guard above is PREVENTION, and it is deliberately the ONLY protection against a
      // parser overflow here: kotlinx's recursive parser throws a StackOverflowError on deep enough
      // nesting (an Error the codec lets propagate). No catch wraps this parse, for two reasons.
      // First, it is unreachable at MAX_JSON_DEPTH: the ceiling-depth test parses a
      // MAX_JSON_DEPTH-deep frame on the real listener thread every CI run, so the guard keeps
      // depth below what the parser chokes on — a margin the ceiling cell re-checks each build, not
      // one proven once. Second, a catch would be the wrong tool even if
      // it were reachable: were a too-deep frame ever to reach the parser, the JDK WebSocket catches
      // the Error thrown from this callback and delivers it to onError (confirmed empirically), so the
      // connection fails CLOSED — it does not wedge. A catch(Throwable) here would instead INTERCEPT
      // that Error and try to run breach()/abort() on a stack the overflow has just exhausted, trading
      // a clean fail-closed for an attempted recovery that cannot reliably complete. So there is no
      // catch; correctness rests on the guard, which the ceiling-depth cell re-checks every build.
      val message = parseRelayMessage(text) ?: return
      // offer, not put: a full queue must not block this serialized listener thread. A relay
      // flooding complete messages past the COUNT bound is treated as the abuse it is.
      if (!inbound.offer(message)) {
        breach(webSocket, "inbound queue exceeded $MAX_QUEUED_MESSAGES unconsumed messages")
      }
    }

    override fun onError(webSocket: WebSocket, error: Throwable) {
      failure.compareAndSet(null, "transport error: ${error.javaClass.simpleName}: ${error.message}")
    }

    override fun onClose(webSocket: WebSocket, statusCode: Int, reason: String): CompletionStage<*>? {
      failure.compareAndSet(null, "relay closed: $statusCode '$reason'")
      return null
    }
  }

  companion object {
    /** SIZE bound (#36): the accumulated inbound buffer ceiling, measured in CHARS — the unit the
     * StringBuilder accumulator counts, deliberately not bytes (a multi-byte UTF-8 content field
     * makes the two diverge; don't "correct" this to a byte budget). 1 MiB of chars, matching
     * AcpClient's per-line cap; comfortably above a NIP-44 max-plaintext event (~90 KB, and base64
     * so its chars ≈ its bytes). */
    const val MAX_MESSAGE_CHARS: Long = 1L shl 20

    /** DEPTH bound (#38): the ceiling on JSON structural nesting depth in one message. A string-aware
     * scan (see deliver()) measures how deep the structural `[` / `{` nest — ignoring brackets inside
     * string literals — and breaches ABOVE this ceiling, so a wide-but-shallow message is delivered
     * while a genuinely over-deep one is rejected before the kotlinx parser (agents-oss #41). Far above
     * any auth/gate message (a handful of levels) and below the depth at which that parser
     * StackOverflows on this listener's thread. That it sits below the overflow depth is not trusted to
     * any single measured number (the overflow depth is not a constant — it shifts run to run, and with
     * the thread's stack size): instead the ceiling-depth test parses a MAX_JSON_DEPTH-deep frame on the
     * real listener thread every CI run, so a parser or stack change that lowered the overflow depth
     * under this ceiling would fail the build. */
    const val MAX_JSON_DEPTH: Int = 1024

    /** COUNT bound: complete-but-unconsumed messages the queue holds before a flood is treated as
     * abuse. Generous — the auth handshake drains within a handful. */
    const val MAX_QUEUED_MESSAGES: Int = 1024

    // Backstop beyond the builder's own connectTimeout, so a stuck future.get cannot hang forever.
    private const val CONNECT_SLACK_MILLIS: Long = 1_000L

    // Wait granularity for an auth await, so a mid-wait fault is seen without waiting out the whole
    // deadline.
    private const val POLL_SLICE_MILLIS: Long = 50L

    private const val CLOSE_TIMEOUT_MILLIS: Long = 2_000L

    // How far to unwrap a connect failure's cause chain before giving up on classifying it.
    private const val CAUSE_CHAIN_LIMIT: Int = 5
  }
}
