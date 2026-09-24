package com.geekinasuit.agency.nostr

import com.geekinasuit.agency.shared.json.jsonMayNestDeeperThan
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
import java.util.concurrent.BlockingQueue
import java.util.concurrent.CompletionStage
import java.util.concurrent.ConcurrentHashMap
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
// (which relay and which key are the deployment's policy, never defaulted here), and it never
// makes an authorization decision. What arrives from the relay is DATA: it is parsed by
// NostrWire's TOTAL codec, never trusted, and never reaches the fold as a nostr type (A4-3).
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
 * Bundles the relay with the lead key that authenticates to it as one required unit, so reaching a
 * second relay is another config, not another pair of constructor arguments threaded through the
 * transport. SINGLE-CONNECTION-USE, not reusable data: constructing a [RelayConnection] hands it
 * custody of the key, and [RelayConnection.close] zeroes it (#42) — the key does not outlive the
 * connection it authenticated. A reconnect builds a fresh RelayConfig from fresh key material;
 * handing a closed connection's config to a new [RelayConnection] decodes a zeroed key and fails
 * closed at authenticate(). Both fields are REQUIRED and carry NO default: the relay URL and the
 * keypair are the deployment's configuration, and a default here is exactly how this mechanism
 * would quietly acquire a relay or a key it was never configured with. The key is taken CONCRETELY
 * as secret-key hex, not behind an injectable signer interface: A4-7 forbids a daemon-side
 * remote-signer seam, so there is deliberately no place to slot a NIP-46 remote signer into this
 * transport.
 *
 * Plaintext `ws://` is permitted alongside `wss://`, and that is a confidentiality/deployment
 * choice left to the caller, NOT a hole in this gate. Plaintext lets a network observer SEE the
 * events carried, but it cannot weaken authorization INTEGRITY: the lead's release decision is a
 * fold over each approval's own detached BIP-340 signature, re-verified after transport, so an
 * approval forged or tampered on the wire is rejected regardless of scheme; and NIP-42 only gates
 * what the relay agrees to serve back to us. `ws://` is what a loopback relay and the test doubles
 * speak, so refusing it here would buy no integrity and break legitimate local deployments. The
 * confidentiality call (must this link be encrypted in transit?) belongs with the relay URL in the
 * deployment's configuration, which is where the scheme is chosen.
 */
class RelayConfig(
  val relayUrl: String,
  val leadSecretKey: SecretKeyHex,
) {
  init {
    require(relayUrl.startsWith("ws://") || relayUrl.startsWith("wss://")) {
      "relayUrl must be a ws:// or wss:// URL, was '$relayUrl'"
    }
    // The key's structural validation (64 hex characters) lives in SecretKeyHex.ofHex, so a
    // RelayConfig cannot even be built around a malformed key. That the key derives a valid pubkey
    // is still proven by the native at authenticate() time; construction stays native-free.
  }

  // NOT a data class. The secret now lives in a SecretKeyHex backed by a mutable CharArray, and a
  // data class would (1) compare that array by identity in its generated equals/hashCode — a silent
  // behaviour change — and (2) hand copy() a second reference to the SAME array, so one holder's
  // clear() would zero another config's key. RelayConfig equality is unused, so a plain class is
  // correct (the call NostrFilter made). toString still redacts: SecretKeyHex redacts itself, so
  // the key cannot reach a log line or an exception string through the config.
  override fun toString(): String = "RelayConfig(relayUrl='$relayUrl', leadSecretKey=$leadSecretKey)"
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

/** The outcome of [RelayConnection.publish]. Only [Accepted] means the relay took the event;
 * everything else is fail-closed and MUST NOT be read as "it landed". Never thrown. */
sealed interface PublishResult {
  /** The relay accepted the event (`OK ... true`). */
  object Accepted : PublishResult

  /** The relay explicitly rejected the event (`OK ... false`). [message] is the relay's reason. */
  data class Rejected(val message: String) : PublishResult

  /** No verdict: the event could not be sent, no matching OK arrived within the deadline, or the
   * socket dropped. Fail-closed — never assume the event was stored. */
  data class Failed(val detail: String) : PublishResult
}

/** The outcome of [RelayConnection.subscribe] or [RelayConnection.closeSubscription]. NIP-01 gives
 * a REQ/CLOSE no relay ACK (unlike a publish's OK), so the only outcomes are that the control frame
 * was SENT or that it could not be. [Sent] means exactly that the frame went onto the wire — NOT
 * that the relay accepted the subscription: a relay may still refuse it with a `CLOSED`, which
 * arrives through [RelayConnection.receive] like any other message. Never thrown for a send fault. */
sealed interface SubscribeResult {
  /** The REQ (or CLOSE) frame was sent. */
  object Sent : SubscribeResult

  /** The frame could not be sent: not connected, the socket dropped, or the send timed out.
   * Fail-closed — the subscription is not established. */
  data class Failed(val detail: String) : SubscribeResult
}

/**
 * One connection to one relay. Construct it, [connect], [authenticate], [publish] or [subscribe],
 * [receive] messages, [closeSubscription] when done with a subscription, and [close] when done with
 * the connection. Single inbound consumer: one caller drains [receive] (the auth handshake, and the
 * EVENT/EOSE/CLOSED that a [subscribe] produces).
 *
 * Built on the JDK's [WebSocket]: no new dependency, matching the [HttpClient] the harness already
 * uses. The receive path is a callback [Listener], which the JDK invokes on a thread of its choosing
 * (one of the client's executor threads, or a thread of `CompletableFuture`'s default executor: a
 * worker of the common ForkJoinPool, or a new thread per task when that pool's parallelism is below
 * 2); it hands typed [RelayMessage]s to the caller through a bounded queue. It is deliberately NOT
 * bridged into a coroutine Channel/Flow: the WebSocket's demand model (one `request(1)` per
 * delivery = exactly one outstanding listener invocation) already IS the backpressure, and it is
 * what lets the fragment accumulator below be a plain [StringBuilder] with no lock — the listener
 * is invoked serially. A Channel would add a second backpressure system that can disagree with the
 * first, and its full state either blocks inside the callback (wedging that serialized thread) or
 * drops. (AcpClient uses Flow only because its acp-jvm SDK's Transport takes a CoroutineScope;
 * nothing in java.net.http.WebSocket does.)
 */
class RelayConnection(
  private val config: RelayConfig,
  // Injectable for tests; production uses the JDK default. The DEPTH guard's headroom (that
  // MAX_JSON_DEPTH parses below the parser's overflow depth; [MAX_JSON_DEPTH] says what checks
  // that, and what does not) is scoped to the default thread-stack size, which every thread the
  // JDK invokes the listener on gets by default: the client's executor threads, and the threads of
  // CompletableFuture's default executor (the common ForkJoinPool's workers, or a new thread per
  // task when that pool's parallelism is below 2). A caller passing its own HttpClient backed by an
  // executor with smaller-stack threads lowers that overflow depth for each frame the JDK delivers
  // on one of them, and owns that margin.
  private val httpClient: HttpClient = HttpClient.newHttpClient(),
) {
  // Complete, parsed messages awaiting the caller. Bounded (see COUNT bound above); offered to,
  // never put to — a blocking put on the listener thread would wedge the serialized callback.
  private val inbound = LinkedBlockingQueue<RelayMessage>(MAX_QUEUED_MESSAGES)

  // OK-ack routing. An OK relay-message acknowledges one event we sent (the auth event, or a
  // published event), matched by event id — it is NOT subscription data and must not reach the
  // single inbound consumer. Each in-flight publish/authenticate registers a one-slot queue keyed by
  // its event id BEFORE sending (so an OK racing back ahead of the await still lands) and removes it
  // in a finally, so this map holds only genuinely in-flight acks — it does not grow with traffic.
  // CROSS-THREAD BY CONSTRUCTION, unlike the listener's lock-free `assembling` StringBuilder: the
  // listener thread offers an OK into a slot while caller threads register/await/remove theirs, so it
  // is a ConcurrentHashMap of thread-safe queues. Keyed by event id, unique per NIP-01 (sha256 of
  // the event), so two live awaits never share a key.
  private val okWaiters = ConcurrentHashMap<String, BlockingQueue<RelayMessage.Ok>>()

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
   * `["OK", <our-event-id>, <accepted>, ...]`. [timeout] is the whole handshake's budget: the
   * challenge-await, the send, and the OK-await all draw from it.
   *
   * Fail-closed: a missing challenge, a missing OK, an OK for a DIFFERENT event id (a relay cannot
   * authenticate us by acknowledging someone else's event), a signing fault, or a dropped socket all
   * return a non-[Authenticated] result. And if signing overruns the budget — a cold native load on
   * the first call, or a slow entropy draw on a low-entropy host — that is reported distinctly from
   * the relay staying silent, never a false "no OK" that blames the relay for a slow local sign.
   * Never throws.
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
        // Yield the key bytes only for the signing call — useKeyBytes zeroes the working ByteArray
        // as soon as buildAuthEvent returns (or throws). The held key (config.leadSecretKey) stays
        // intact so a relay re-challenge can re-sign; it is wiped in close(). (#42)
        config.leadSecretKey.useKeyBytes { keyBytes ->
          buildAuthEvent(
            secretKey = keyBytes,
            relayUrl = config.relayUrl,
            challenge = challenge,
            createdAt = Instant.now().epochSecond,
            auxRandHex = freshAuxRandHex(),
          )
        }
      } catch (e: Exception) {
        // No e.message: signing is the one exception path that handles the secret key, and its
        // message could echo key-derived material into a result string, so only the exception class
        // is reported. That class does not say whose fault it was: an IllegalArgumentException can
        // come from the relay, whose challenge, if it holds an unpaired surrogate, leaves the auth
        // event with no id to sign (buildAuthEvent).
        return AuthResult.Failed("could not sign auth event: ${e.javaClass.simpleName}")
      }

    // Awaiting the challenge and signing above both draw from [deadline]. Signing is bounded work but
    // not free — the first sign in a fresh JVM loads the secp256k1 native (seconds under contention),
    // and every sign draws fresh aux randomness, which can block on a low-entropy host. If preparing
    // the event spent the whole budget, report THAT: a blown deadline makes pollUntilDeadline below
    // return null before it ever polls the slot, which reads as "the relay never answered", when the
    // truth is the client never finished preparing the frame. `remaining` also bounds the send, so a
    // slow sign cannot then spend a second full [timeout] on sendText.
    val remaining =
      preparationBudget(Instant.now(), deadline)
        ?: return AuthResult.Failed(failedDetail("deadline elapsed while preparing the auth event"))

    // Register the ack sink BEFORE sending, so an OK that races back ahead of the await still lands
    // in our slot rather than being dropped. Removed in the finally whether we get it or time out.
    val slot = registerOkWaiter(authEvent.id)
    try {
      sendFrameOrBreach(ws, authMessage(authEvent), remaining)?.let {
        return AuthResult.Failed("could not send auth event: $it")
      }
      val ok =
        pollUntilDeadline(slot, deadline)
          ?: return AuthResult.Failed(failedDetail("no OK for our auth event within deadline"))
      return if (ok.accepted) AuthResult.Authenticated else AuthResult.Refused(ok.message)
    } finally {
      unregisterOkWaiter(authEvent.id, slot)
    }
  }

  /**
   * Publish [event] to the relay and await its verdict. Frames the event as `["EVENT", <event>]`,
   * sends it, and awaits the relay's `["OK", <event-id>, <accepted>, <message>]` for THIS event's
   * id. [timeout] bounds the send and the wait.
   *
   * Fail-closed: a send fault, no OK within the deadline, an OK for a DIFFERENT event id (a relay
   * cannot ack our event by acknowledging another), or a dropped socket all yield
   * [PublishResult.Failed], never a hopeful assumption the event landed. Never throws.
   *
   * MECHANISM, not policy: the caller builds and signs [event] — WHAT to publish is the
   * deployment's choice; this only carries it and reports the relay's answer, making no
   * authorization decision. It does not require [authenticate] first: whether a relay demands
   * NIP-42 before it accepts an event is the relay's policy, surfaced here as a
   * [PublishResult.Rejected] if so.
   */
  fun publish(event: NostrEvent, timeout: Duration): PublishResult {
    val ws = webSocket ?: return PublishResult.Failed("not connected")
    failure.get()?.let { return PublishResult.Failed("connection failed: $it") }
    val deadline = Instant.now().plus(timeout)
    val slot = registerOkWaiter(event.id)
    try {
      sendFrameOrBreach(ws, eventMessage(event), timeout)?.let {
        return PublishResult.Failed("could not send event: $it")
      }
      val ok =
        pollUntilDeadline(slot, deadline)
          ?: return PublishResult.Failed(failedDetail("no OK for published event within deadline"))
      return if (ok.accepted) PublishResult.Accepted else PublishResult.Rejected(ok.message)
    } finally {
      unregisterOkWaiter(event.id, slot)
    }
  }

  /**
   * Open a subscription: send `["REQ", <subscriptionId>, <filter>, ...]`. The matching events arrive
   * through [receive] as [RelayMessage.Event]s carrying this [subscriptionId], followed by an
   * [RelayMessage.Eose] once the relay's stored events are exhausted; end it with [closeSubscription].
   *
   * SEND-ONLY: NIP-01 gives a REQ no acknowledgement, so this returns as soon as the frame is sent
   * ([SubscribeResult.Sent]) and does NOT wait for events or EOSE. Waiting for EOSE would invent a
   * handshake NIP-01 lacks and hand a hostile relay a way to stall the caller by simply never sending
   * one; the caller drains [receive] on its own schedule. [timeout] bounds only the send.
   *
   * A relay may REFUSE the subscription with `["CLOSED", <subscriptionId>, ...]` — DATA the caller
   * sees through [receive] (a [RelayMessage.Closed]), not a transport fault; the substrate decides
   * what to do about a refusal (A4-3: the relay is a door, not an authority). Likewise the transport
   * delivers whatever the relay DOES send — withheld, reordered, delayed, or replayed — FAITHFULLY,
   * adding no dedup or ordering of its own: a replay is rejected by the single-use nonce in the
   * mechanical layer, not papered over here.
   *
   * MECHANISM, not policy: WHICH events to ask for — the [filters]' kinds and tag references — is
   * the deployment's choice; this only carries the request. Fail-closed: not connected, a send
   * fault, or a dropped socket all yield [SubscribeResult.Failed]. Never throws for a remote fault; a
   * malformed [subscriptionId] or an empty [filters] is a caller error and throws.
   */
  fun subscribe(
    subscriptionId: String,
    filters: List<NostrFilter>,
    timeout: Duration,
  ): SubscribeResult {
    requireValidSubscriptionId(subscriptionId)
    require(filters.isNotEmpty()) { "a REQ must carry at least one filter (NIP-01)" }
    return sendControlFrame(reqMessage(subscriptionId, filters), timeout, "REQ")
  }

  /**
   * End a subscription: send `["CLOSE", <subscriptionId>]`, asking the relay to stop sending that
   * subscription's events. It is a request, not a guarantee — a faithful relay stops, but a hostile
   * one may keep sending, and those events still surface through [receive] for the caller to ignore
   * (the relay is a door, not an authority). Send-only and fail-closed exactly like [subscribe]: a
   * send fault yields [SubscribeResult.Failed] and it never throws for a remote fault. [timeout]
   * bounds the send. A malformed [subscriptionId] throws, exactly as [subscribe] does — it is caller
   * input, checked as a precondition; that is unlike [close], which tears down an already-established
   * socket best-effort and has no caller input to validate.
   */
  fun closeSubscription(subscriptionId: String, timeout: Duration): SubscribeResult {
    requireValidSubscriptionId(subscriptionId)
    return sendControlFrame(closeMessage(subscriptionId), timeout, "CLOSE")
  }

  /**
   * Take the next relay message, or null if none arrives before [timeout] or the connection has
   * failed. Single-consumer. Never throws. Never returns a [RelayMessage.Ok]: an OK acks an event we
   * sent and is routed to that sender by event id in deliver(), not queued here — a subscription
   * draining this sees only EVENT/EOSE/CLOSED/NOTICE/AUTH. [subscribe] opens a subscription whose
   * EVENT/EOSE/CLOSED surface here; this feed is NOT filtered by subscription id — every message the
   * relay sends arrives, and the caller matches each to its subscription by the id the message carries
   * (a hostile relay may send an id you never opened). The auth handshake drains this feed too.
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

  /** Whether the connection has recorded a terminal fault (error, relay close, a bounds breach, or a
   * stalled send). Once true it stays true. */
  fun hasFailed(): Boolean = failure.get() != null

  /** The first terminal fault's classified reason, or null if the connection has not failed. The
   * substrate's words for what went wrong (a transport error, a relay close, which bound, or a send
   * that stalled past its deadline). */
  fun failureReason(): String? = failure.get()

  /** Close the socket. Idempotent and bounded: a graceful close that does not complete in time is
   * dropped with an abort. Never throws. */
  fun close() {
    if (!closed.compareAndSet(false, true)) return
    // Wipe the lead key first: the connection is finished with it, and the clearable holder exists
    // precisely so the plaintext does not outlive the connection. Above the webSocket null-check so a
    // connection that never dialled still clears its key. (#42)
    config.leadSecretKey.clear()
    val ws = webSocket ?: return
    try {
      ws.sendClose(WebSocket.NORMAL_CLOSURE, "").get(CLOSE_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
    } catch (e: Exception) {
      ws.abort()
    }
  }

  // Await the first inbound message [match] accepts, discarding others: the caller waits for one
  // specific message in a stream that may carry others (e.g. a NOTICE before the AUTH challenge).
  private fun <T : Any> awaitMessage(deadline: Instant, match: (RelayMessage) -> T?): T? {
    while (true) {
      val msg = pollUntilDeadline(inbound, deadline) ?: return null
      match(msg)?.let { return it }
    }
  }

  // Poll [queue] in slices until it yields a message, the deadline passes, or the connection fails.
  // Slices so a fault recorded mid-wait (by the listener thread) is seen within POLL_SLICE_MILLIS
  // rather than only at the deadline. Shared by the challenge await (the inbound queue) and the OK
  // await (a per-event ack slot). A fault checked before the poll ends the wait even if an ack is
  // already buffered in the slot: fail-closed is the only safe posture for authenticate() (which
  // shares this and needs a live socket), and for publish a false Failed costs only an idempotent
  // republish, never a false Accepted. Returns null on deadline, failure, or interrupt.
  private fun <M : RelayMessage> pollUntilDeadline(queue: BlockingQueue<M>, deadline: Instant): M? {
    while (true) {
      if (failure.get() != null) return null
      val remaining = Duration.between(Instant.now(), deadline)
      if (remaining.isNegative || remaining.isZero) return null
      val sliceMillis = minOf(remaining.toMillis(), POLL_SLICE_MILLIS)
      val msg =
        try {
          queue.poll(sliceMillis, TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
          Thread.currentThread().interrupt()
          return null
        }
      if (msg != null) return msg
    }
  }

  // Register a one-slot ack sink for [eventId] BEFORE the event is sent. A relay's OK is CAUSED by
  // the event we send, so it cannot precede the send; registering first therefore guarantees the slot
  // exists before any solicited OK can arrive — even one that comes back before the await starts
  // polling, which the slot then buffers. Registering AFTER the send would open a window where a fast
  // OK finds no slot, is dropped, and spuriously times the call out. The test
  // `publish Accepted through a synchronous relay double pins register-before-send` pins this order:
  // a WebSocket double whose sendText delivers the OK to the listener synchronously — the earliest an
  // OK can arrive — returns Accepted only while registration precedes the send. The same ordering
  // guards the landed NIP-42 authenticate() path, which awaits its OK the same way. (An UNSOLICITED
  // OK, for an id with no registered waiter, is dropped in deliver() and never reaches a slot — a
  // different case, covered there.) Capacity 1 admits exactly one OK to the awaiter: a second arriving
  // before the first is taken is rejected by the full slot; one arriving after is dropped when the
  // finally unregisters the slot, or — in the narrow window before that — is offered into the emptied
  // slot that no one polls again.
  private fun registerOkWaiter(eventId: String): BlockingQueue<RelayMessage.Ok> {
    val slot = LinkedBlockingQueue<RelayMessage.Ok>(1)
    okWaiters[eventId] = slot
    return slot
  }

  // Remove our own slot — conditionally, so a slot a later awaiter registered under the same id is
  // never yanked (id reuse does not occur for unique NIP-01 ids; the conditional keeps the map
  // correct regardless).
  private fun unregisterOkWaiter(eventId: String, slot: BlockingQueue<RelayMessage.Ok>) {
    okWaiters.remove(eventId, slot)
  }

  // Send one subscription-control frame (REQ or CLOSE) and report only whether it went onto the
  // wire. Unlike publish()/authenticate() there is no relay ACK to await — NIP-01 answers neither a
  // REQ nor a CLOSE — so this bounds the send with the same get(timeout) and classifies a send fault
  // the same way, and that is the whole outcome. [what] names the frame for the failure detail.
  private fun sendControlFrame(frame: String, timeout: Duration, what: String): SubscribeResult {
    val ws = webSocket ?: return SubscribeResult.Failed("not connected")
    failure.get()?.let { return SubscribeResult.Failed("connection failed: $it") }
    sendFrameOrBreach(ws, frame, timeout)?.let {
      return SubscribeResult.Failed("could not send $what: $it")
    }
    return SubscribeResult.Sent
  }

  private fun failedDetail(default: String): String =
    failure.get()?.let { "connection failed: $it" } ?: default

  private fun freshAuxRandHex(): String {
    val bytes = ByteArray(32)
    secureRandom.nextBytes(bytes)
    return bytes.joinToString("") { "%02x".format(it) }
  }

  // Send [frame] and wait up to [budget] for the JDK to hand it to the socket. Returns null once the
  // frame is on the wire, or a classified reason if the send faulted — the caller maps that reason
  // into its own Failed type. A TIMEOUT or an INTERRUPT leaves the send OUTSTANDING: the JDK
  // WebSocket permits one outstanding send, so the NEXT sendText on this socket would throw
  // IllegalStateException — a poisoned connection a caller cannot tell from a live one. So on those
  // two we breach: abort the socket (tearing down the stuck send) and record the failure, which makes
  // every later send short-circuit at its failure.get() entry guard instead of hitting the poisoned
  // socket. Any OTHER fault classifies WITHOUT a breach, as before: an ExecutionException means the
  // future COMPLETED (the send itself failed, nothing outstanding), and a synchronous throw is not a
  // pending send either — so the broad catch keeps this method's "never throws for a send fault"
  // contract while breaching only the two cases that actually leave a send in flight.
  private fun sendFrameOrBreach(ws: WebSocket, frame: String, budget: Duration): String? =
    try {
      ws.sendText(frame, true).get(budget.toMillis(), TimeUnit.MILLISECONDS)
      null
    } catch (e: TimeoutException) {
      val reason = "send did not complete within ${budget.toMillis()}ms"
      breach(ws, reason)
      reason
    } catch (e: InterruptedException) {
      Thread.currentThread().interrupt()
      val reason = "send interrupted"
      breach(ws, reason)
      reason
    } catch (e: Exception) {
      "${e.javaClass.simpleName}: ${e.message}"
    }

  private fun breach(ws: WebSocket, reason: String) {
    // Record the cause (first one wins) and drop the socket immediately. abort(), not sendClose():
    // the reasons breach() fires — an ingress-bounds breach (protocol abuse from a hostile relay) or
    // a send stuck outstanding past its deadline — both leave the socket unusable, not in a state to
    // handshake a courteous close through.
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
      // DEPTH bound, applied BEFORE the parser: deep enough nesting makes kotlinx's parser recurse
      // until it StackOverflows (the check's KDoc says which nesting), so a frame that may nest deeper
      // than MAX_JSON_DEPTH breaches before the parse. [jsonMayNestDeeperThan] counts only STRUCTURAL
      // brackets, which is what lets it bound DEPTH rather than a total-opener COUNT: a
      // wide-but-shallow message (a kind-3 with thousands of sibling `p` tags) nests only a few deep
      // and is DELIVERED, where a total-opener count would have aborted the connection on the sibling
      // count alone (agents-oss #41). It also refuses a value after a closer, which kotlinx reads as
      // deeper nesting than the brackets show, so a frame malformed that way breaches here instead of
      // being dropped as junk, or misread as another message, below. Its KDoc carries why it may
      // over-count but never under-count.
      if (jsonMayNestDeeperThan(text, MAX_JSON_DEPTH)) {
        breach(webSocket, "inbound message failed the JSON depth check (max $MAX_JSON_DEPTH levels)")
        return
      }
      // TOTAL parse: null on any malformed input. Junk from a relay is noise the fold never trusts,
      // so drop it and keep the connection — only a bounds breach (an attack) closes the socket.
      // The depth guard above is PREVENTION, and it is deliberately the ONLY protection against a
      // parser overflow here: kotlinx's recursive parser throws a StackOverflowError on deep enough
      // nesting (an Error the codec lets propagate). No catch wraps this parse, for two reasons.
      // First, the guard keeps the overflow out of reach: it admits no frame the parser would nest
      // deeper than MAX_JSON_DEPTH, a depth that sits below where the parser overflows on this
      // listener's thread ([MAX_JSON_DEPTH] says what checks that margin, and what does not).
      // Second, a catch would be the wrong tool even if it were reachable: were a too-deep frame
      // ever to reach the parser, the JDK WebSocket catches the Error thrown from this callback and
      // delivers it to onError (confirmed empirically), so the connection fails CLOSED — it does
      // not wedge. A catch(Throwable) here would instead INTERCEPT that Error and try to run
      // breach()/abort() on a stack the overflow has just exhausted, trading a clean fail-closed
      // for an attempted recovery that cannot reliably complete. So there is no catch; correctness
      // rests on the guard — its agreement with the parser checked in JsonNestingTest, its margin
      // as [MAX_JSON_DEPTH] describes.
      val message = parseRelayMessage(text) ?: return
      // An OK relay-message is a publish/auth ACK, routed to the waiter that sent the matching event
      // id — NOT subscription data. Divert it here so the single inbound consumer (receive()) sees
      // only EVENT/EOSE/CLOSED/NOTICE/AUTH; an OK for an id no one is awaiting (unsolicited, late, or
      // a duplicate) finds no slot and is dropped, never queued. See [okWaiters].
      if (message is RelayMessage.Ok) {
        okWaiters[message.eventId]?.offer(message)
        return
      }
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
     * scan ([jsonMayNestDeeperThan], run in deliver()) measures how deep the structural `[` / `{` nest
     * — ignoring brackets inside string literals — and breaches ABOVE this ceiling, so a
     * wide-but-shallow message is delivered while a genuinely over-deep one is rejected before the
     * kotlinx parser (agents-oss #41). Far above
     * any auth/gate message (a handful of levels) and below the depth at which that parser
     * StackOverflows on this listener's thread. That overflow depth is not a constant: it shifts
     * with the frame's shape, with the thread's stack size, and with whether the parse runs
     * interpreted or compiled, and by which compiler. So the margin is not trusted to a single
     * measured number; instead RelayCeilingTest parses frames nested exactly this deep on the
     * listener thread every CI run. It parses three shapes: arrays only; objects only, which keeps
     * only about 200 of its levels on the stack; and objects with an array inside the 200th, which
     * keeps all but one of its levels there ([jsonMayNestDeeperThan] says which nesting). It parses
     * them in three pinned JIT states: interpreted, the parser's state until the JIT compiles it;
     * C1-compiled with profiling (tier 3); and tier 3 with kotlinx's readArray left interpreted, a
     * split that a tiered run can also be in. Of the states measured, all on aarch64, the last two
     * need the most stack per level, the split more than tier 3 per array level. So a parser or JDK
     * change that lowered the overflow depth under this ceiling in one of these states, on the
     * default thread stack of the platform CI runs on, fails the build. On aarch64 the other states
     * measured need no more stack per level than these, and none was measured on the x86_64 CI runs
     * on; they, a smaller default stack elsewhere, and a caller's executor with smaller stacks are
     * not checked. */
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

// The budget left for the send + OK-await after the challenge has been awaited and the event signed,
// or null if less than a millisecond remains before [deadline]. Pure in ([now], [deadline]) so the
// "signing overran the budget → distinct fail-closed result, not a false 'no OK'" contract is
// unit-testable directly: the daemon signs in-process with no injectable signer to slow, so an
// integration test cannot reproduce a slow sign on demand. Sub-millisecond counts as elapsed: the
// caller bounds the send with remaining.toMillis(), and a zero-millisecond get() on an as-yet-
// incomplete future throws immediately rather than waiting — a third failure classification in the
// exact boundary this exists to disambiguate. pollUntilDeadline absorbs the same sub-ms remainder
// gracefully (a zero-length poll returns empty, not a throw); returning null here makes the send path
// agree — too little time left to send is "deadline elapsed while preparing", never a stray
// TimeoutException that reads like the relay never answered.
internal fun preparationBudget(now: Instant, deadline: Instant): Duration? {
  val remaining = Duration.between(now, deadline)
  return if (remaining.toMillis() <= 0L) null else remaining
}

// A caller-supplied subscription id must be non-empty and within NIP-01's 64-char cap. A bad id is
// a caller bug, not a remote fault, so it throws (like RelayConfig's structural checks) rather than
// returning a fail-closed result.
internal fun requireValidSubscriptionId(subscriptionId: String) {
  require(subscriptionId.isNotEmpty()) { "subscription id must not be empty" }
  require(subscriptionId.length <= 64) {
    "subscription id must be at most 64 characters (NIP-01), was ${subscriptionId.length}"
  }
}
