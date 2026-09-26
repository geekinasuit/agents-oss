package com.geekinasuit.agency.nostr

import java.net.URI
import java.net.http.HttpClient
import java.net.http.WebSocket
import java.time.Duration
import java.util.concurrent.CompletableFuture

/**
 * An [HttpClient] for [RelayConnection]'s injectable httpClient seam whose WebSocket is a test
 * double: its builder hands the connection's listener to [makeSocket] and returns the socket in an
 * already-completed future, so connect() resolves with no live handshake. A double decides when each
 * relay frame reaches the listener, relative to the client's own calls, so a cell can fix an order
 * that a [FakeRelay] on a real socket leaves to the scheduler. connect() calls only
 * newWebSocketBuilder() on the client, so every other client member is unreachable on the paths the
 * cells drive. Parameterizing on [makeSocket] lets this one scaffold serve every double.
 */
fun webSocketClient(makeSocket: (WebSocket.Listener) -> WebSocket): HttpClient =
  DoubleHttpClient(makeSocket)

/** What a double does in a member it does not model: it throws. */
fun notUsed(): Nothing =
  throw UnsupportedOperationException("this test double does not model this member")

private class DoubleHttpClient(private val makeSocket: (WebSocket.Listener) -> WebSocket) :
  HttpClient() {
  override fun newWebSocketBuilder(): WebSocket.Builder = DoubleWebSocketBuilder(makeSocket)

  // connect() only ever calls newWebSocketBuilder(); the rest of HttpClient is never reached.
  override fun cookieHandler(): java.util.Optional<java.net.CookieHandler> = notUsed()
  override fun connectTimeout(): java.util.Optional<Duration> = notUsed()
  override fun followRedirects(): HttpClient.Redirect = notUsed()
  override fun proxy(): java.util.Optional<java.net.ProxySelector> = notUsed()
  override fun sslContext(): javax.net.ssl.SSLContext = notUsed()
  override fun sslParameters(): javax.net.ssl.SSLParameters = notUsed()
  override fun authenticator(): java.util.Optional<java.net.Authenticator> = notUsed()
  override fun version(): HttpClient.Version = notUsed()
  override fun executor(): java.util.Optional<java.util.concurrent.Executor> = notUsed()

  override fun <T> send(
    request: java.net.http.HttpRequest,
    responseBodyHandler: java.net.http.HttpResponse.BodyHandler<T>,
  ): java.net.http.HttpResponse<T> = notUsed()

  override fun <T> sendAsync(
    request: java.net.http.HttpRequest,
    responseBodyHandler: java.net.http.HttpResponse.BodyHandler<T>,
  ): CompletableFuture<java.net.http.HttpResponse<T>> = notUsed()

  override fun <T> sendAsync(
    request: java.net.http.HttpRequest,
    responseBodyHandler: java.net.http.HttpResponse.BodyHandler<T>,
    pushPromiseHandler: java.net.http.HttpResponse.PushPromiseHandler<T>,
  ): CompletableFuture<java.net.http.HttpResponse<T>> = notUsed()
}

private class DoubleWebSocketBuilder(private val makeSocket: (WebSocket.Listener) -> WebSocket) :
  WebSocket.Builder {
  override fun header(name: String, value: String): WebSocket.Builder = this
  override fun connectTimeout(timeout: Duration): WebSocket.Builder = this

  override fun subprotocols(
    mostPreferred: String,
    vararg lesserPreferred: String,
  ): WebSocket.Builder = this

  override fun buildAsync(uri: URI, listener: WebSocket.Listener): CompletableFuture<WebSocket> =
    CompletableFuture.completedFuture<WebSocket>(makeSocket(listener))
}

/**
 * What the WebSocket doubles share, so each overrides only sendText and the members its cells use.
 * sendText is not here, so the compiler makes each double say what a send does: RelayConnection
 * catches a send that throws and reports it as an ordinary failure, which a cell that asserts only
 * the failure cannot tell from the path it means to drive. sendBinary, sendPing and sendPong are
 * never reached. close() calls sendClose, and aborts only when the close frame is not sent: here it
 * is sent at once, so close() never aborts. request() is called by the listener on each delivery.
 */
abstract class DoubleWebSocket : WebSocket {
  override fun sendClose(statusCode: Int, reason: String): CompletableFuture<WebSocket> =
    CompletableFuture.completedFuture<WebSocket>(this)
  override fun abort() {}
  override fun request(n: Long) {}
  override fun sendBinary(data: java.nio.ByteBuffer, last: Boolean): CompletableFuture<WebSocket> =
    notUsed()
  override fun sendPing(message: java.nio.ByteBuffer): CompletableFuture<WebSocket> = notUsed()
  override fun sendPong(message: java.nio.ByteBuffer): CompletableFuture<WebSocket> = notUsed()
  override fun getSubprotocol(): String = ""
  override fun isOutputClosed(): Boolean = false
  override fun isInputClosed(): Boolean = false
}

/**
 * A double whose send hands the listener an accepting OK and then reports the relay's close, both
 * before the send completes. The OK carries the event id that [okIdOf] reads from the sent frame. It
 * is routed to the caller's ack slot while the connection is still up, so it is waiting there once
 * the connection has failed.
 */
class OkThenCloseOnSendWebSocket(
  private val listener: WebSocket.Listener,
  private val okIdOf: (String) -> String,
) : DoubleWebSocket() {
  override fun sendText(data: CharSequence, last: Boolean): CompletableFuture<WebSocket> {
    listener.onText(this, "[\"OK\",\"${okIdOf(data.toString())}\",true,\"\"]", true)
    listener.onClose(this, WebSocket.NORMAL_CLOSURE, "bye")
    return CompletableFuture.completedFuture<WebSocket>(this)
  }
}
