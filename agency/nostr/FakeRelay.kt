package com.geekinasuit.agency.nostr

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * A raw-socket RFC-6455 WebSocket SERVER, for exercising [RelayConnection] against a controllable
 * relay. The JDK ships a WebSocket client but no server, so the test double is hand-rolled: the
 * handshake (Sec-WebSocket-Accept), unmasked server-to-client framing, and masked client-to-server
 * frame decoding are all here. ~150 lines, hermetic, no dependency.
 *
 * It is a TEST DOUBLE, not a relay: it agrees with whatever bytes a test tells it to send, so it
 * can NEVER stand in for the "authenticates against a REAL relay" check (cross-impl truth — a fake
 * relay validates only against the test author's reading of NIP-42). It exists to drive framing,
 * fragmentation, ingress-bound, and (in 3b-2) hostile-relay behaviour, where full control over the
 * exact bytes and their timing is the whole point.
 *
 * Usage: construct it (binds an ephemeral port; read [url]), register a [serve] script that runs on
 * its own thread once the client connects, then point a [RelayConnection] at [url]. The script and
 * the connection's authenticate() run concurrently, which is required — the NIP-42 exchange needs
 * the relay side to send a challenge, read the client's response, and answer while authenticate()
 * blocks waiting.
 */
class FakeRelay : AutoCloseable {
  private val server = ServerSocket(0)
  val port: Int = server.localPort
  val url: String = "ws://127.0.0.1:$port"

  @Volatile private var accepted: Socket? = null
  @Volatile private var script: Thread? = null
  private val scriptError = AtomicReference<Throwable?>(null)

  /** Run [block] on a dedicated thread once the client has connected and the handshake is done.
   * [block] gets a [Session] to send frames and read the client's frames. An exception it throws is
   * captured and re-raised by [assertScriptClean]. */
  fun serve(block: (Session) -> Unit) {
    script =
      thread(isDaemon = true, name = "fake-relay-$port") {
        try {
          val sock = server.accept()
          accepted = sock
          handshake(sock)
          block(Session(sock))
        } catch (t: Throwable) {
          scriptError.compareAndSet(null, t)
        }
      }
  }

  /** Wait up to [timeoutMillis] for the last [serve] script to end, and return whether it ended.
   * Once it has, [assertScriptClean] sees anything it threw, since the script's thread records a
   * throw before it ends. [timeoutMillis] must be positive: as with [Thread.join], zero waits
   * with no limit and a negative value throws. */
  fun awaitScript(timeoutMillis: Long): Boolean {
    val running = checkNotNull(script) { "no script was served" }
    running.join(timeoutMillis)
    return !running.isAlive
  }

  /** Re-raise anything the [serve] script threw, so a relay-side failure fails the test rather than
   * hiding on a daemon thread. Call after the client-side assertions. It sees only what the script
   * has thrown so far: when the client does not see the script's last step, [awaitScript] first. */
  fun assertScriptClean() {
    scriptError.get()?.let { throw AssertionError("fake relay script failed", it) }
  }

  override fun close() {
    try {
      accepted?.close()
    } catch (_: Exception) {}
    try {
      server.close()
    } catch (_: Exception) {}
  }

  private fun handshake(sock: Socket) {
    val reader = sock.getInputStream().bufferedReader(Charsets.US_ASCII)
    var key = ""
    while (true) {
      val line = reader.readLine() ?: break
      if (line.isEmpty()) break
      if (line.startsWith("Sec-WebSocket-Key:", ignoreCase = true)) {
        key = line.substringAfter(":").trim()
      }
    }
    val magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    val accept =
      Base64.getEncoder()
        .encodeToString(
          MessageDigest.getInstance("SHA-1").digest((key + magic).toByteArray(Charsets.US_ASCII))
        )
    val response =
      "HTTP/1.1 101 Switching Protocols\r\n" +
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
        "Sec-WebSocket-Accept: $accept\r\n\r\n"
    sock.getOutputStream().write(response.toByteArray(Charsets.US_ASCII))
    sock.getOutputStream().flush()
  }

  /** Frame primitives over one accepted socket. Server-to-client frames are unmasked (RFC 6455);
   * client-to-server frames are masked, and [nextClientText] unmasks them. */
  inner class Session(private val sock: Socket) {
    private val output = sock.getOutputStream()
    private val input = sock.getInputStream()

    /** A single complete text message. */
    fun sendText(text: String) = sendFrame(OPCODE_TEXT, text.toByteArray(Charsets.UTF_8), fin = true)

    /** One logical text message split into fragments (first TEXT, rest CONTINUATION, last fin). */
    fun sendTextFragments(parts: List<String>) {
      parts.forEachIndexed { i, part ->
        sendFrame(
          opcode = if (i == 0) OPCODE_TEXT else OPCODE_CONTINUATION,
          payload = part.toByteArray(Charsets.UTF_8),
          fin = i == parts.lastIndex,
        )
      }
    }

    fun sendPing(payload: ByteArray = ByteArray(0)) = sendFrame(OPCODE_PING, payload, fin = true)

    fun sendBinary(payload: ByteArray) = sendFrame(OPCODE_BINARY, payload, fin = true)

    /** A CLOSE frame carrying [statusCode], as a relay sends when it ends the connection. */
    fun sendClose(statusCode: Int = 1000) =
      sendFrame(OPCODE_CLOSE, byteArrayOf((statusCode ushr 8).toByte(), statusCode.toByte()), fin = true)

    @Synchronized
    fun sendFrame(opcode: Int, payload: ByteArray, fin: Boolean) {
      val header = ByteArrayOutputStream()
      header.write((if (fin) 0x80 else 0x00) or opcode)
      when {
        payload.size < 126 -> header.write(payload.size)
        payload.size < 65536 -> {
          header.write(126)
          header.write((payload.size ushr 8) and 0xFF)
          header.write(payload.size and 0xFF)
        }
        else -> {
          header.write(127)
          for (shift in 56 downTo 0 step 8) header.write(((payload.size.toLong() ushr shift) and 0xFF).toInt())
        }
      }
      output.write(header.toByteArray())
      output.write(payload)
      output.flush()
    }

    /** Read and reassemble the next client TEXT message, unmasking it; skips PING/PONG; returns null
     * on CLOSE, EOF, or a [timeoutMillis] read timeout. */
    fun nextClientText(timeoutMillis: Int): String? {
      sock.soTimeout = timeoutMillis
      val message = ByteArrayOutputStream()
      while (true) {
        val frame =
          try {
            readFrame(input)
          } catch (e: SocketTimeoutException) {
            return null
          } ?: return null
        when (frame.opcode) {
          OPCODE_TEXT, OPCODE_CONTINUATION -> {
            message.write(frame.payload)
            if (frame.fin) return message.toString(Charsets.UTF_8.name())
          }
          OPCODE_CLOSE -> return null
          OPCODE_PING, OPCODE_PONG -> {} // the client's auto-pong (and any ping): skip, keep reading
          else -> {} // binary or any other frame: skip, keep reading for text
        }
      }
    }
  }

  private data class Frame(val fin: Boolean, val opcode: Int, val payload: ByteArray)

  private fun readFrame(input: InputStream): Frame? {
    val head = readFully(input, 2) ?: return null
    val fin = (head[0].toInt() and 0x80) != 0
    val opcode = head[0].toInt() and 0x0F
    val masked = (head[1].toInt() and 0x80) != 0
    var len = (head[1].toInt() and 0x7F).toLong()
    if (len == 126L) {
      val ext = readFully(input, 2) ?: return null
      len = ((ext[0].toInt() and 0xFF) shl 8 or (ext[1].toInt() and 0xFF)).toLong()
    } else if (len == 127L) {
      val ext = readFully(input, 8) ?: return null
      len = 0
      for (b in ext) len = (len shl 8) or (b.toLong() and 0xFF)
    }
    val mask = if (masked) readFully(input, 4) ?: return null else ByteArray(0)
    val payload = readFully(input, len.toInt()) ?: return null
    if (masked) for (i in payload.indices) payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
    return Frame(fin, opcode, payload)
  }

  private fun readFully(input: InputStream, n: Int): ByteArray? {
    val buf = ByteArray(n)
    var off = 0
    while (off < n) {
      val r = input.read(buf, off, n - off)
      if (r < 0) return null
      off += r
    }
    return buf
  }

  private companion object {
    const val OPCODE_CONTINUATION = 0x0
    const val OPCODE_TEXT = 0x1
    const val OPCODE_BINARY = 0x2
    const val OPCODE_CLOSE = 0x8
    const val OPCODE_PING = 0x9
    const val OPCODE_PONG = 0xA
  }
}

/** Poll [cond] until it holds or [timeoutMillis] passes, and return whether it held. What a [FakeRelay]
 * script sends lands on the client's listener thread, so a cell waits for its effect this way. */
fun waitUntil(timeoutMillis: Long, cond: () -> Boolean): Boolean {
  val deadline = System.currentTimeMillis() + timeoutMillis
  while (System.currentTimeMillis() < deadline) {
    if (cond()) return true
    Thread.sleep(20)
  }
  return cond()
}
