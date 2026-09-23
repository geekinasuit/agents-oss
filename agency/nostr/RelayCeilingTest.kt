package com.geekinasuit.agency.nostr

import java.time.Duration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test

/**
 * The DEPTH bound's margin: a frame nested exactly [RelayConnection.MAX_JSON_DEPTH] deep, which the
 * depth check admits, parses on the listener thread without overflowing that thread's stack. The
 * JDK invokes the listener on a thread of its choosing: one of the client's executor threads, or a
 * thread of `CompletableFuture`'s default executor, which is a worker of the common ForkJoinPool,
 * or a new thread per task when that pool's parallelism is below 2. With the default client, all
 * of them get the JVM's default thread stack. Each cell sends such a frame and then a NOTICE on one
 * connection. A parse that overflowed would reach the listener's onError and fail the connection,
 * and the NOTICE would never arrive, so the NOTICE arriving is the evidence that the ceiling-depth
 * parse survived on that thread. None of these frames is a relay message, so each parses to null
 * and is dropped, with no breach.
 *
 * How much stack the parser needs per level depends on the JIT state it runs in, so the build runs
 * this class under three targets, each pinning one state: interpreted, the parser's state until
 * the JIT compiles it; compiled by C1 with profiling (tier 3); and tier 3 with kotlinx's
 * `JsonTreeReader.readArray` left interpreted, so that each array level calls between compiled and
 * interpreted code. Of the states measured, all on aarch64, the last two need the most stack per
 * level. [warmUp] parses each of the three nested frames before any cell runs, so that under the
 * compiled targets the listener's parses of them run compiled, rather than whenever the compiler
 * catches up.
 *
 * So the cells fail once a change lowers the parser's overflow depth below the ceiling on the
 * default thread stack of the platform the build runs on, in any of these states.
 */
class RelayCeilingTest {
  private val key = "0000000000000000000000000000000000000000000000000000000000000003"

  private fun config(url: String) = RelayConfig(relayUrl = url, leadSecretKey = SecretKeyHex.ofHexString(key))

  @Test
  fun `a message nested to the depth ceiling is parsed safely on the listener thread`() {
    // The parser recurses on the stack once per level of array nesting, so all of this frame's
    // levels run on the listener thread's stack.
    assertParsedOnTheListenerThread(ARRAYS)
  }

  @Test
  fun `an object nested to the depth ceiling is parsed safely on the listener thread`() {
    // The depth check counts `{` as it counts `[`, so it admits this frame too, and a check that
    // refused at the ceiling would breach before the NOTICE. It is not a stack-margin check: the
    // parser reads the 200th object and every object inside it on the heap, so this frame keeps
    // only about 200 of its levels on the stack.
    assertParsedOnTheListenerThread(OBJECTS)
  }

  @Test
  fun `an array inside the 200th object, nested to the depth ceiling, is parsed safely on the listener thread`() {
    // An array inside the heap region puts the objects inside it back on the stack
    // ([jsonMayNestDeeperThan] says which nesting stays on the stack), so all but one of this
    // frame's levels run on the listener thread's stack, most of them objects.
    assertParsedOnTheListenerThread(OBJECTS_AROUND_AN_ARRAY)
  }

  private fun assertParsedOnTheListenerThread(frame: String) {
    FakeRelay().use { relay ->
      relay.serve { session ->
        session.sendText(frame)
        session.sendText("[\"NOTICE\",\"alive\"]")
      }
      val conn = RelayConnection(config(relay.url))
      assertEquals(ConnectResult.Connected, conn.connect(Duration.ofSeconds(5)))
      assertEquals(RelayMessage.Notice("alive"), conn.receive(Duration.ofSeconds(5)))
      assertTrue("the connection must survive the ceiling-depth parse", !conn.hasFailed())
      conn.close()
    }
  }

  companion object {
    private const val DEPTH = RelayConnection.MAX_JSON_DEPTH

    // kotlinx reads the 200th object, and every object past it, on the heap, unless an array lies
    // between them.
    private const val HEAP_READER_OBJECT = 200

    private val ARRAYS = "[".repeat(DEPTH) + "]".repeat(DEPTH)

    private val OBJECTS = objects(DEPTH, "0")

    private val OBJECTS_AROUND_AN_ARRAY =
      objects(HEAP_READER_OBJECT, "[" + objects(DEPTH - HEAP_READER_OBJECT - 1, "0") + "]")

    // More than one: code compiled during the first warm-up can be discarded before that warm-up
    // ends, to be compiled again during the next.
    private const val WARM_UPS = 3

    private const val ROOMY_STACK_BYTES = 64L * 1024 * 1024

    /** [n] objects, each the value of the one before it, around [value]. */
    private fun objects(n: Int, value: String): String = "{\"a\":".repeat(n) + value + "}".repeat(n)

    /**
     * Parses each of the three nested frames [WARM_UPS] times, through the parse the listener runs,
     * on a stack roomy enough that none can overflow. Under the compiled targets this compiles the
     * methods the parser recurses through (all but `readArray` under the target that leaves that
     * method interpreted), and -Xbatch finishes each compile before the parse that triggered it
     * goes on. Under the interpreted target it changes nothing. A warm-up that threw would rethrow
     * here and fail the class before any cell runs.
     */
    @BeforeClass
    @JvmStatic
    fun warmUp() {
      for (frame in listOf(ARRAYS, OBJECTS, OBJECTS_AROUND_AN_ARRAY)) {
        repeat(WARM_UPS) { parseOnRoomyStack(frame) }
      }
    }

    private fun parseOnRoomyStack(frame: String) {
      var outcome: Result<RelayMessage?>? = null
      val thread =
        Thread(
          null,
          { outcome = runCatching { parseRelayMessage(frame) } },
          "warm-up",
          ROOMY_STACK_BYTES,
        )
      thread.start()
      thread.join()
      outcome!!.getOrThrow()
    }
  }
}
