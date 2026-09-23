package com.geekinasuit.agency.shared.json

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * What kotlinx's tree parser does with deep nesting on the small stack [onSmallStack] runs a
 * block on.
 *
 * First, the premise every onSmallStack cell rests on. Such a cell feeds a guarded parse nesting
 * that its depth check must refuse, and reads the refusal as proof the check stopped the parse.
 * That holds only if the parse, unguarded, would overflow the small stack: on a stack roomy enough
 * to finish, the parser throws an Exception at the end of the text instead, which a total parse
 * maps to the same refusal.
 *
 * Then the facts [jsonMayNestDeeperThan]'s KDoc states about which nesting the parser reads on the
 * stack, so that a kotlinx version that changed one fails here instead of leaving that KDoc wrong.
 */
class SmallStackTest {

  @Test
  fun `the unguarded parse of the shallowest nesting any cell feeds overflows the small stack`() {
    assertEndings(SHALLOWEST, roomy = EXCEPTION, small = OVERFLOW)
  }

  @Test
  fun `nested arrays overflow the small stack`() {
    assertEndings(arrays(DEEP), roomy = PARSED, small = OVERFLOW)
  }

  @Test
  fun `nested objects alone do not overflow the small stack`() {
    // From the 200th object on, the parser reads objects on the heap, so objects alone keep at most
    // 199 levels on the stack.
    assertEndings(objects(DEEP, "0"), roomy = PARSED, small = PARSED)
  }

  @Test
  fun `an array inside the 200th object puts the objects inside it back on the stack`() {
    assertEndings(objects(200, "[" + objects(DEEP, "0") + "]"), roomy = PARSED, small = OVERFLOW)
  }

  @Test
  fun `an array inside the 199th object does not put the objects inside it on the stack`() {
    // Its first object is the 200th, where the parser switches to the heap, so it reads that object
    // and every object inside it there. With the cell above, this puts the switch at exactly the
    // 200th object.
    assertEndings(objects(199, "[" + objects(DEEP, "0") + "]"), roomy = PARSED, small = PARSED)
  }

  /**
   * Parses [text] [WARM_UPS] times on a roomy stack, then once on the small stack, and checks that
   * each warm-up ends as [roomy] says and the attempt as [small] says.
   *
   * Compiled frames are smaller than interpreted ones, so the parser nests deeper before it
   * overflows once the JIT has compiled it. The warm-ups are enough calls to compile the reader,
   * and the target's -Xbatch finishes each compile before the parse that triggered it goes on, so
   * the attempt runs on the compiled reader. No warm-up may overflow: that shows it is the small
   * stack, not the text, that stops an attempt that does.
   */
  private fun assertEndings(text: String, roomy: String, small: String) {
    val warmUps = List(WARM_UPS) { ending(outcomeOnRoomyStack(text)) }
    val attempt = ending(onSmallStack { parseOutcome(text) })
    assertEquals(
      "how the parse ended on a roomy stack, then on the small one",
      List(WARM_UPS) { roomy } + small,
      warmUps + attempt,
    )
  }

  /** [n] arrays, each inside the one before it, around a 0. */
  private fun arrays(n: Int): String = "[".repeat(n) + "0" + "]".repeat(n)

  /** [n] objects, each the value of the one before it, around [value]. */
  private fun objects(n: Int, value: String): String = "{\"a\":".repeat(n) + value + "}".repeat(n)

  /** What parsing [text] threw, or null if it returned. */
  private fun parseOutcome(text: String): Throwable? =
    runCatching { Json.parseToJsonElement(text) }.exceptionOrNull()

  /** [parseOutcome] on a thread whose stack is roomy enough for the parse to run the whole text. */
  private fun outcomeOnRoomyStack(text: String): Throwable? {
    var outcome: Throwable? = null
    val thread = Thread(null, { outcome = parseOutcome(text) }, "roomy-stack", ROOMY_STACK_BYTES)
    thread.start()
    thread.join()
    return outcome
  }

  /** How a parse ended, named for the assertion message. */
  private fun ending(outcome: Throwable?): String =
    when (outcome) {
      null -> PARSED
      is StackOverflowError -> OVERFLOW
      is Exception -> EXCEPTION
      else -> outcome.javaClass.name
    }

  private companion object {
    // The shallowest nesting any onSmallStack cell feeds: `[1]` repeated 13,000 times, which
    // kotlinx nests one level per `[1]`. A cell that feeds shallower array nesting must lower
    // this. Nesting objects alone does not overflow the small stack ([jsonMayNestDeeperThan] says
    // which nesting does), so a cell that feeds only objects passes whether or not its guard fires.
    val SHALLOWEST = "[1]".repeat(13_000)
    // Levels enough that a parse reading them all on the stack overflows the small stack several
    // times over even compiled, and few enough that the roomy stack holds them even interpreted.
    // The cells that do not overflow keep about 200 levels on the stack, which the small stack
    // holds even interpreted. So no cell's ending depends on which JIT state its attempt runs in.
    const val DEEP = 13_000
    const val ROOMY_STACK_BYTES = 64L * 1024 * 1024
    // More than one: the reader compiled during the first warm-up can be discarded before that
    // warm-up ends, to be compiled again during the next.
    const val WARM_UPS = 3
    const val PARSED = "parsed"
    const val EXCEPTION = "an Exception"
    const val OVERFLOW = "a StackOverflowError"
  }
}
