package com.geekinasuit.agency.shared.json

import kotlinx.serialization.json.Json
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The premise every [onSmallStack] cell rests on. Such a cell feeds a guarded parse nesting that
 * its depth check must refuse, and reads the refusal as proof the check stopped the parse. That
 * holds only if the parse, unguarded, would overflow the small stack: on a stack roomy enough to
 * finish, the parser throws an Exception at the end of the text instead, which a total parse maps
 * to the same refusal.
 */
class SmallStackTest {

  @Test
  fun `the unguarded parse of the shallowest nesting any cell feeds overflows the small stack`() {
    // Compiled frames are smaller than interpreted ones, so the parser nests deeper before it
    // overflows once the JIT has compiled it. The warm-ups run the whole text on a roomy stack,
    // enough calls to compile the reader, and the target's -Xbatch finishes each compile before
    // the parse that triggered it goes on, so the attempt on the small stack runs on the compiled
    // reader. Each warm-up must end in an Exception, not an overflow: that shows it is the small
    // stack, not the text, that stops the attempt.
    val warmUps = List(WARM_UPS) { outcomeOnRoomyStack() }
    assertTrue(
      "on a roomy stack the parse ends in an Exception, not an overflow: ${names(warmUps)}",
      warmUps.all { it is Exception },
    )
    val attempt = onSmallStack { parseOutcome() }
    assertTrue(
      "the parse overflows the small stack: ${names(listOf(attempt))}",
      attempt is StackOverflowError,
    )
  }

  /** What parsing [SHALLOWEST] threw, or null if it returned. */
  private fun parseOutcome(): Throwable? =
    runCatching { Json.parseToJsonElement(SHALLOWEST) }.exceptionOrNull()

  /** [parseOutcome] on a thread whose stack is roomy enough for the parse to run the whole text. */
  private fun outcomeOnRoomyStack(): Throwable? {
    var outcome: Throwable? = null
    val thread = Thread(null, { outcome = parseOutcome() }, "roomy-stack", ROOMY_STACK_BYTES)
    thread.start()
    thread.join()
    return outcome
  }

  private fun names(outcomes: List<Throwable?>): List<String?> =
    outcomes.map { it?.javaClass?.simpleName }

  private companion object {
    // The shallowest nesting any onSmallStack cell feeds: `[1]` repeated 13,000 times, which
    // kotlinx nests one level per `[1]`. A cell that feeds shallower array nesting must lower
    // this. Nesting objects alone does not overflow the small stack ([jsonMayNestDeeperThan] says
    // which nesting does), so a cell that feeds only objects passes whether or not its guard fires.
    val SHALLOWEST = "[1]".repeat(13_000)
    const val ROOMY_STACK_BYTES = 64L * 1024 * 1024
    // More than one: the reader compiled during the first warm-up can be discarded before that
    // warm-up ends, to be compiled again during the next.
    const val WARM_UPS = 3
  }
}
