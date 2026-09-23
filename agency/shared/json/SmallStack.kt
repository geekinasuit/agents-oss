package com.geekinasuit.agency.shared.json

/**
 * Runs [block] on a new thread with a deliberately small stack (256 KiB) and returns its result,
 * rethrowing on the calling thread whatever it threw — an Error such as StackOverflowError included.
 *
 * For cells that prove a depth check stops a parse before it starts: on this stack, a parse of the
 * nesting such a cell feeds overflows, so a check that let it through fails the cell loudly rather
 * than passing on a stack deep enough to survive it.
 */
fun <T> onSmallStack(block: () -> T): T {
  var outcome: Result<T>? = null
  val thread = Thread(null, { outcome = runCatching(block) }, "small-stack", SMALL_STACK_BYTES)
  thread.start()
  thread.join()
  return outcome!!.getOrThrow()
}

private const val SMALL_STACK_BYTES = 256L * 1024
