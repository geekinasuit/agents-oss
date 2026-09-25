package com.geekinasuit.agency.shared.journal

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.long

/**
 * `state = fold(log)` — the single state-derivation. Everything durable is an entry:
 * effects (intent/done), timers
 * (armed/fired), mailbox (appended/delivered), sessions, key epochs, gate releases.
 * Recovery after any process death is re-folding the journal; nothing lives only in
 * process memory.
 *
 * CONSUMPTION CONTRACT (the state-bump rule): unknown
 * kinds fold as no-ops so OLD code tolerates NEW event kinds — which is only safe under
 * the rule that adding an entry kind that CARRIES STATE requires a schemaVersion bump, so
 * pre-bump readers hit the version gate instead of silently folding the new kind away.
 *
 * Gate releases are a PROVENANCE check, not a kind check: a
 * [KIND_GATE_RELEASED] entry counts only when its origin is the authorization layer;
 * a gate-release-shaped entry from any other origin is retained VISIBLY in
 * [JournalState.rejectedGateReleases] — never silently dropped, never honored. (The fold
 * enforces this rule even before an authorization layer exists to emit legitimate
 * releases.)
 */
data class ArmedTimer(val id: String, val fireAtEpochMs: Long, val action: String)

data class JournalState(
  val intents: Map<String, JsonObject> = emptyMap(),
  val doneKeys: Map<String, Int> = emptyMap(), // key -> attempts recorded at completion
  val armedTimers: Map<String, ArmedTimer> = emptyMap(),
  val firedTimers: Set<String> = emptySet(),
  val sessions: Set<String> = emptySet(),
  val mailboxAppended: Map<Long, String> = emptyMap(), // append seq -> message
  val mailboxDelivered: Set<Long> = emptySet(),
  val currentKeyEpoch: Int = 0,
  /**
   * Gate ids whose release carried authorization provenance (origin == auth layer). This is
   * a PROVENANCE-ONLY view: it does NOT verify DIGEST BINDING — a release whose digest does
   * not match the gate as opened is still listed here, because the shared fold does not
   * track gate digests. A consumer that requires binding — "the
   * approver signed the exact artifact the gate was opened on" — MUST use its own component
   * fold's rule (e.g. the lead's `releasedGates`, which honors a release only on a digest
   * match and holds mismatches as stale) and treat this list as "provenance seen", not
   * "approved". Using it directly as authorization would honor a stale-digest release.
   */
  val gateReleases: List<String> = emptyList(),
  val rejectedGateReleases: List<Pair<Long, String>> = emptyList(), // (seq, gateId)
) {
  val pendingTimers: List<ArmedTimer>
    get() = armedTimers.values.filter { it.id !in firedTimers }.sortedBy { it.fireAtEpochMs }

  val pendingEffectKeys: List<String>
    get() = intents.keys.filter { it !in doneKeys }.sorted()

  val undeliveredMail: List<Pair<Long, String>>
    get() = mailboxAppended.filterKeys { it !in mailboxDelivered }.toList().sortedBy { it.first }
}

const val KIND_GATE_RELEASED = "gate-released"

/** Folds [entries] in order. An entry the fold cannot read fails the fold with a
 * [JournalFoldException] that names it. */
fun fold(entries: List<JournalEntry>): JournalState {
  var s = JournalState()
  for (e in entries) {
    s =
      try {
        foldOne(s, e)
      } catch (x: Exception) {
        throw JournalFoldException(e.seq, e.kind, x)
      }
  }
  return s
}

private fun foldOne(s: JournalState, e: JournalEntry): JournalState {
  val p = payloadObject(e.payloadJson)
  return when (e.kind) {
    KIND_GENESIS -> s
    KIND_KEY_EPOCH_STARTED -> s.copy(currentKeyEpoch = e.keyEpoch)
    "effect-intent" -> {
      val key = e.idempotencyKey
      requireContract(key != null) { "an effect-intent entry carries no idempotency key" }
      s.copy(intents = s.intents + (key to p))
    }
    "effect-done" -> s.copy(doneKeys = s.doneKeys + (p.str("key") to p.int("attempt")))
    "timer-armed" ->
      s.copy(
        armedTimers =
          s.armedTimers + (p.str("id") to ArmedTimer(p.str("id"), p.lng("fireAtEpochMs"), p.str("action")))
      )
    "timer-fired" -> s.copy(firedTimers = s.firedTimers + p.str("id"))
    "session-started" -> s.copy(sessions = s.sessions + p.str("sessionId"))
    "mailbox-appended" -> s.copy(mailboxAppended = s.mailboxAppended + (e.seq to p.str("message")))
    "mailbox-delivered" -> s.copy(mailboxDelivered = s.mailboxDelivered + p.lng("appendSeq"))
    KIND_GATE_RELEASED ->
      if (e.origin == ORIGIN_AUTH_LAYER) s.copy(gateReleases = s.gateReleases + p.str("gateId"))
      else s.copy(rejectedGateReleases = s.rejectedGateReleases + (e.seq to p.str("gateId")))
    "note" -> s
    else -> s // unknown kinds no-op — legal ONLY under the state-bump rule above
  }
}

// The readers take any scalar's text, an integer's text, and a JSON long. A field they cannot read
// is refused with a message that names the field and not its content.
private fun JsonObject.scalar(k: String): JsonPrimitive =
  this[k] as? JsonPrimitive
    ?: throw PayloadContractException("payload field '$k' is missing or not a JSON scalar")

private fun JsonObject.str(k: String): String = scalar(k).content

private fun JsonObject.int(k: String): Int =
  scalar(k).content.toIntOrNull()
    ?: throw PayloadContractException("payload field '$k' is not an integer")

private fun JsonObject.lng(k: String): Long {
  val field = scalar(k)
  return try {
    field.long
  } catch (_: RuntimeException) {
    // .long only parses the field's text, and its lexer throws more than IllegalArgumentException
    // for text it cannot read (a quote that never closes, for one), so any failure means the field
    // is not an integer.
    throw PayloadContractException("payload field '$k' is not an integer")
  }
}
