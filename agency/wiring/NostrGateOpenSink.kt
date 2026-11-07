package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.lead.AnnounceOutcome
import com.geekinasuit.agency.lead.GateOpenSignal
import com.geekinasuit.agency.lead.GateOpenSink
import com.geekinasuit.agency.nostr.GateOpenNotice
import com.geekinasuit.agency.nostr.Nip59
import com.geekinasuit.agency.nostr.Notifier
import com.geekinasuit.agency.nostr.NotifyOutcome
import com.geekinasuit.agency.nostr.RecipientKey
import java.time.Duration

/**
 * The [GateOpenSink] a deployment that notifies over nostr wires into the host: it turns the host's
 * [GateOpenSignal] into a [GateOpenNotice] and hands it to [notifier] for [recipients], passing it
 * [timeout] for each publish. How long that holds the host's loop thread is the notifier's: a
 * [com.geekinasuit.agency.nostr.RelayNotifier] publishes to each recipient in turn, so its publisher's
 * whole per-publish bound (connect and authenticate included, for a reconnecting one) times the number
 * of recipients.
 *
 * The outcome follows the sink contract:
 *  - no recipients: [AnnounceOutcome.NoSink], without calling [notifier], so the host escalates at
 *    once rather than retrying a sink that can never deliver;
 *  - every recipient delivered: [AnnounceOutcome.Announced];
 *  - a notice that cannot be built, or that is too large to wrap for a recipient:
 *    [AnnounceOutcome.Unsendable], since sending the same signal again gets the same answer;
 *  - any other recipient missed, or the notice could not be sent at all: [AnnounceOutcome.Failed],
 *    with a summary naming each recipient missed. The host sends the whole signal again on its backoff
 *    until every recipient has it, and escalates once along the way. A quorum may need more than one
 *    of the recipients, so a partial delivery is not treated as enough; a recipient told twice is
 *    harmless, since the nonce is single-use. The cost: while one recipient cannot be reached, every
 *    gate it delays long enough is escalated, and each reachable recipient gets the notice once per
 *    attempt, for as long as the gate stays open.
 *
 * Never throws: [announce] runs on the host's loop thread. The summary and detail are journaled, so
 * each relay message in them is cut to [MAX_MESSAGE_CHARS], and a recipient is named by the first
 * [KEY_PREFIX_CHARS] hex digits of its key.
 */
class NostrGateOpenSink(
  private val notifier: Notifier,
  private val recipients: Set<RecipientKey>,
  private val timeout: Duration,
) : GateOpenSink {

  /** The most a gift wrap can carry as its rumor. The notice adds tags to the artifact, so an
   * artifact at this size can still fail to wrap; the host refuses one larger before calling. */
  override val maxArtifactBytes: Int
    get() = Nip59.RUMOR_CEILING_BYTES

  override fun announce(signal: GateOpenSignal): AnnounceOutcome {
    if (recipients.isEmpty()) return AnnounceOutcome.NoSink
    val notice =
      try {
        GateOpenNotice(signal.gateId, signal.payloadDigest, signal.nonce, signal.artifact)
      } catch (x: IllegalArgumentException) {
        return AnnounceOutcome.Unsendable("notice not built: ${cut(x.message)}")
      }
    val report =
      try {
        notifier.notifyGateOpen(notice, recipients, timeout)
      } catch (x: Exception) {
        return AnnounceOutcome.Failed("notice not sent: ${x.javaClass.simpleName}: ${cut(x.message)}")
      }
    val delivered = report.outcomes.count { it.value == NotifyOutcome.Delivered }
    val misses =
      report.outcomes
        .filterValues { it != NotifyOutcome.Delivered }
        .map { (key, outcome) -> "${key.hex.take(KEY_PREFIX_CHARS)}: ${describe(outcome)}" }
    val summary =
      (listOf("delivered $delivered of ${report.outcomes.size}") + misses).joinToString("; ")
    return when {
      misses.isEmpty() -> AnnounceOutcome.Announced(summary)
      report.outcomes.values.any { it is NotifyOutcome.NotEncodable } -> AnnounceOutcome.Unsendable(summary)
      else -> AnnounceOutcome.Failed(summary)
    }
  }

  private fun describe(outcome: NotifyOutcome): String =
    when (outcome) {
      NotifyOutcome.Delivered -> "delivered"
      is NotifyOutcome.Rejected -> "rejected: ${cut(outcome.message)}"
      is NotifyOutcome.Failed -> "failed: ${cut(outcome.detail)}"
      is NotifyOutcome.NotEncodable -> "too large: ${outcome.plaintextBytes} > ${outcome.ceilingBytes} bytes"
    }

  private fun cut(text: String?): String = (text ?: "").take(MAX_MESSAGE_CHARS)

  companion object {
    /** How much of each relay message or fault detail a summary keeps. */
    const val MAX_MESSAGE_CHARS = 200

    /** How many hex digits of a recipient's key a summary names it by. */
    const val KEY_PREFIX_CHARS = 8
  }
}
