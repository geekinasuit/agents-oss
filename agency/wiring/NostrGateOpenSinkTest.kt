package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.lead.AnnounceOutcome
import com.geekinasuit.agency.lead.GateOpenSignal
import com.geekinasuit.agency.nostr.Bip340
import com.geekinasuit.agency.nostr.EventPublisher
import com.geekinasuit.agency.nostr.GateOpenNotice
import com.geekinasuit.agency.nostr.Nip59
import com.geekinasuit.agency.nostr.Notifier
import com.geekinasuit.agency.nostr.NotifyOutcome
import com.geekinasuit.agency.nostr.NotifyReport
import com.geekinasuit.agency.nostr.PublishResult
import com.geekinasuit.agency.nostr.RecipientKey
import com.geekinasuit.agency.nostr.RelayNotifier
import com.geekinasuit.agency.nostr.SecretKeyHex
import java.time.Duration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The nostr gate-open sink: how a notifier's per-recipient report becomes the host's announce
 * outcome, through a scripted [Notifier], and one cell through the real [RelayNotifier] showing the
 * signal reaches the wire as a gift wrap per recipient.
 */
class NostrGateOpenSinkTest {

  private class ScriptedNotifier(private val outcome: (RecipientKey) -> NotifyOutcome) : Notifier {
    val notices = mutableListOf<GateOpenNotice>()

    override fun notifyGateOpen(notice: GateOpenNotice, recipients: Set<RecipientKey>, timeout: Duration): NotifyReport {
      notices += notice
      return NotifyReport(recipients.associateWith(outcome))
    }
  }

  @Test
  fun aSinkWithNoRecipientsHasNowhereToAnnounceAndSendsNothing() {
    val notifier = ScriptedNotifier { NotifyOutcome.Delivered }
    assertEquals(AnnounceOutcome.NoSink, NostrGateOpenSink(notifier, emptySet(), TIMEOUT).announce(SIGNAL))
    assertTrue(notifier.notices.isEmpty())
  }

  @Test
  fun aNoticeDeliveredToEveryRecipientIsAnnouncedAndCarriesTheSignal() {
    val notifier = ScriptedNotifier { NotifyOutcome.Delivered }
    val outcome = NostrGateOpenSink(notifier, setOf(ALICE, BOB), TIMEOUT).announce(SIGNAL)
    assertEquals(AnnounceOutcome.Announced("delivered 2 of 2"), outcome)
    assertEquals(
      listOf(GateOpenNotice(SIGNAL.gateId, SIGNAL.payloadDigest, SIGNAL.nonce, SIGNAL.artifact)),
      notifier.notices,
    )
  }

  @Test
  fun aNoticeDeliveredToOneOfTwoFailsAndNamesTheOther() {
    // A two-of-two quorum needs both custodians told, so one delivery is not enough to stop retrying.
    val notifier = ScriptedNotifier { if (it == ALICE) NotifyOutcome.Delivered else NotifyOutcome.Rejected("blocked") }
    val outcome = NostrGateOpenSink(notifier, setOf(ALICE, BOB), TIMEOUT).announce(SIGNAL)
    assertEquals(AnnounceOutcome.Failed("delivered 1 of 2; ${BOB.hex.take(8)}: rejected: blocked"), outcome)
  }

  @Test
  fun aRelaysLongMessageIsCutInTheSummary() {
    val long = "r".repeat(5000)
    for (miss in listOf(NotifyOutcome.Rejected(long), NotifyOutcome.Failed(long))) {
      val outcome = NostrGateOpenSink(ScriptedNotifier { miss }, setOf(ALICE), TIMEOUT).announce(SIGNAL)
      val detail = (outcome as AnnounceOutcome.Failed).detail
      assertTrue("${miss::class.simpleName}: cut to ${NostrGateOpenSink.MAX_MESSAGE_CHARS}: ${detail.length}", detail.length < 300)
    }
  }

  @Test
  fun aNoticeDeliveredToNobodyFailsSoTheHostRetriesIt() {
    for (miss in listOf(NotifyOutcome.Rejected("no"), NotifyOutcome.Failed("socket closed"))) {
      val outcome = NostrGateOpenSink(ScriptedNotifier { miss }, setOf(ALICE), TIMEOUT).announce(SIGNAL)
      assertTrue("$miss: $outcome", outcome is AnnounceOutcome.Failed)
    }
  }

  @Test
  fun aNoticeTooLargeToEncodeIsUnsendableSoTheHostDoesNotRetryIt() {
    val notifier = ScriptedNotifier { NotifyOutcome.NotEncodable(50_000, 40_960) }
    assertEquals(
      AnnounceOutcome.Unsendable("delivered 0 of 1; ${ALICE.hex.take(8)}: too large: 50000 > 40960 bytes"),
      NostrGateOpenSink(notifier, setOf(ALICE), TIMEOUT).announce(SIGNAL),
    )
  }

  @Test
  fun anArtifactWithinTheSinksCapacityCanStillBeUnsendableThroughTheRelayNotifier() {
    // The capacity the host checks is the artifact's bytes, and the notice adds tags and JSON
    // escapes the artifact, so a copy the host accepts can still fail to encode.
    val publisher = EventPublisher { _, _ -> PublishResult.Accepted }
    val notifier = RelayNotifier(SecretKeyHex.ofHexString(LEAD_SECRET), publisher)
    val sink = NostrGateOpenSink(notifier, setOf(ALICE), TIMEOUT)
    val artifact = "\"".repeat(36_000)
    assertTrue("the host would accept it", artifact.toByteArray().size <= sink.maxArtifactBytes)

    val outcome = sink.announce(SIGNAL.copy(artifact = artifact))
    assertTrue("$outcome", outcome is AnnounceOutcome.Unsendable)
  }

  @Test
  fun aNotifierThatThrowsIsAFailureNotAThrow() {
    val throwing =
      object : Notifier {
        override fun notifyGateOpen(notice: GateOpenNotice, recipients: Set<RecipientKey>, timeout: Duration): NotifyReport =
          throw IllegalStateException("x".repeat(1000))
      }
    val outcome = NostrGateOpenSink(throwing, setOf(ALICE), TIMEOUT).announce(SIGNAL)
    assertTrue(outcome is AnnounceOutcome.Failed)
    val detail = (outcome as AnnounceOutcome.Failed).detail
    assertTrue("the message is cut: ${detail.length}", detail.length < 300)
  }

  @Test
  fun aSignalNoNoticeCanCarryIsUnsendableNotAThrow() {
    // A lone surrogate has no UTF-8 encoding, which a notice refuses at construction.
    val signal = SIGNAL.copy(gateId = "plan-approval:" + Char(0xD800))
    val outcome = NostrGateOpenSink(ScriptedNotifier { NotifyOutcome.Delivered }, setOf(ALICE), TIMEOUT).announce(signal)
    assertTrue("$outcome", outcome is AnnounceOutcome.Unsendable)
  }

  @Test
  fun theSinkDeclaresTheLargestRumorAGiftWrapCarries() {
    val sink = NostrGateOpenSink(ScriptedNotifier { NotifyOutcome.Delivered }, setOf(ALICE), TIMEOUT)
    assertEquals(Nip59.RUMOR_CEILING_BYTES, sink.maxArtifactBytes)
  }

  @Test
  fun throughTheRelayNotifierEachRecipientGetsOneGiftWrap() {
    val published = mutableListOf<Int>()
    val publisher = EventPublisher { event, _ ->
      published += event.kind
      PublishResult.Accepted
    }
    val notifier = RelayNotifier(SecretKeyHex.ofHexString(LEAD_SECRET), publisher)
    val outcome = NostrGateOpenSink(notifier, setOf(ALICE, BOB), TIMEOUT).announce(SIGNAL)
    assertEquals(AnnounceOutcome.Announced("delivered 2 of 2"), outcome)
    assertEquals("one kind-1059 gift wrap per recipient", listOf(1059, 1059), published)
  }

  private companion object {
    const val LEAD_SECRET = "0000000000000000000000000000000000000000000000000000000000000003"
    val ALICE = RecipientKey.of(Bip340.xonlyPubkeyHex("0000000000000000000000000000000000000000000000000000000000000005"))
    val BOB = RecipientKey.of(Bip340.xonlyPubkeyHex("0000000000000000000000000000000000000000000000000000000000000007"))
    val TIMEOUT: Duration = Duration.ofSeconds(5)
    val SIGNAL = GateOpenSignal("plan-approval:t1", "a".repeat(64), "b".repeat(64), "The plan, in words a person reads.")
  }
}
