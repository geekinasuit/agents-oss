package com.geekinasuit.agency.nostr

import java.time.Duration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The relay-backed notifier's fan-out over a recipient SET. Tests through a fake [EventPublisher] —
 * no socket — but signs in the crypto phase, so it needs the native runtime. Pins: case-variant
 * recipients dedup to one publish, an empty set is refused fail-closed, a malformed lead key is
 * refused at construction, each recipient gets its own outcome (partial delivery is a liveness gap),
 * an oversize notice is NotEncodable for every recipient without publishing, all crypto completes
 * before any publish (the #45 phase separation), and a closed notifier fails its next notify closed.
 */
class RelayNotifierTest {
  private val leadSecret = "0000000000000000000000000000000000000000000000000000000000000001"
  private val recipASecret = "0000000000000000000000000000000000000000000000000000000000000002"
  private val recipBSecret = "0000000000000000000000000000000000000000000000000000000000000003"
  private val recipCSecret = "0000000000000000000000000000000000000000000000000000000000000004"
  private val timeout = Duration.ofSeconds(3)
  private val notice = GateOpenNotice("gate-1", "digest", "nonce", "artifact")

  private fun key(secret: String) = RecipientKey.of(Bip340.xonlyPubkeyHex(secret))

  private class FakePublisher : EventPublisher {
    val published = mutableListOf<NostrEvent>()
    val timeouts = mutableListOf<Duration>()
    private val queued = ArrayDeque<PublishResult>()

    fun enqueue(vararg results: PublishResult) = queued.addAll(results)

    override fun publish(event: NostrEvent, timeout: Duration): PublishResult {
      published.add(event)
      timeouts.add(timeout)
      return if (queued.isEmpty()) PublishResult.Accepted else queued.removeFirst()
    }
  }

  @Test
  fun deduplicates_case_variant_recipients_to_one_publish() {
    val lower = Bip340.xonlyPubkeyHex(recipASecret)
    val recipients = setOf(RecipientKey.of(lower), RecipientKey.of(lower.uppercase()))
    assertEquals("case variants of one key collapse to one recipient", 1, recipients.size)

    val fake = FakePublisher()
    val report =
      RelayNotifier(SecretKeyHex.ofHexString(leadSecret), fake)
        .notifyGateOpen(notice, recipients, timeout)
    assertEquals("one recipient, one publish", 1, fake.published.size)
    assertEquals(1, report.outcomes.size)
  }

  @Test
  fun refuses_an_empty_recipient_set() {
    val fake = FakePublisher()
    assertThrows(IllegalArgumentException::class.java) {
      RelayNotifier(SecretKeyHex.ofHexString(leadSecret), fake)
        .notifyGateOpen(notice, emptySet(), timeout)
    }
    assertEquals("nothing is published when refused", 0, fake.published.size)
  }

  @Test
  fun rejects_a_malformed_lead_key() {
    // 0x00…00 is the zero scalar — not a valid secp256k1 secret key. Left unvalidated it would abort
    // the fan-out's crypto phase (Nip44 ECDH / signEvent) and notify no custodian, so RelayNotifier
    // must refuse it at construction, the config boundary, not on the first notify. ofHexString accepts
    // it (64 hex characters is structurally valid); the scalar rejection is RelayNotifier's init.
    assertThrows(IllegalArgumentException::class.java) {
      RelayNotifier(SecretKeyHex.ofHexString("00".repeat(32)), FakePublisher())
    }
  }

  @Test
  fun close_clears_the_lead_key_so_a_later_notify_fails_closed() {
    // close() zeroes the held SecretKeyHex; a later notify decodes the zeroed hex inside useKeyBytes and
    // throws in the crypto phase, so the notifier fails closed — it never signs or publishes a zeroed
    // key. The recipient set is non-empty, so the empty-set guard passes first and the throw is the
    // zeroed-key decode's, pinned on the message (not just the type). SecretKeyHexTest proves clear()
    // zeroes the backing array directly; this pins the notifier's observable behavior after close().
    val fake = FakePublisher()
    val notifier = RelayNotifier(SecretKeyHex.ofHexString(leadSecret), fake)
    notifier.close()
    val thrown =
      assertThrows(IllegalArgumentException::class.java) {
        notifier.notifyGateOpen(notice, setOf(key(recipASecret)), timeout)
      }
    assertTrue(
      "a notify after close must fail on the zeroed-key decode, not some other check",
      thrown.message!!.contains("64 hex"),
    )
    assertEquals("a closed notifier publishes nothing", 0, fake.published.size)
  }

  @Test
  fun maps_each_recipient_to_its_own_outcome() {
    val a = key(recipASecret)
    val b = key(recipBSecret)
    val c = key(recipCSecret)
    val recipients = linkedSetOf(a, b, c) // insertion-ordered; publishes follow this order
    val fake = FakePublisher()
    fake.enqueue(
      PublishResult.Accepted,
      PublishResult.Rejected("duplicate"),
      PublishResult.Failed("socket closed"),
    )

    val report =
      RelayNotifier(SecretKeyHex.ofHexString(leadSecret), fake)
        .notifyGateOpen(notice, recipients, timeout)

    assertEquals(NotifyOutcome.Delivered, report.outcomes[a])
    assertEquals(NotifyOutcome.Rejected("duplicate"), report.outcomes[b])
    assertEquals(NotifyOutcome.Failed("socket closed"), report.outcomes[c])
  }

  @Test
  fun surfaces_an_oversize_notice_as_not_encodable_for_every_recipient_without_publishing() {
    val recipients = linkedSetOf(key(recipASecret), key(recipBSecret), key(recipCSecret))
    val huge = GateOpenNotice("gate-1", "digest", "nonce", "x".repeat(70_000))
    val fake = FakePublisher()

    val report =
      RelayNotifier(SecretKeyHex.ofHexString(leadSecret), fake)
        .notifyGateOpen(huge, recipients, timeout)

    // The size test is on the notice plaintext, identical for every recipient, so oversize is a
    // notice-global outcome: all recipients NotEncodable, or none. A single recipient could not show
    // this — the property is precisely that the outcome does not vary across the set.
    assertEquals("every recipient has an outcome", 3, report.outcomes.size)
    for ((who, outcome) in report.outcomes) {
      assertTrue("$who is NotEncodable", outcome is NotifyOutcome.NotEncodable)
      assertEquals(65535, (outcome as NotifyOutcome.NotEncodable).ceilingBytes)
    }
    assertEquals("an unencodable notice is never published for anyone", 0, fake.published.size)
  }

  @Test
  fun computes_all_signatures_before_the_first_publish() {
    val a = key(recipASecret)
    val b = key(recipBSecret)
    val c = key(recipCSecret)
    val log = mutableListOf<String>()
    val timeouts = mutableListOf<Duration>()
    val fake =
      EventPublisher { _, publishTimeout ->
        log.add("publish")
        timeouts.add(publishTimeout)
        PublishResult.Accepted
      }
    var n = 0
    val auxRand = {
      log.add("aux")
      "%064x".format(java.math.BigInteger.valueOf((++n).toLong()))
    }

    RelayNotifier(SecretKeyHex.ofHexString(leadSecret), fake, auxRandHex = auxRand)
      .notifyGateOpen(notice, linkedSetOf(a, b, c), timeout)

    // All crypto (aux draws) precede all I/O (publishes): the timeout never charges signing (#45).
    assertEquals(listOf("aux", "aux", "aux", "publish", "publish", "publish"), log)
    assertTrue("the timeout is passed straight to each publish", timeouts.all { it == timeout })
  }
}
