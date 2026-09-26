package com.geekinasuit.agency.nostr

import java.time.Duration
import java.time.Instant
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
 * before any publish (the #45 phase separation), the gift-wrap timestamps (one notice time for the
 * whole fan-out, read again on each call, by default too, each seal backdated from its call's time
 * by its own draw, within two days by default), and a closed notifier fails its next notify closed.
 */
class RelayNotifierTest {
  private val leadSecret = "0000000000000000000000000000000000000000000000000000000000000001"
  private val recipASecret = "0000000000000000000000000000000000000000000000000000000000000002"
  private val recipBSecret = "0000000000000000000000000000000000000000000000000000000000000003"
  private val recipCSecret = "0000000000000000000000000000000000000000000000000000000000000004"
  private val timeout = Duration.ofSeconds(3)
  private val notice = GateOpenNotice("gate-1", "digest", "nonce", "artifact")
  private val noticeTime = 1_700_000_000L

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
    // 50,000 bytes: within what one NIP-44 layer carries (65,535), over what a gift wrap carries.
    val huge = GateOpenNotice("gate-1", "digest", "nonce", "x".repeat(50_000))
    val fake = FakePublisher()

    val report =
      RelayNotifier(SecretKeyHex.ofHexString(leadSecret), fake)
        .notifyGateOpen(huge, recipients, timeout)

    // The size test is on the serialized rumor, which differs between recipients only in the key its
    // `p` tag carries — always 64 hex characters — so oversize is a notice-global outcome: all
    // recipients NotEncodable, or none. A single recipient could not show this — the property is
    // precisely that the outcome does not vary across the set.
    assertEquals("every recipient has an outcome", 3, report.outcomes.size)
    for ((who, outcome) in report.outcomes) {
      assertTrue("$who is NotEncodable", outcome is NotifyOutcome.NotEncodable)
      assertEquals(Nip59.RUMOR_CEILING_BYTES, (outcome as NotifyOutcome.NotEncodable).ceilingBytes)
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
    val backdate = {
      log.add("backdate")
      60L
    }

    RelayNotifier(
        SecretKeyHex.ofHexString(leadSecret),
        fake,
        auxRandHex = auxRand,
        sealBackdateSeconds = backdate,
      )
      .notifyGateOpen(notice, linkedSetOf(a, b, c), timeout)

    // Each recipient draws two aux values (the seal's and the wrap's signatures) and one seal
    // backdate, and every draw precedes all I/O: the timeout never charges signing (#45).
    assertEquals("two aux draws per recipient", 6, log.count { it == "aux" })
    assertEquals("one seal backdate per recipient", 3, log.count { it == "backdate" })
    assertEquals("one publish per recipient", 3, log.count { it == "publish" })
    assertTrue(
      "every draw precedes the first publish: $log",
      log.indexOfLast { it != "publish" } < log.indexOfFirst { it == "publish" },
    )
    assertTrue("the timeout is passed straight to each publish", timeouts.all { it == timeout })
  }

  @Test
  fun dates_every_rumor_and_wrap_at_one_notice_time_and_backdates_each_seal_by_its_own_draw() {
    val fake = FakePublisher()
    var clockReads = 0
    val clock = {
      clockReads++
      noticeTime
    }
    val backdates = ArrayDeque(listOf(10L, 20L))

    RelayNotifier(
        SecretKeyHex.ofHexString(leadSecret),
        fake,
        now = clock,
        sealBackdateSeconds = { backdates.removeFirst() },
      )
      .notifyGateOpen(notice, linkedSetOf(key(recipASecret), key(recipBSecret)), timeout)

    assertEquals("one notice time for the whole fan-out", 1, clockReads)
    assertEquals(2, fake.published.size)
    val (wrapA, wrapB) = fake.published
    for ((wrap, secret) in listOf(wrapA to recipASecret, wrapB to recipBSecret)) {
      assertEquals("the wrap carries the notice time", noticeTime, wrap.createdAt)
      val rumor = Nip59.unwrap(hexToBytes(secret), wrap)
      assertEquals("the rumor carries the notice time", noticeTime, rumor!!.createdAt)
    }
    val sealA = sealOf(wrapA, recipASecret)
    val sealB = sealOf(wrapB, recipBSecret)
    assertEquals("A's seal is backdated by the first draw", noticeTime - 10L, sealA.createdAt)
    assertEquals("B's seal is backdated by the second draw", noticeTime - 20L, sealB.createdAt)
  }

  // A retried announce is a new call, so it carries the time of that call. A relay that refuses an
  // event whose created_at is older than some bound would refuse a retry dated at the first attempt
  // once the retry came more than that bound after it. The seal is backdated from its own call's
  // time too: backdated from an earlier call's, it would land further back than its draw.
  @Test
  fun dates_each_call_at_its_own_reading_of_the_clock() {
    val fake = FakePublisher()
    val times = listOf(noticeTime, noticeTime + 90L)
    val reads = ArrayDeque(times)
    val backdate = 10L
    val notifier =
      RelayNotifier(
        SecretKeyHex.ofHexString(leadSecret),
        fake,
        now = { reads.removeFirst() },
        sealBackdateSeconds = { backdate },
      )

    notifier.notifyGateOpen(notice, setOf(key(recipASecret)), timeout)
    notifier.notifyGateOpen(notice, setOf(key(recipASecret)), timeout)

    assertEquals("one publish per call", 2, fake.published.size)
    for ((wrap, time) in fake.published.zip(times)) {
      assertEquals("the wrap carries its call's time", time, wrap.createdAt)
      val rumor = Nip59.unwrap(hexToBytes(recipASecret), wrap)
      assertEquals("the rumor carries its call's time", time, rumor!!.createdAt)
      assertEquals(
        "the seal is backdated from its call's time",
        time - backdate,
        sealOf(wrap, recipASecret).createdAt,
      )
    }
  }

  // The default clock is read on each call. Read once, when the notifier is built or on its first
  // call, it would date every later notice at that time, and a relay that refuses events whose
  // created_at is older than some bound would refuse every notice once the process had run longer
  // than that. Each reading here is taken after the event before it, so a clock read at that event
  // is never later than the reading, whichever side of a second boundary the two fall on.
  @Test
  fun the_default_clock_is_read_on_each_call() {
    val fake = FakePublisher()
    val notifier = RelayNotifier(SecretKeyHex.ofHexString(leadSecret), fake)
    val afterBuild = Instant.now().epochSecond
    Thread.sleep(1_100)
    notifier.notifyGateOpen(notice, setOf(key(recipASecret)), timeout)
    val afterFirstCall = Instant.now().epochSecond
    Thread.sleep(1_100)
    notifier.notifyGateOpen(notice, setOf(key(recipASecret)), timeout)

    assertEquals("one publish per call", 2, fake.published.size)
    val (first, second) = fake.published
    assertTrue(
      "the first notice is dated after the notifier was built: ${first.createdAt} vs $afterBuild",
      first.createdAt > afterBuild,
    )
    assertTrue(
      "the second notice is dated after the first call: ${second.createdAt} vs $afterFirstCall",
      second.createdAt > afterFirstCall,
    )
  }

  @Test
  fun backdates_each_seal_by_default_to_within_two_days_in_the_past() {
    val fake = FakePublisher()
    val secrets = listOf(recipASecret, recipBSecret, recipCSecret)

    val recipients = linkedSetOf(key(recipASecret), key(recipBSecret), key(recipCSecret))
    RelayNotifier(SecretKeyHex.ofHexString(leadSecret), fake, now = { noticeTime })
      .notifyGateOpen(notice, recipients, timeout)

    assertEquals(3, fake.published.size)
    val backdates =
      fake.published.zip(secrets).map { (wrap, secret) ->
        noticeTime - sealOf(wrap, secret).createdAt
      }
    val twoDays = 2L * 24 * 60 * 60
    assertTrue(
      "every backdate lies in [0, two days): $backdates",
      backdates.all { it in 0L until twoDays },
    )
    // Three uniform draws over 172,800 seconds are all zero with probability about 2^-52.
    assertTrue("the default does backdate: $backdates", backdates.any { it > 0L })
  }

  /** The seal inside [wrap], opened by hand with [recipientSecret]: [Nip59.unwrap] returns only the
   * rumor. */
  private fun sealOf(wrap: NostrEvent, recipientSecret: String): NostrEvent {
    val conversationKey = Nip44.conversationKey(hexToBytes(recipientSecret), hexToBytes(wrap.pubkey))
    return parseEvent(Nip44.decrypt(wrap.content, conversationKey)!!)!!
  }

  /** Local hex decoder — the module's `Hex` is internal, and a test target links `:nostr` as a dep,
   * not `associates`, so it cannot reach it. */
  private fun hexToBytes(s: String): ByteArray =
    ByteArray(s.length / 2) {
      ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte()
    }
}
