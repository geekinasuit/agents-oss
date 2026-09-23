package com.geekinasuit.agency.nostr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The gate-open notice codec (A4-6). These cells wrap and open with the real BIP-340, NIP-44, and
 * NIP-59 primitives (native runtime), and pin the slice's cross-component and security-bearing
 * choices: the rumor a recipient reads (its kind, author, content, and the exact tags a reader
 * parses), the wrap a relay stores (a regular kind, a single-use signer, one `p` tag naming the
 * recipient), the timestamps (the notice time on the rumor and the wrap, the caller's backdate on the
 * seal), an oversize notice as a typed refusal at the gift-wrap ceiling, and one custodian's notice
 * staying closed to another.
 */
class GateOpenNoticeTest {
  private val leadSecret = "0000000000000000000000000000000000000000000000000000000000000001"
  private val recipASecret = "0000000000000000000000000000000000000000000000000000000000000002"
  private val recipBSecret = "0000000000000000000000000000000000000000000000000000000000000003"
  private val sealAux = "0101010101010101010101010101010101010101010101010101010101010101"
  private val wrapAux = "0202020202020202020202020202020202020202020202020202020202020202"
  private val noticeTime = 1_700_000_000L
  private val sealTime = noticeTime - 3_600L

  private val leadPub = Bip340.xonlyPubkeyHex(leadSecret)
  private val recipA = RecipientKey.of(Bip340.xonlyPubkeyHex(recipASecret))

  private fun encode(notice: GateOpenNotice, recipient: RecipientKey = recipA): NoticeEncoding =
    encodeGateOpenNotice(
      leadKeyBytes = hexToBytes(leadSecret),
      recipient = recipient,
      notice = notice,
      createdAt = noticeTime,
      sealCreatedAt = sealTime,
      sealAuxRandHex = sealAux,
      wrapAuxRandHex = wrapAux,
    )

  private fun wrapped(notice: GateOpenNotice, recipient: RecipientKey = recipA): NostrEvent {
    val encoding = encode(notice, recipient)
    assertTrue("expected an Encoded result, was $encoding", encoding is NoticeEncoding.Encoded)
    return (encoding as NoticeEncoding.Encoded).event
  }

  @Test
  fun the_recipient_opens_a_lead_authored_kind_14_rumor_carrying_the_artifact() {
    val notice = GateOpenNotice("gate-1", "digest-abc", "nonce-xyz", "approve deploy of build 42")
    val rumor = Nip59.unwrap(hexToBytes(recipASecret), wrapped(notice))

    assertNotNull("the addressed recipient opens the wrap", rumor)
    assertEquals("NIP-17's chat-message kind", 14, GATE_OPEN_NOTICE_RUMOR_KIND)
    assertEquals(GATE_OPEN_NOTICE_RUMOR_KIND, rumor!!.kind)
    assertEquals("authored by the lead", leadPub, rumor.pubkey)
    assertEquals("dated at the notice time", noticeTime, rumor.createdAt)
    assertEquals("the content is the artifact, verbatim", "approve deploy of build 42", rumor.content)
  }

  @Test
  fun the_rumor_carries_exactly_the_tags_a_reader_parses() {
    val notice = GateOpenNotice("gate-1", "digest-abc", "nonce-xyz", "artifact")
    val rumor = Nip59.unwrap(hexToBytes(recipASecret), wrapped(notice))!!

    assertEquals(
      listOf(
        listOf("p", recipA.hex),
        listOf("subject", "Approval requested: gate gate-1"),
        listOf("agency-gate-id", "gate-1"),
        listOf("agency-payload-digest", "digest-abc"),
        listOf("agency-nonce", "nonce-xyz"),
      ),
      rumor.tags,
    )
  }

  @Test
  fun the_relay_sees_a_regular_kind_gift_wrap_naming_only_its_recipient() {
    val wrap = wrapped(GateOpenNotice("gate-1", "d", "n", "a"))

    assertEquals(Nip59.GIFT_WRAP_KIND, wrap.kind)
    assertTrue("regular (relay-stored) kinds are 1000..9999", wrap.kind in 1000..9999)
    assertEquals("one tag, naming the recipient", listOf(listOf("p", recipA.hex)), wrap.tags)
    assertNotEquals("signed by a single-use key, not the lead", leadPub, wrap.pubkey)
    assertTrue("the wrap's signature verifies", wrap.verify())
  }

  @Test
  fun the_wrap_carries_the_notice_time_and_only_the_seal_is_backdated() {
    val wrap = wrapped(GateOpenNotice("gate-1", "d", "n", "a"))
    assertEquals("the wrap is dated at the notice time", noticeTime, wrap.createdAt)

    val seal = openWrapLayer(wrap, recipASecret)
    assertEquals(Nip59.SEAL_KIND, seal.kind)
    assertEquals("the seal is signed by the lead", leadPub, seal.pubkey)
    assertEquals("the seal carries the caller's backdated time", sealTime, seal.createdAt)
  }

  @Test
  fun refuses_an_oversize_notice_at_the_gift_wrap_ceiling_as_a_typed_result() {
    // 50,000 bytes: within what one NIP-44 layer carries (65,535), over what a gift wrap carries.
    val encoding = encode(GateOpenNotice("gate-1", "digest", "nonce", "x".repeat(50_000)))

    assertTrue("an oversize notice is a typed refusal", encoding is NoticeEncoding.TooLarge)
    val tooLarge = encoding as NoticeEncoding.TooLarge
    assertEquals("names the gift wrap's ceiling", Nip59.RUMOR_CEILING_BYTES, tooLarge.ceilingBytes)
    assertTrue("reports the whole rumor's size", tooLarge.plaintextBytes > 50_000)
  }

  @Test
  fun a_notice_for_one_custodian_does_not_open_for_another() {
    val wrap = wrapped(GateOpenNotice("gate-1", "digest-abc", "nonce-xyz", "custodian-only artifact"))

    assertNull("a wrap for A does not open for B", Nip59.unwrap(hexToBytes(recipBSecret), wrap))
    assertNotNull("the addressed custodian opens it", Nip59.unwrap(hexToBytes(recipASecret), wrap))
  }

  @Test
  fun refuses_a_notice_field_holding_an_unpaired_surrogate_at_construction() {
    // Every field rides in the rumor, whose id needs each string's UTF-8 encoding, and a string
    // holding an unpaired surrogate has none. Refusing it here keeps notifyGateOpen from meeting a
    // notice it cannot encode.
    val lone = "a" + Char(0xD800) + "b"
    assertThrows("gateId", IllegalArgumentException::class.java) { GateOpenNotice(lone, "d", "n", "a") }
    assertThrows("payloadDigest", IllegalArgumentException::class.java) { GateOpenNotice("g", lone, "n", "a") }
    assertThrows("nonce", IllegalArgumentException::class.java) { GateOpenNotice("g", "d", lone, "a") }
    assertThrows("artifact", IllegalArgumentException::class.java) { GateOpenNotice("g", "d", "n", lone) }
  }

  @Test
  fun rejects_an_off_curve_recipient_key() {
    // 64 valid hex characters, but 0xff…ff is beyond the secp256k1 field prime — not a curve point.
    // RecipientKey.of must refuse it here, at the config boundary, rather than let it abort the
    // fan-out's crypto phase downstream and sink delivery to every custodian.
    assertThrows(IllegalArgumentException::class.java) { RecipientKey.of("ff".repeat(32)) }
  }

  @Test
  fun refuses_a_notice_whose_artifact_has_nothing_to_read_at_construction() {
    // The artifact is what the operator reads instead of a digest, so an artifact with nothing to
    // read is refused whether or not it is blank.
    val unreadable =
      mapOf(
        "blank" to " \n",
        "a zero-width space and a newline" to codePoints(0x200B, 0x0A),
        "the Hangul filler" to codePoints(0x3164),
      )
    for ((label, artifact) in unreadable) {
      assertThrows(label, IllegalArgumentException::class.java) { GateOpenNotice("g", "d", "n", artifact) }
    }
  }

  /** The string of [codePoints], so that no invisible character is written into this file. */
  private fun codePoints(vararg codePoints: Int): String =
    buildString { codePoints.forEach { appendCodePoint(it) } }

  /** Opens the wrap's outer layer by hand, to read the seal inside: [Nip59.unwrap] returns only the
   * rumor. */
  private fun openWrapLayer(wrap: NostrEvent, recipientSecret: String): NostrEvent {
    val conversationKey = Nip44.conversationKey(hexToBytes(recipientSecret), hexToBytes(wrap.pubkey))
    val sealJson = Nip44.decrypt(wrap.content, conversationKey)
    assertNotNull("the recipient decrypts the wrap layer", sealJson)
    return parseEvent(sealJson!!)!!
  }

  /** Local hex decoder — the module's `Hex` is internal, and a test target links `:nostr` as a dep,
   * not `associates`, so it cannot reach it. */
  private fun hexToBytes(s: String): ByteArray =
    ByteArray(s.length / 2) {
      ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte()
    }
}
