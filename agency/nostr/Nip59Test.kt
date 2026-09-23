package com.geekinasuit.agency.nostr

import com.geekinasuit.agency.shared.json.onSmallStack
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The NIP-59 gift-wrap codec. These cells run the real BIP-340 / NIP-44 primitives (native runtime)
 * and pin: interop with the spec's own worked example (produced by another implementation), the
 * three-layer structure (rumor inside a kind-13 seal inside a kind-1059 wrap), a fresh ephemeral key
 * per wrap, TOTAL unwrap over hostile events — the impersonation check NIP-17 mandates and the
 * nesting bound on decrypted plaintext included — and the double-wrap size ceiling, measured by
 * execution on both sides of the boundary.
 */
class Nip59Test {
  private val senderSecret = "0000000000000000000000000000000000000000000000000000000000000001"
  private val recipASecret = "0000000000000000000000000000000000000000000000000000000000000002"
  private val recipBSecret = "0000000000000000000000000000000000000000000000000000000000000003"
  private val otherSecret = "0000000000000000000000000000000000000000000000000000000000000004"
  // The wrap key of the test's OWN hand-built wraps — the codec draws a fresh one per wrap.
  private val handWrapSecret = "0000000000000000000000000000000000000000000000000000000000000005"
  private val aux = "0101010101010101010101010101010101010101010101010101010101010101"

  private val senderPub = Bip340.xonlyPubkeyHex(senderSecret)
  private val recipAPub = Bip340.xonlyPubkeyHex(recipASecret)
  private val recipA = RecipientKey.of(recipAPub)

  private fun rumor(
    content: String = "a gate opened",
    pubkey: String = senderPub,
    tags: List<List<String>> = emptyList(),
  ) = Rumor(pubkey = pubkey, createdAt = 1_700_000_000L, kind = 14, tags = tags, content = content)

  private fun wrap(rumor: Rumor, recipient: RecipientKey = recipA): GiftWrapEncoding =
    Nip59.wrap(
      senderKey = Hex.decode(senderSecret),
      recipient = recipient,
      rumor = rumor,
      sealCreatedAt = 1_700_000_100L,
      wrapCreatedAt = 1_700_000_200L,
      sealAuxRandHex = aux,
      wrapAuxRandHex = aux,
    )

  private fun wrapped(rumor: Rumor): NostrEvent {
    val encoding = wrap(rumor)
    assertTrue("expected a Wrapped result, was $encoding", encoding is GiftWrapEncoding.Wrapped)
    return (encoding as GiftWrapEncoding.Wrapped).event
  }

  private fun unwrapForA(wrap: NostrEvent): Rumor? = Nip59.unwrap(Hex.decode(recipASecret), wrap)

  @Test
  fun unwraps_the_spec_example_produced_by_another_implementation() {
    // Transcription guards first: if one of these fails, suspect the copied vector, not the codec.
    assertEquals(SPEC_AUTHOR_PUB, Bip340.xonlyPubkeyHex(SPEC_AUTHOR_SECRET))
    assertEquals(SPEC_RECIPIENT_PUB, Bip340.xonlyPubkeyHex(SPEC_RECIPIENT_SECRET))
    assertEquals(SPEC_WRAP.pubkey, Bip340.xonlyPubkeyHex(SPEC_EPHEMERAL_SECRET))
    assertTrue("the spec's seal must verify as transcribed", SPEC_SEAL.verify())
    assertTrue("the spec's wrap must verify as transcribed", SPEC_WRAP.verify())

    // The wrap layer decrypts to exactly the spec's seal...
    val sealJson = Nip44.decrypt(SPEC_WRAP.content, conv(SPEC_RECIPIENT_SECRET, SPEC_WRAP.pubkey))
    assertEquals(SPEC_SEAL, sealJson?.let { parseEvent(it) })

    // ...and the whole unwrap yields the spec's rumor, id included.
    val rumor = Nip59.unwrap(Hex.decode(SPEC_RECIPIENT_SECRET), SPEC_WRAP)
    assertEquals(SPEC_RUMOR, rumor)
    assertEquals(SPEC_RUMOR_ID, rumor!!.id)
  }

  @Test
  fun round_trips_a_rumor_to_its_recipient() {
    val original =
      rumor(
        content = "approve deploy of build 42",
        tags = listOf(listOf("subject", "gate-1"), listOf("t", "agency")),
      )
    assertEquals(original, unwrapForA(wrapped(original)))
  }

  @Test
  fun the_wrap_is_kind_1059_and_signed_by_a_key_that_is_not_the_senders() {
    val wrap = wrapped(rumor())
    assertEquals(1059, Nip59.GIFT_WRAP_KIND)
    assertEquals(Nip59.GIFT_WRAP_KIND, wrap.kind)
    assertEquals("the caller's timestamp, not a clock", 1_700_000_200L, wrap.createdAt)
    assertTrue("the wrap verifies under its own key", wrap.verify())
    assertNotEquals("the sender never signs the outer layer", senderPub, wrap.pubkey)
  }

  @Test
  fun the_wrap_names_its_recipient_in_one_p_tag_and_nothing_else() {
    assertEquals(listOf(listOf("p", recipAPub)), wrapped(rumor()).tags)
  }

  @Test
  fun the_seal_inside_is_kind_13_untagged_and_signed_by_the_sender() {
    val wrap = wrapped(rumor())
    val seal = parseEvent(Nip44.decrypt(wrap.content, conv(recipASecret, wrap.pubkey))!!)!!
    assertEquals(13, Nip59.SEAL_KIND)
    assertEquals(Nip59.SEAL_KIND, seal.kind)
    assertTrue("NIP-59: a seal's tags MUST be empty", seal.tags.isEmpty())
    assertEquals(senderPub, seal.pubkey)
    assertEquals("the caller's timestamp, not a clock", 1_700_000_100L, seal.createdAt)
    assertTrue(seal.verify())
  }

  @Test
  fun draws_a_fresh_ephemeral_key_for_every_wrap() {
    val r = rumor()
    val wrapKeys = (1..5).map { wrapped(r).pubkey }.toSet()
    assertEquals("a reused wrap key would link wraps to one another", 5, wrapKeys.size)
  }

  @Test
  fun a_wrap_for_one_recipient_does_not_unwrap_for_another() {
    val wrap = wrapped(rumor())
    assertNull(Nip59.unwrap(Hex.decode(recipBSecret), wrap))
    assertNotNull(unwrapForA(wrap))
  }

  @Test
  fun the_hand_built_layers_unwrap_when_honest() {
    // Control for the hostile cells below: the test's own seal and wrap builders produce a wrap the
    // codec accepts, so each null below is the codec refusing the one thing that cell changed.
    val honest = rumor()
    assertEquals(honest, unwrapForA(handWrap(handSeal(honest.serialize()).serialize())))
  }

  @Test
  fun refuses_a_seal_signed_by_someone_other_than_the_rumors_author() {
    // NIP-17's impersonation check: the seal's signature is the only authentication of the sender,
    // so a rumor that names a different author than the seal's signer is refused.
    val claimsOther = rumor(pubkey = Bip340.xonlyPubkeyHex(otherSecret))
    val seal = handSeal(claimsOther.serialize(), signerSecret = senderSecret)
    assertNull(unwrapForA(handWrap(seal.serialize())))
  }

  @Test
  fun refuses_a_seal_whose_pubkey_is_not_spelled_canonically() {
    // A signer can spell its own pubkey in uppercase and sign the id computed over that spelling:
    // the signature verifies, because both spellings decode to the same key bytes. unwrap returns a
    // rumor only under NIP-01's lowercase spelling, so the authenticated pubkey string-equals the
    // canonical key. The lowercase control is built the same way and unwraps.
    fun sealSpelledAs(pubkey: String): NostrEvent {
      val content = Nip44.encrypt(rumor(pubkey = pubkey).serialize(), conv(senderSecret, recipAPub))
      val id = Nip01.eventId(pubkey, 1_700_000_100L, 13, emptyList(), content)
      return NostrEvent(
        id = id,
        pubkey = pubkey,
        createdAt = 1_700_000_100L,
        kind = 13,
        tags = emptyList(),
        content = content,
        sig = Bip340.signHex(id, senderSecret, aux),
      )
    }
    assertNotNull(unwrapForA(handWrap(sealSpelledAs(senderPub).serialize())))
    assertNull(unwrapForA(handWrap(sealSpelledAs(senderPub.uppercase()).serialize())))
  }

  @Test
  fun unwrap_is_total_over_a_malformed_or_tampered_wrap() {
    val good = handWrap(handSeal(rumor().serialize()).serialize())
    val cases =
      mapOf(
        "not the gift-wrap kind" to handWrap(handSeal(rumor().serialize()).serialize(), kind = 1),
        "a forged signature" to good.copy(sig = flipLastHexDigit(good.sig)),
        "content changed after signing" to good.copy(content = handWrap("x").content),
        "an off-curve pubkey" to good.copy(pubkey = "ff".repeat(32)),
        "a non-hex pubkey" to good.copy(pubkey = "zz".repeat(32)),
        "content that is not a NIP-44 payload" to
          signEvent(handWrapSecret, 1L, 1059, listOf(listOf("p", recipAPub)), "not a payload", aux),
      )
    for ((name, wrap) in cases) assertNull(name, unwrapForA(wrap))
  }

  @Test
  fun unwrap_is_total_over_a_malformed_or_tampered_seal() {
    val rumorJson = rumor().serialize()
    val good = handSeal(rumorJson)
    val cases =
      mapOf(
        "seal plaintext that is not JSON" to "not json",
        "seal plaintext that is a JSON array" to "[]",
        "a seal of the wrong kind" to handSeal(rumorJson, kind = 1).serialize(),
        "a seal carrying tags" to handSeal(rumorJson, tags = listOf(listOf("p", recipAPub))).serialize(),
        "a seal with a forged signature" to good.copy(sig = flipLastHexDigit(good.sig)).serialize(),
        "a seal whose pubkey is off-curve" to good.copy(pubkey = "ff".repeat(32)).serialize(),
        "a seal whose content is not a NIP-44 payload" to
          signEvent(senderSecret, 1L, 13, emptyList(), "not a payload", aux).serialize(),
      )
    for ((name, sealPlaintext) in cases) assertNull(name, unwrapForA(handWrap(sealPlaintext)))
  }

  @Test
  fun unwrap_is_total_over_a_malformed_rumor() {
    val honestRumor = rumor()
    val honest = honestRumor.serialize()
    val cases =
      mapOf(
        "rumor plaintext that is not JSON" to "not json",
        "a rumor missing its content" to honest.replace(",\"content\":\"a gate opened\"", ""),
        "a rumor whose claimed id is not its own" to honest.replace(honestRumor.id, "00".repeat(32)),
        "a rumor with a kind outside 0..65535" to honest.replace("\"kind\":14", "\"kind\":70000"),
        "a rumor with a quoted created_at" to honest.replace("1700000000", "\"1700000000\""),
      )
    for ((name, rumorPlaintext) in cases) {
      assertNotEquals("$name: the edit must change the honest rumor", honest, rumorPlaintext)
      assertNull(name, unwrapForA(handWrap(handSeal(rumorPlaintext).serialize())))
    }
  }

  @Test
  fun refuses_a_rumor_whose_question_mark_is_spelled_as_a_lone_surrogate() {
    // A sender can spell a '?' in its rumor as the JSON escape for U+D800, which parses to a lone
    // surrogate: a different string. A lenient UTF-8 encoder hashes that surrogate as '?', so the
    // rumor's claimed id, computed over the '?', would still match. The honest spelling unwraps.
    val honest = rumor(content = "a?b").serialize()
    val respelled = honest.replace("a?b", "a" + "\\" + "ud800" + "b")
    assertNotEquals(honest, respelled)
    assertNotNull(unwrapForA(handWrap(handSeal(honest).serialize())))
    val unwrapped = unwrapForA(handWrap(handSeal(respelled).serialize()))
    assertNull("unwrapped, with content chars ${unwrapped?.content?.map { it.code }}", unwrapped)
  }

  @Test
  fun refuses_a_deeply_nested_seal_plaintext_before_the_parser_can_overflow() {
    // Anyone can address a wrap to the recipient, so the decrypted plaintext is hostile JSON that
    // no relay-frame bound ever saw (it crossed the transport as base64). This runs on a small
    // stack, where parsing this nesting would overflow it, so a null here means unwrap refused the
    // plaintext before parsing it.
    val wrap = handWrap("[".repeat(60_000))
    assertNull(onSmallStack { unwrapForA(wrap) })
  }

  @Test
  fun refuses_a_deeply_nested_rumor_plaintext_before_the_parser_can_overflow() {
    val wrap = handWrap(handSeal("[".repeat(40_000)).serialize())
    assertNull(onSmallStack { unwrapForA(wrap) })
  }

  @Test
  fun refuses_a_seal_plaintext_that_continues_past_its_closers_before_the_parser_can_overflow() {
    // kotlinx keeps reading an array after its `]` when a value follows, so this plaintext — a full
    // NIP-44 payload of `[1]` — nests one level per `[1]` in the parser although its brackets never
    // nest past one. Parsing it would overflow this small stack.
    val wrap = handWrap("[1]".repeat(21_845))
    assertNull(onSmallStack { unwrapForA(wrap) })
  }

  @Test
  fun refuses_a_rumor_plaintext_that_continues_past_its_closers_before_the_parser_can_overflow() {
    val wrap = handWrap(handSeal("[1]".repeat(13_000)).serialize())
    assertNull(onSmallStack { unwrapForA(wrap) })
  }

  @Test
  fun refuses_plaintext_nested_deeper_than_any_event_field() {
    // An event object nests at most three deep: the object, its tags array, one tag. A seal that
    // verifies but carries a deeper extra field is refused, although parseEvent alone would ignore
    // the unknown key; one at depth three still unwraps, so the refusal is the depth, not the key.
    val seal = handSeal(rumor().serialize()).serialize()
    assertNull(unwrapForA(handWrap(seal.dropLast(1) + ",\"x\":[[[0]]]}")))
    assertNotNull(unwrapForA(handWrap(seal.dropLast(1) + ",\"x\":[[0]]}")))
  }

  @Test
  fun brackets_quotes_and_backslashes_inside_a_string_are_content_not_nesting() {
    // The depth bound counts only structural brackets. Content full of them nests no deeper than
    // any other rumor, so it must unwrap; a plain bracket count would refuse it.
    val r = rumor(content = "[[[[ \" \\ ]]]] {{{{")
    assertEquals(r, unwrapForA(wrapped(r)))
  }

  @Test
  fun an_escaped_backslash_does_not_hide_the_nesting_after_it() {
    // `"\\"` is a complete string: the escape consumes the second backslash, so the next quote
    // closes the string. A scan that read that quote as escaped would stay in string mode and miss
    // the nesting the parser then recurses into, overflowing this small stack instead of refusing.
    val wrap = handWrap("[\"\\\\\"," + "[".repeat(60_000))
    assertNull(onSmallStack { unwrapForA(wrap) })
  }

  @Test
  fun wraps_a_rumor_exactly_at_the_ceiling_and_refuses_one_byte_more() {
    val atCeiling = rumorOfJsonBytes(Nip59.RUMOR_CEILING_BYTES)
    assertEquals(atCeiling, unwrapForA(wrapped(atCeiling)))

    val over = rumorOfJsonBytes(Nip59.RUMOR_CEILING_BYTES + 1)
    assertEquals(
      GiftWrapEncoding.TooLarge(
        rumorBytes = Nip59.RUMOR_CEILING_BYTES + 1,
        ceilingBytes = Nip59.RUMOR_CEILING_BYTES,
      ),
      wrap(over),
    )
  }

  @Test
  fun the_ceiling_is_the_largest_rumor_whose_seal_fits_a_nip44_plaintext() {
    // At the ceiling the seal JSON fits NIP-44's 65,535-byte plaintext limit even with the longest
    // created_at a Long can spell. One byte over, the rumor pads into the next NIP-44 bucket and its
    // seal JSON no longer fits even with the shortest — so the ceiling is tight, not merely safe.
    val nip44PlaintextLimit = 65_535
    val atCeiling = sealJsonBytes(rumorOfJsonBytes(Nip59.RUMOR_CEILING_BYTES), sealCreatedAt = Long.MIN_VALUE)
    val overCeiling = sealJsonBytes(rumorOfJsonBytes(Nip59.RUMOR_CEILING_BYTES + 1), sealCreatedAt = 0L)
    assertTrue("seal JSON at the ceiling is $atCeiling bytes", atCeiling <= nip44PlaintextLimit)
    assertTrue("seal JSON one byte over is $overCeiling bytes", overCeiling > nip44PlaintextLimit)
  }

  @Test
  fun measures_the_ceiling_in_utf8_bytes_not_characters() {
    // 'é' is one char but two UTF-8 bytes: this rumor is under the ceiling in chars, over it in bytes.
    val base = rumor(content = "")
    val overhead = base.serialize().toByteArray(Charsets.UTF_8).size
    val twoByteChars = base.copy(content = "é".repeat((Nip59.RUMOR_CEILING_BYTES - overhead) / 2 + 1))
    val json = twoByteChars.serialize()
    assertTrue("under the ceiling in chars", json.length <= Nip59.RUMOR_CEILING_BYTES)
    val bytes = json.toByteArray(Charsets.UTF_8).size
    assertEquals(GiftWrapEncoding.TooLarge(bytes, Nip59.RUMOR_CEILING_BYTES), wrap(twoByteChars))
  }

  @Test
  fun refuses_to_seal_a_rumor_the_sender_did_not_author() {
    val notSenders = rumor(pubkey = Bip340.xonlyPubkeyHex(otherSecret))
    assertThrows(IllegalArgumentException::class.java) { wrap(notSenders) }
  }

  @Test
  fun a_malformed_recipient_secret_key_is_a_local_bug_and_throws() {
    val wrap = wrapped(rumor())
    assertThrows(IllegalArgumentException::class.java) { Nip59.unwrap(ByteArray(31), wrap) }
  }

  @Test
  fun a_rumor_kind_outside_the_nip01_range_is_refused_at_construction() {
    assertThrows(IllegalArgumentException::class.java) { rumor().copy(kind = 65_536) }
  }

  @Test
  fun a_rumor_string_holding_an_unpaired_surrogate_is_refused_at_construction() {
    // Such a string has no UTF-8 encoding, so the rumor would have no NIP-01 id.
    val lone = "a" + Char(0xD800) + "b"
    assertThrows("content", IllegalArgumentException::class.java) { rumor(content = lone) }
    assertThrows("tag", IllegalArgumentException::class.java) { rumor(tags = listOf(listOf("e", lone))) }
    assertThrows("pubkey", IllegalArgumentException::class.java) { rumor(pubkey = lone) }
  }

  /** A kind-13 seal over [plaintext], signed by [signerSecret] and encrypted to recipient A — the
   * test's own builder, independent of [Nip59.wrap], so a cell can craft a hostile inner layer. */
  private fun handSeal(
    plaintext: String,
    signerSecret: String = senderSecret,
    kind: Int = 13,
    tags: List<List<String>> = emptyList(),
  ): NostrEvent =
    signEvent(signerSecret, 1_700_000_100L, kind, tags, Nip44.encrypt(plaintext, conv(signerSecret, recipAPub)), aux)

  /** A gift wrap around [plaintext] (normally a serialized seal), addressed to recipient A. */
  private fun handWrap(plaintext: String, kind: Int = 1059): NostrEvent =
    signEvent(
      handWrapSecret,
      1_700_000_200L,
      kind,
      listOf(listOf("p", recipAPub)),
      Nip44.encrypt(plaintext, conv(handWrapSecret, recipAPub)),
      aux,
    )

  private fun conv(secret: String, theirPub: String): ByteArray =
    Nip44.conversationKey(Hex.decode(secret), Hex.decode(theirPub))

  private fun flipLastHexDigit(hex: String): String = hex.dropLast(1) + if (hex.last() == '0') '1' else '0'

  /** A rumor whose serialized JSON is exactly [bytes] UTF-8 bytes (ASCII content, so bytes = chars). */
  private fun rumorOfJsonBytes(bytes: Int): Rumor {
    val empty = rumor(content = "")
    val overhead = empty.serialize().toByteArray(Charsets.UTF_8).size
    val sized = empty.copy(content = "x".repeat(bytes - overhead))
    assertEquals(bytes, sized.serialize().toByteArray(Charsets.UTF_8).size)
    return sized
  }

  /** The UTF-8 size of the seal JSON [rumor] produces — the plaintext the wrap layer must encrypt. */
  private fun sealJsonBytes(rumor: Rumor, sealCreatedAt: Long): Int =
    signEvent(senderSecret, sealCreatedAt, 13, emptyList(), Nip44.encrypt(rumor.serialize(), conv(senderSecret, recipAPub)), aux)
      .serialize()
      .toByteArray(Charsets.UTF_8)
      .size

  private companion object {
    // The worked example in NIP-59 itself (github.com/nostr-protocol/nips, 59.md, retrieved
    // 2026-09-22). Another implementation produced it, so unwrapping it is evidence that this
    // codec's layering matches the spec's — not only that the codec agrees with itself.
    const val SPEC_AUTHOR_SECRET = "0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273"
    const val SPEC_RECIPIENT_SECRET = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45"
    const val SPEC_EPHEMERAL_SECRET = "4f02eac59266002db5801adc5270700ca69d5b8f761d8732fab2fbf233c90cbd"
    const val SPEC_AUTHOR_PUB = "611df01bfcf85c26ae65453b772d8f1dfd25c264621c0277e1fc1518686faef9"
    const val SPEC_RECIPIENT_PUB = "166bf3765ebd1fc55decfe395beff2ea3b2a4e0a8946e7eb578512b555737c99"
    const val SPEC_RUMOR_ID = "9dd003c6d3b73b74a85a9ab099469ce251653a7af76f523671ab828acd2a0ef9"

    val SPEC_RUMOR =
      Rumor(
        pubkey = SPEC_AUTHOR_PUB,
        createdAt = 1691518405L,
        kind = 1,
        tags = emptyList(),
        content = "Are you going to the party tonight?",
      )

    val SPEC_SEAL =
      NostrEvent(
        id = "28a87d7c074d94a58e9e89bb3e9e4e813e2189f285d797b1c56069d36f59eaa7",
        pubkey = SPEC_AUTHOR_PUB,
        createdAt = 1703015180L,
        kind = 13,
        tags = emptyList(),
        content =
          "AqBCdwoS7/tPK+QGkPCadJTn8FxGkd24iApo3BR9/M0uw6n4RFAFSPAKKMgkzVMoRyR3ZS/aqATDFvoZJOkE9cPG/TAzmyZvr/WUIS8k" +
            "LmuI1dCA+itFF6+ULZqbkWS0YcVU0j6UDvMBvVlGTzHz+UHzWYJLUq2LnlynJtFap5k8560+tBGtxi9Gx2NIycKgbOUv0gEqhfVzAwvg" +
            "1IhTltfSwOeZXvDvd40rozONRxwq8hjKy+4DbfrO0iRtlT7G/eVEO9aJJnqagomFSkqCscttf/o6VeT2+A9JhcSxLmjcKFG3FEK3Try/" +
            "WkarJa1jM3lMRQqVOZrzHAaLFW/5sXano6DqqC5ERD6CcVVsrny0tYN4iHHB8BHJ9zvjff0NjLGG/v5Wsy31+BwZA8cUlfAZ0f5EYRo9" +
            "/vKSd8TV0wRb9DQ=",
        sig =
          "02fc3facf6621196c32912b1ef53bac8f8bfe9db51c0e7102c073103586b0d29" +
            "c3f39bdaa1e62856c20e90b6c7cc5dc34ca8bb6a528872cf6e65e6284519ad73",
      )

    val SPEC_WRAP =
      NostrEvent(
        id = "5c005f3ccf01950aa8d131203248544fb1e41a0d698e846bd419cec3890903ac",
        pubkey = "18b1a75918f1f2c90c23da616bce317d36e348bcf5f7ba55e75949319210c87c",
        createdAt = 1703021488L,
        kind = 1059,
        tags = listOf(listOf("p", SPEC_RECIPIENT_PUB)),
        content =
          "AhC3Qj/QsKJFWuf6xroiYip+2yK95qPwJjVvFujhzSguJWb/6TlPpBW0CGFwfufCs2Zyb0JeuLmZhNlnqecAAalC4ZCugB+I9ViA5pxL" +
            "yFfQjs1lcE6KdX3euCHBLAnE9GL/+IzdV9vZnfJH6atVjvBkNPNzxU+OLCHO/DAPmzmMVx0SR63frRTCz6Cuth40D+VzluKu1/Fg2Q1L" +
            "Sst65DE7o2efTtZ4Z9j15rQAOZfE9jwMCQZt27rBBK3yVwqVEriFpg2mHXc1DDwHhDADO8eiyOTWF1ghDds/DxhMcjkIi/o+FS3gG1dG" +
            "7gJHu3KkGK5UXpmgyFKt+421m5o++RMD/BylS3iazS1S93IzTLeGfMCk+7IKxuSCO06k1+DaasJJe8RE4/rmismUvwrHu/HDutZWkvOA" +
            "hd4z4khZo7bJLtiCzZCZ74lZcjOB4CYtuAX2ZGpc4I1iOKkvwTuQy9BWYpkzGg3ZoSWRD6ty7U+KN+fTTmIS4CelhBTT15QVqD02JxfL" +
            "F7nA6sg3UlYgtiGw61oH68lSbx16P3vwSeQQpEB5JbhofW7t9TLZIbIW/ODnI4hpwj8didtk7IMBI3Ra3uUP7ya6vptkd9TwQkd/7cOF" +
            "aSJmU+BIsLpOXbirJACMn+URoDXhuEtiO6xirNtrPN8jYqpwvMUm5lMMVzGT3kMMVNBqgbj8Ln8VmqouK0DR+gRyNb8fHT0BFPwsHxDs" +
            "kFk5yhe5c/2VUUoKCGe0kfCcX/EsHbJLUUtlHXmTqaOJpmQnW1tZ/siPwKRl6oEsIJWTUYxPQmrM2fUpYZCuAo/29lTLHiHMlTbarFOd" +
            "6J/ybIbICy2gRRH/LFSryty3Cnf6aae+A9uizFBUdCwTwffc3vCBae802+R92OL78bbqHKPbSZOXNC+6ybqziezwG+OPWHx1Qk39RYaF" +
            "0aFsM4uZWrFic97WwVrH5i+/Nsf/OtwWiuH0gV/SqvN1hnkxCTF/+XNn/laWKmS3e7wFzBsG8+qwqwmO9aVbDVMhOmeUXRMkxcj4QreQ" +
            "kHxLkCx97euZpC7xhvYnCHarHTDeD6nVK+xzbPNtzeGzNpYoiMqxZ9bBJwMaHnEoI944Vxoodf51cMIIwpTmmRvAzI1QgrfnOLOUS7uU" +
            "jQ/IZ1Qa3lY08Nqm9MAGxZ2Ou6R0/Z5z30ha/Q71q6meAs3uHQcpSuRaQeV29IASmye2A2Nif+lmbhV7w8hjFYoaLCRsdchiVyNjOEM4" +
            "VmxUhX4VEvw6KoCAZ/XvO2eBF/SyNU3Of4SO",
        sig =
          "35fabdae4634eb630880a1896a886e40fd6ea8a60958e30b89b33a93e6235df7" +
            "50097b04f9e13053764251b8bc5dd7e8e0794a3426a90b6bcc7e5ff660f54259",
      )
  }
}
