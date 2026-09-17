package com.geekinasuit.agency.nostr

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The wire codec over the real BIP-340 primitive: the NIP-42 auth event, and the proof that a
 * genuinely signed event survives serialization and parsing with its signature intact. The
 * native-free structural cells are in [NostrWireTest]; these need the secp256k1 native because
 * they sign and verify.
 */
class NostrWireSignTest {
  // Same deterministic key as NostrEventSignVerifyTest: secret scalar 3, zero aux randomness.
  private val secretKey = "0000000000000000000000000000000000000000000000000000000000000003"
  private val auxRand = "0000000000000000000000000000000000000000000000000000000000000000"

  @Test
  fun `buildAuthEvent produces a verifiable kind-22242 event with relay and challenge tags`() {
    val relay = "wss://relay.example.com"
    val challenge = "the-relay-challenge-string"
    val ev = buildAuthEvent(secretKey, relay, challenge, 1700000000L, auxRand)
    assertEquals(22242, ev.kind)
    assertEquals(listOf(listOf("relay", relay), listOf("challenge", challenge)), ev.tags)
    assertEquals("", ev.content)
    assertEquals(Bip340.xonlyPubkeyHex(secretKey), ev.pubkey)
    assertTrue(ev.verify())
  }

  @Test
  fun `buildAuthEvent over key bytes produces the identical event to the hex overload`() {
    // The #42 clearable-key auth path builds the event from key bytes; it must match the hex path.
    // The hex key is secret scalar 3, so its bytes are 31 zeros then 0x03.
    val secretKeyBytes = ByteArray(32).also { it[31] = 3 }
    val relay = "wss://relay.example.com"
    val challenge = "the-relay-challenge-string"
    val fromHex = buildAuthEvent(secretKey, relay, challenge, 1700000000L, auxRand)
    val fromBytes = buildAuthEvent(secretKeyBytes, relay, challenge, 1700000000L, auxRand)
    assertEquals(fromHex, fromBytes)
  }

  @Test
  fun `a signed event survives the wire round-trip and still verifies`() {
    val ev =
      signEvent(secretKey, 1700000000L, 1, listOf(listOf("e", "x"), listOf("p", "y")), "hello", auxRand)
    val parsed = parseEvent(ev.serialize())
    assertEquals(ev, parsed)
    assertTrue(parsed!!.verify())
  }

  @Test
  fun `a signed auth event survives the AUTH envelope round-trip and still verifies`() {
    val ev = buildAuthEvent(secretKey, "wss://relay.example.com", "chal", 1700000000L, auxRand)
    // The full client path a relay sees: frame with authMessage, then unwrap and verify. Parsing
    // the ["AUTH", <event>] envelope needs a JSON reader — parseRelayMessage handles the inbound
    // ["AUTH", <challenge>] shape, not this outbound one — so unwrap with kotlinx directly.
    val arr = Json.parseToJsonElement(authMessage(ev)).jsonArray
    assertEquals(2, arr.size)
    assertEquals("AUTH", arr[0].jsonPrimitive.content)
    val unwrapped = parseEvent(arr[1].toString())
    assertEquals(ev, unwrapped)
    assertTrue(unwrapped!!.verify())
  }

  @Test
  fun `a signed event with C0 controls in content survives the wire round-trip and verifies`() {
    // The two-escapings property, end to end: 0x01 and 0x1F are raw in the id-preimage but escaped
    // numerically on the wire. The signature verifies only if parse restores the raw bytes so
    // eventId recomputes the same preimage — this fails loudly if the wire codec and
    // Nip01.appendString ever disagreed on a control byte. (The hermetic half is in NostrWireTest.)
    val content = "x" + 1.toChar() + "y" + 0x1F.toChar() + "z"
    val ev = signEvent(secretKey, 1700000000L, 1, emptyList(), content, auxRand)
    val parsed = parseEvent(ev.serialize())
    assertEquals(ev, parsed)
    assertTrue(parsed!!.verify())
  }

  // ---- #34: cross-implementation id vectors (external anchor) ----
  // Real events from go-nostr's asserted test suite (nbd-wtf, fiatjaf's org — the NIP-01 reference
  // maintainers): TestEventParsingAndVerifying recomputes each id as
  // sha256([0,pubkey,created_at,kind,tags,content]) and BIP-340-verifies each sig in CI, so
  // agreement here proves this codec matches the network, not merely itself. Because each sig is a
  // Schnorr signature over the id, a transcription error FAILS verification loudly — it cannot pass
  // with wrong bytes, so verify() is its own final check on these values.
  // Source: https://github.com/nbd-wtf/go-nostr/blob/master/event_test.go

  @Test
  fun `external vector reproduces its id and verifies (empty tags, ASCII content)`() {
    // A famous 2022-02-07 fiatjaf note; id and sig independently corroborated from njump.me, a
    // live relay explorer of a separate lineage from the go-nostr test file.
    val ev =
      NostrEvent(
        id = "dc90c95f09947507c1044e8f48bcf6350aa6bff1507dd4acfc755b9239b5c962",
        pubkey = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
        createdAt = 1644271588L,
        kind = 1,
        tags = emptyList(),
        content =
          "now that https://blueskyweb.org/blog/2-7-2022-overview was announced we can stop working on nostr?",
        sig =
          "230e9d8f0ddaf7eb70b5f7741ccfa37e87a455c9a469282e3464e2052d3192cd63a167e196e381ef9d7e69e9ea43af2443b839974dc85d8aaab9efe1d9296524",
      )
    assertEquals(ev.id, Nip01.eventId(ev.pubkey, ev.createdAt, ev.kind, ev.tags, ev.content))
    assertTrue(ev.verify())
  }

  @Test
  fun `external vector reproduces its id and verifies (tags, quote-escaped content)`() {
    // A kind:3 contact list whose content is a JSON object serialized as a string — every " forces
    // the NIP-01 quote-escaping path that vector 1 cannot reach. This exercises the hand-rolled
    // appendString against an independent implementation over real, escape-dense bytes.
    val ev =
      NostrEvent(
        id = "9e662bdd7d8abc40b5b15ee1ff5e9320efc87e9274d8d440c58e6eed2dddfbe2",
        pubkey = "373ebe3d45ec91977296a178d9f19f326c70631d2a1b0bbba5c5ecc2eb53b9e7",
        createdAt = 1644844224L,
        kind = 3,
        tags =
          listOf(
            listOf("p", "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"),
            listOf("p", "75fc5ac2487363293bd27fb0d14fb966477d0f1dbc6361d37806a6a740eda91e"),
            listOf("p", "46d0dfd3a724a302ca9175163bdf788f3606b3fd1bb12d5fe055d1e418cb60ea"),
          ),
        content =
          """{"wss://nostr-pub.wellorder.net":{"read":true,"write":true},"wss://nostr.bitcoiner.social":{"read":false,"write":true},"wss://expensive-relay.fiatjaf.com":{"read":true,"write":true},"wss://relayer.fiatjaf.com":{"read":true,"write":true},"wss://relay.bitid.nz":{"read":true,"write":true},"wss://nostr.rocks":{"read":true,"write":true}}""",
        sig =
          "811355d3484d375df47581cb5d66bed05002c2978894098304f20b595e571b7e01b2efd906c5650080ffe49cf1c62b36715698e9d88b9e8be43029a2f3fa66be",
      )
    assertEquals(ev.id, Nip01.eventId(ev.pubkey, ev.createdAt, ev.kind, ev.tags, ev.content))
    assertTrue(ev.verify())
  }
}
