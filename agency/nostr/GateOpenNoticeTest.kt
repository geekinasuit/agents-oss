package com.geekinasuit.agency.nostr

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The gate-open notice codec (A4-6). These cells sign and encrypt with the real BIP-340 / NIP-44
 * primitives (native runtime), and pin the slice's irreversible or security-bearing choices: the
 * event is lead-signed and regular-kinded, the notice round-trips to the recipient, an oversize
 * notice is a typed refusal (not a throw), no recipient tag leaks the custodian set, and
 * trial-decryption cleanly separates custodians — which is what makes dropping the `#p` tag safe.
 */
class GateOpenNoticeTest {
  private val leadSecret = "0000000000000000000000000000000000000000000000000000000000000001"
  private val recipASecret = "0000000000000000000000000000000000000000000000000000000000000002"
  private val recipBSecret = "0000000000000000000000000000000000000000000000000000000000000003"
  private val aux = "0101010101010101010101010101010101010101010101010101010101010101"

  private fun encoded(notice: GateOpenNotice, recipientSecret: String = recipASecret): NostrEvent {
    val recipient = RecipientKey.of(Bip340.xonlyPubkeyHex(recipientSecret))
    val encoding = encodeGateOpenNotice(leadSecret, recipient, notice, createdAt = 1000L, auxRandHex = aux)
    assertTrue("expected an Encoded result", encoding is NoticeEncoding.Encoded)
    return (encoding as NoticeEncoding.Encoded).event
  }

  @Test
  fun encodes_a_lead_signed_event_the_recipient_can_decrypt() {
    val notice = GateOpenNotice("gate-1", "digest-abc", "nonce-xyz", "approve deploy of build 42")
    val event = encoded(notice)

    assertEquals("signed by the lead", Bip340.xonlyPubkeyHex(leadSecret), event.pubkey)
    assertTrue("the lead's transport signature must verify", event.verify())

    // Operator side (step 6): the SAME conversation key derived from the recipient's own secret and
    // the lead's pubkey (ECDH is symmetric), then decrypt.
    val leadPub = Bip340.xonlyPubkeyHex(leadSecret)
    val convKey = Nip44.conversationKey(hexToBytes(recipASecret), hexToBytes(leadPub))
    val plaintext = Nip44.decrypt(event.content, convKey)
    assertNotNull("the addressed recipient can decrypt", plaintext)

    val obj = Json.parseToJsonElement(plaintext!!).jsonObject
    assertEquals("gate-1", obj["gateId"]!!.jsonPrimitive.content)
    assertEquals("digest-abc", obj["payloadDigest"]!!.jsonPrimitive.content)
    assertEquals("nonce-xyz", obj["nonce"]!!.jsonPrimitive.content)
    assertEquals("approve deploy of build 42", obj["artifact"]!!.jsonPrimitive.content)
  }

  @Test
  fun refuses_an_oversize_notice_as_a_typed_result_not_a_throw() {
    // > 65535 UTF-8 bytes in the artifact alone, before JSON overhead.
    val notice = GateOpenNotice("gate-1", "digest", "nonce", "x".repeat(70_000))
    val recipient = RecipientKey.of(Bip340.xonlyPubkeyHex(recipASecret))
    val encoding = encodeGateOpenNotice(leadSecret, recipient, notice, 1000L, aux)

    assertTrue("an oversize notice is a typed refusal", encoding is NoticeEncoding.TooLarge)
    val tooLarge = encoding as NoticeEncoding.TooLarge
    assertEquals("names NIP-44 v2's 16-bit length ceiling", 65535, tooLarge.ceilingBytes)
    assertTrue("reports the actual over-ceiling size", tooLarge.plaintextBytes > 65535)
  }

  @Test
  fun attaches_no_recipient_tag_so_the_relay_never_learns_the_custodian_set() {
    val event = encoded(GateOpenNotice("gate-1", "d", "n", "a"))
    assertTrue(
      "A4-6's ratified residuals do not include recipient-set disclosure — no #p tag",
      event.tags.isEmpty(),
    )
  }

  @Test
  fun publishes_under_a_regular_stored_kind() {
    assertTrue("regular (relay-stored) kinds are 1000..9999", GATE_OPEN_NOTICE_KIND in 1000..9999)
    assertEquals(GATE_OPEN_NOTICE_KIND, encoded(GateOpenNotice("gate-1", "d", "n", "a")).kind)
  }

  @Test
  fun a_notice_for_one_custodian_does_not_decrypt_for_another() {
    val notice = GateOpenNotice("gate-1", "digest-abc", "nonce-xyz", "custodian-only artifact")
    val event = encoded(notice, recipientSecret = recipASecret)
    val leadPub = Bip340.xonlyPubkeyHex(leadSecret)

    // Custodian B trial-decrypts with its own (B, lead) key — folds to null, so B learns nothing and
    // the relay needed no recipient tag to route.
    val bKey = Nip44.conversationKey(hexToBytes(recipBSecret), hexToBytes(leadPub))
    assertNull("a notice for A does not decrypt for B", Nip44.decrypt(event.content, bKey))

    // Custodian A trial-decrypts and reads it.
    val aKey = Nip44.conversationKey(hexToBytes(recipASecret), hexToBytes(leadPub))
    assertNotNull("the addressed custodian reads it", Nip44.decrypt(event.content, aKey))
  }

  @Test
  fun rejects_an_off_curve_recipient_key() {
    // 64 valid hex characters, but 0xff…ff is beyond the secp256k1 field prime — not a curve point.
    // RecipientKey.of must refuse it here, at the config boundary, rather than let it abort the
    // fan-out's crypto phase downstream and sink delivery to every custodian.
    assertThrows(IllegalArgumentException::class.java) { RecipientKey.of("ff".repeat(32)) }
  }

  /** Local hex decoder — the module's `Hex` is internal, and a test target links `:nostr` as a dep,
   * not `associates`, so it cannot reach it. */
  private fun hexToBytes(s: String): ByteArray =
    ByteArray(s.length / 2) {
      ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte()
    }
}
