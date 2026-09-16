package com.geekinasuit.agency.nostr

import com.geekinasuit.agency.shared.auth.AllowList
import com.geekinasuit.agency.shared.auth.Principal
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.committedPreimage
import com.geekinasuit.agency.shared.auth.oneOfOne
import com.geekinasuit.agency.shared.auth.quorumSatisfied
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The A4-6 property made executable: "listening never authorizes." The notifier slice adds a way to
 * PUBLISH a notice and no way for an inbound event to RELEASE a gate — the only release path
 * re-verifies an AUTHORIZATION signature (BIP-340 over the committed preimage) that a command-shaped
 * carrier does not carry. This drives the real verifier + allow-list + quorum to show it, rather
 * than restating the principle.
 *
 * The event is signed by an ALLOW-LISTED key and its NIP-01 transport signature VERIFIES — the
 * strong form of the test. A garbage or unsigned event would fail for boring reasons; a valid
 * carrier from a known author isolates exactly the two-layer split the design rests on: transport
 * signature present and good, authorization signature absent, release refused.
 */
class ListeningNeverAuthorizesTest {
  private val authorSecret = "0000000000000000000000000000000000000000000000000000000000000001"
  private val aux = "0101010101010101010101010101010101010101010101010101010101010101"

  @Test
  fun a_command_shaped_event_from_an_allow_listed_author_releases_nothing() {
    val authorPub = Bip340.xonlyPubkeyHex(authorSecret)
    // The author is a bona-fide allow-listed authorizer, and a 1-of-1 quorum names them.
    val allowList =
      AllowList(listOf(Principal("operator", "authorizer", listOf(SchemeKey("bip340", authorPub)))))
    val quorum = oneOfOne("operator")

    // A well-formed event of the notifier's OWN gate-open kind, whose CONTENT reads like a release
    // directive — the sharpest carrier an attacker could replay inbound at the daemon.
    val commandShaped =
      signEvent(
        secretKeyHex = authorSecret,
        createdAt = 1L,
        kind = GATE_OPEN_NOTICE_KIND,
        tags = emptyList(),
        content = """{"cmd":"release_gate","gateId":"gate-1"}""",
        auxRandHex = aux,
      )

    // Transport layer: the carrier is genuine — the author really signed it, and is allow-listed.
    assertTrue("transport signature verifies", commandShaped.verify())
    assertNotNull(
      "author is on the allow-list",
      allowList.principalFor(SchemeKey("bip340", commandShaped.pubkey)),
    )

    // Authorization layer: the ONLY signature the event carries is its transport sig over the event
    // id. Offered to the approval verifier as a signature over the committed preimage, it fails — it
    // commits to no gate/digest/nonce. There is no other signature to offer.
    val preimage = committedPreimage(commandShaped.pubkey, "gate-1", "any-digest", "any-nonce")
    val verifiedAsApproval =
      Bip340ApprovalVerifier.verifies("bip340", commandShaped.pubkey, commandShaped.sig, preimage)
    assertFalse(
      "a transport signature is not an authorization over the committed preimage",
      verifiedAsApproval,
    )

    // So the set of verified approvers is empty, and the quorum is not satisfied: no release.
    val verifiedApprovers = emptySet<String>()
    assertFalse("no gate clears from a command-shaped event", quorumSatisfied(quorum, verifiedApprovers))
  }
}
