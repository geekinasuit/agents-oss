package com.geekinasuit.agency.nostr

import com.geekinasuit.agency.shared.auth.ApprovalEvidence
import com.geekinasuit.agency.shared.auth.committedPreimage
import java.security.MessageDigest

/**
 * The approver's half of the ceremony, over nostr: reading a gate-open notice the lead sent, and
 * signing the approval of one. These are the pieces an approval client is built from; showing the
 * approver exactly what they are approving is that client's job, and these give it what to show.
 */
object ApprovalSigning {
  /**
   * The [GateOpenNotice] [rumor] carries from the lead [leadPubkey], or null. Applies every check
   * [encodeGateOpenNotice]'s KDoc asks of a reader: the kind is [GATE_OPEN_NOTICE_RUMOR_KIND], the
   * rumor's author (which [Nip59.unwrap] authenticated) is [leadPubkey], each of `agency-gate-id`,
   * `agency-payload-digest` and `agency-nonce` appears exactly once, and the artifact's UTF-8 bytes
   * hash to the digest, so what is shown is what the nonce authorizes. Total.
   *
   * Deduplicating repeats (the lead may announce one gate-open again) is the caller's, on the nonce.
   * [leadPubkey] is compared as given, and [Nip59.unwrap] returns authors in lowercase hex, so pass the
   * lead's key in that form ([RecipientKey.hex] is).
   */
  fun decodeNotice(rumor: Rumor, leadPubkey: String): GateOpenNotice? {
    if (rumor.kind != GATE_OPEN_NOTICE_RUMOR_KIND || rumor.pubkey != leadPubkey) return null
    val gateId = soleTag(rumor, "agency-gate-id") ?: return null
    val digest = soleTag(rumor, "agency-payload-digest") ?: return null
    val nonce = soleTag(rumor, "agency-nonce") ?: return null
    if (sha256Hex(rumor.content) != digest) return null
    return try {
      GateOpenNotice(gateId, digest, nonce, rumor.content)
    } catch (_: IllegalArgumentException) {
      null
    }
  }

  /**
   * The approval of [notice] by the holder of [approverKey] (raw bytes the caller holds and zeroes):
   * a BIP-340 signature over sha256 of the [committedPreimage] of the approver's key and the notice's
   * gate, digest and nonce, with the evidence the lead re-verifies. Throws [IllegalArgumentException]
   * when the lead's decoder would refuse the carrier ([carrierDecodes]). That is the carrier's bound;
   * the lead's accept boundary also bounds the row it journals (a few thousand characters), which an
   * approval of a notice the lead minted stays well under. [auxRandHex] is the signature's aux
   * randomness, 32 bytes of hex.
   */
  fun sign(notice: GateOpenNotice, approverKey: ByteArray, auxRandHex: String): ApprovalCarrier {
    val publicKey = Bip340.xonlyPubkeyFromKeyBytes(approverKey)
    val preimage = committedPreimage(publicKey, notice.gateId, notice.payloadDigest, notice.nonce)
    val evidence =
      ApprovalEvidence(
        schemeId = "bip340",
        publicKey = publicKey,
        signature = Bip340.signWithKeyBytes(sha256Hex(preimage), approverKey, auxRandHex),
        // The lead replaces this with the rumor's id on decode; it is required non-blank here.
        carrierArtifactId = "set-by-the-lead",
        gateId = notice.gateId,
        payloadDigest = notice.payloadDigest,
        nonce = notice.nonce,
        signedPreimage = preimage,
      )
    val carrier = ApprovalCarrier(notice.gateId, notice.nonce, notice.payloadDigest, evidence.toJson())
    require(carrierDecodes(carrier)) { "the approval would be too large or malformed for the lead to read" }
    return carrier
  }

  private fun soleTag(rumor: Rumor, name: String): String? =
    rumor.tags.filter { it.firstOrNull() == name }.singleOrNull()?.takeIf { it.size == 2 }?.get(1)

  private fun sha256Hex(text: String): String =
    Hex.encode(MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)))
}
