package com.geekinasuit.agency.nostr

import com.geekinasuit.agency.shared.auth.ApprovalVerifier
import java.security.MessageDigest

/**
 * The bip340 realization of the authorization layer's [ApprovalVerifier] port. This is the
 * concrete verifier the fold has been missing: it verifies that [signature] is a valid BIP-340
 * signature, by [publicKey], over `sha256(preimage)` — the identity an approval's signature
 * commits to (ApprovalEvidence documents that the signed identity is derived by hashing the
 * committed preimage).
 *
 * This signature is the AUTHORIZATION signature — what an approver bound themselves to (gate,
 * digest, nonce), carried in the committed preimage. It is DISTINCT from a nostr event's own
 * id+signature (which proves who relayed the carrier): the fold re-verifies THIS, over the
 * substrate-neutral committed preimage, and never trusts the transport. The two are separate
 * BIP-340 uses over two different messages, by design.
 *
 * The coupling points inward, per the standing rule: this adapter depends on the auth port; the
 * auth module and the fold never depend on nostr and never see the string "bip340" as anything
 * but the opaque scheme tag they were handed. A non-bip340 scheme is refused here (fail-closed):
 * a single-scheme verifier answers only for its scheme, and composing schemes is a later
 * concern, not a silent accept.
 *
 * The scheme tag is matched EXACTLY and case-sensitively against the literal `bip340`. That is
 * the registration contract, not an incidental detail: a spec that means this scheme must spell
 * the tag exactly, because a differently-cased or aliased tag (`BIP340`, `bip-340`) matches
 * nothing here and every approval under it fails closed — verifying nothing. Fail-closed makes
 * that safe, but it is a "loads fine, never authorizes anything" failure that surfaces at the
 * worst moment, so the contract is asserted in the tests rather than left implicit.
 *
 * Total and fail-closed: a malformed key, signature, or an unparseable preimage folds to
 * `false`, never a throw — a verification that cannot run is not a pass. So does a preimage
 * holding an unpaired surrogate: it has no UTF-8 encoding, so no signature is over it, and a
 * lenient encoder would hash `?` in its place, the preimage of a different string. Wiring this
 * verifier into the daemon (retiring RejectingVerifier as the default) is step 5's job, not this
 * module's; shipping the verifier does not by itself open any gate.
 */
object Bip340ApprovalVerifier : ApprovalVerifier {
  private const val SCHEME_ID = "bip340"

  override fun verifies(
    schemeId: String,
    publicKey: String,
    signature: String,
    preimage: String,
  ): Boolean {
    if (schemeId != SCHEME_ID) return false
    return try {
      val bytes = utf8OrNull(preimage) ?: return false
      val message = MessageDigest.getInstance("SHA-256").digest(bytes)
      Bip340.verifyBytes(Hex.decode(signature), message, Hex.decode(publicKey))
    } catch (_: Exception) {
      false
    }
  }
}
