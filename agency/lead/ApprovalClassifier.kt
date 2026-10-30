package com.geekinasuit.agency.lead

import com.geekinasuit.agency.lead.PayloadReaders.str
import com.geekinasuit.agency.shared.auth.ApprovalEvidence
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.parseCommitted
import kotlinx.serialization.json.JsonObject

/** What the host makes of one approval payload, before it records anything. See [classifyApproval]. */
internal sealed interface ApprovalVerdict {
  /** The approval re-verified, and no verified approval with its principal, nonce and digest is
   * held under [gateId] yet. */
  data class VerifiedNew(val gateId: String, val approval: VerifiedApproval) : ApprovalVerdict

  /** The approval re-verified, and the verified approval at [originalSeq] already holds its
   * principal, nonce and digest under [gateId]. */
  data class VerifiedDuplicate(val gateId: String, val approval: VerifiedApproval, val originalSeq: Long) :
    ApprovalVerdict

  /**
   * The approval did not re-verify, for [reason]. [claimedKey] is the key the evidence names, when
   * the evidence parses, its gate, digest and nonce copies equal the payload's, and the key is in the
   * allow-list; otherwise null, the unlisted bucket. The key is as claimed: a rejected approval never
   * proves who sent it.
   */
  data class Rejected(val reason: String, val claimedKey: SchemeKey?) : ApprovalVerdict
}

/**
 * Re-verifies an `approval-recorded` payload [p] journaled at [seq] against [auth], and decides
 * whether [verifiedApprovals] already holds it. An approval counts toward a quorum only if it
 * re-verifies: the evidence sub-object parses, the signed preimage is a canonical committed approval,
 * the signature verifies over it, its key resolves to an allow-listed principal, and every committed
 * field agrees with its flat copy. The PREIMAGE is the sole authority; the flat columns (top-level and
 * evidence) are lookup indices held to agreement, never trusted, so the flat `principalId` a record
 * claims can never by itself put an approver in a quorum.
 *
 * The top-level framing (gateId, principalId, nonce, payloadDigest) is the auth layer's own contract,
 * read strictly: a malformed required field throws. The evidence sub-object is carrier-provided proof,
 * so a malformed or absent one is [ApprovalVerdict.Rejected], never a throw. A rejection names which
 * layer disagreed.
 */
internal fun classifyApproval(
  verifiedApprovals: Map<String, List<VerifiedApproval>>,
  p: JsonObject,
  seq: Long,
  auth: LeadAuth,
): ApprovalVerdict {
  val claimedGate = p.str("gateId")
  val claimedPrincipal = p.str("principalId")
  val claimedNonce = p.str("nonce")
  val claimedDigest = p.str("payloadDigest")

  val evidenceObj = p["evidence"] as? JsonObject ?: return ApprovalVerdict.Rejected("carries no evidence sub-object", null)
  val evidence =
    try {
      ApprovalEvidence.fromJson(evidenceObj)
    } catch (x: Exception) {
      return ApprovalVerdict.Rejected("has malformed evidence: ${x.message}", null)
    }
  val claimedKey =
    SchemeKey(evidence.schemeId, evidence.publicKey).takeIf {
      evidence.gateId == claimedGate &&
        evidence.payloadDigest == claimedDigest &&
        evidence.nonce == claimedNonce &&
        auth.allowList.principalFor(it) != null
    }
  fun rejected(reason: String) = ApprovalVerdict.Rejected(reason, claimedKey)

  val preimage =
    evidence.signedPreimage ?: return rejected("carries no signed preimage — cannot re-verify (fail-closed)")
  val committed =
    parseCommitted(preimage) ?: return rejected("has a preimage that is not a canonical committed approval")
  if (!auth.verifier.verifies(evidence.schemeId, committed.publicKey, evidence.signature, preimage))
    return rejected("has a signature that does not verify over its preimage")
  val principal =
    auth.allowList.principalFor(SchemeKey(evidence.schemeId, committed.publicKey))
      ?: return rejected("is signed by a key not in the allow-list")
  // Three-layer agreement: the preimage is authority; the evidence's flat copies AND the
  // top-level payload fields must match it, or the record names one thing and signs another.
  if (evidence.publicKey != committed.publicKey) return rejected("evidence publicKey disagrees with the preimage")
  if (evidence.gateId != committed.gateId) return rejected("evidence gateId disagrees with the preimage")
  if (evidence.payloadDigest != committed.payloadDigest)
    return rejected("evidence payloadDigest disagrees with the preimage")
  if (evidence.nonce != committed.nonce) return rejected("evidence nonce disagrees with the preimage")
  if (claimedGate != committed.gateId) return rejected("payload gateId disagrees with the preimage")
  if (claimedNonce != committed.nonce) return rejected("payload nonce disagrees with the preimage")
  if (claimedDigest != committed.payloadDigest) return rejected("payload payloadDigest disagrees with the preimage")
  if (claimedPrincipal != principal.principalId)
    return rejected("payload principalId disagrees with the allow-list identity resolved from the preimage")

  val verified = VerifiedApproval(principal.principalId, committed.nonce, committed.payloadDigest, seq)
  val original =
    verifiedApprovals[committed.gateId].orEmpty().firstOrNull {
      it.principalId == verified.principalId && it.nonce == verified.nonce && it.payloadDigest == verified.payloadDigest
    }
  return if (original == null) ApprovalVerdict.VerifiedNew(committed.gateId, verified)
  else ApprovalVerdict.VerifiedDuplicate(committed.gateId, verified, original.seq)
}
