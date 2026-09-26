package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.auth.AllowList
import com.geekinasuit.agency.shared.auth.ApprovalEvidence
import com.geekinasuit.agency.shared.auth.ApprovalVerifier
import com.geekinasuit.agency.shared.auth.Principal
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.committedPreimage
import com.geekinasuit.agency.shared.auth.oneOfOne
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import com.geekinasuit.agency.shared.journal.SqliteStore
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * The minimal ceremony auth: one allow-listed principal, `operator`, which is enough for
 * [LeadAuth.hasApprovers] to hold. Its verifier accepts every signature and its quorum is one of
 * one, so an approval [approveAndRelease] journals re-verifies and its release clears. The cells
 * that use it test what the lead does under a ceremony auth, not how a release is verified, which
 * is the fold's concern (AuthFoldTest).
 */
fun ceremonyAuth(): LeadAuth =
  LeadAuth(
    allowList =
      AllowList(
        listOf(Principal("operator", role = "authorizer", keys = listOf(SchemeKey("test", "pk-operator"))))
      ),
    verifier = ApprovalVerifier { _, _, _, _ -> true },
    quorum = oneOfOne("operator"),
  )

/** An approval of ([gateId], [digest], [nonce]) by [ceremonyAuth]'s one principal, which its
 * accepting verifier re-verifies, then the release naming [nonce], which that approval's quorum
 * clears. */
fun SqliteStore.approveAndRelease(gateId: String, digest: String, nonce: String) {
  val publicKey = "pk-operator"
  append(
    LeadKinds.APPROVAL_RECORDED,
    buildJsonObject {
      put("gateId", gateId)
      put("principalId", "operator")
      put("nonce", nonce)
      put("payloadDigest", digest)
      put(
        "evidence",
        ApprovalEvidence(
            schemeId = "test",
            publicKey = publicKey,
            signature = "sig-operator",
            carrierArtifactId = "carrier-$nonce",
            gateId = gateId,
            payloadDigest = digest,
            nonce = nonce,
            signedPreimage = committedPreimage(publicKey, gateId, digest, nonce),
          )
          .toJson(),
      )
    },
    ORIGIN_AUTH_LAYER,
  )
  append(
    KIND_GATE_RELEASED,
    buildJsonObject {
      put("gateId", gateId)
      put("payloadDigest", digest)
      put("nonce", nonce)
    },
    ORIGIN_AUTH_LAYER,
  )
}

/** [approveAndRelease] for the gate and digest [nonce] is bound to. */
fun SqliteStore.approveAndRelease(nonce: IssuedNonce) =
  approveAndRelease(nonce.gateId, nonce.payloadDigest, nonce.nonce)
