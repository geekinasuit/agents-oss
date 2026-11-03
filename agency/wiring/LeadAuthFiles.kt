package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.lead.LeadAuth
import com.geekinasuit.agency.nostr.AuthSpecSigning
import com.geekinasuit.agency.nostr.Bip340ApprovalVerifier
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.SpecLoadResult
import com.geekinasuit.agency.shared.auth.loadAuthorizationSpec
import java.io.File

/**
 * The auth a lead folds under, from the signed spec file at [specFile] (as `auth_spec sign` writes it)
 * and the root public key the deployment pins, [pinnedRoot] (as `auth_spec pubkey` prints it): the
 * spec's allow-list and quorum, loaded only if its signature verifies against [pinnedRoot] and
 * nothing the spec holds, with the bip340 verifier the lead checks approvals with. Whatever reads a
 * lead's journal and must reach the lead's verdicts builds its auth here.
 *
 * Throws [IllegalArgumentException] saying why for a file that is not a signed spec or a spec that
 * does not load, and the [java.io.IOException] of a file it cannot read.
 */
fun loadLeadAuth(specFile: String, pinnedRoot: String): LeadAuth {
  val spec = AuthSpecSigning.fromJson(File(specFile).readText()) ?: throw IllegalArgumentException("$specFile is not a signed spec file")
  return when (val loaded = loadAuthorizationSpec(spec, SchemeKey(AuthSpecSigning.ROOT_SCHEME, pinnedRoot), Bip340ApprovalVerifier)) {
    is SpecLoadResult.Loaded -> LeadAuth(loaded.allowList, Bip340ApprovalVerifier, loaded.quorum)
    is SpecLoadResult.Refused -> throw IllegalArgumentException("the spec did not load: ${loaded.reason}")
  }
}
