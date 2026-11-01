package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalStore
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * TEST SUPPORT — the pre-ceremony release, kept for tests and the lead fixture only. Production
 * journals a release only through the approval accept boundary ([AgentHost.injectApproval]), for a
 * verified quorum. This library is testonly, which keeps the helper out of production targets; it
 * does not make an authorization-layer append impossible (`JournalStore.append` is public). The
 * safeguard is the folds, below.
 *
 * Calling [appendRelease] IS the act of approval: it appends a release with authorization
 * provenance and no nonce, principal or evidence. What the folds check still applies to it:
 * provenance (origin == auth layer), digest binding, and, under a ceremony auth, the rule that a
 * release names a nonce and meets the quorum, so a nonce-less release clears a gate only under
 * [LeadAuth.DENY_ALL]. Tests that drive the pre-ceremony pipeline use it with that auth.
 *
 * Note on echoing: callers copy the payload digest from the pending gate. That is not circular,
 * since the substrate opens gates only on its own recorded evidence: the echo confirms substrate
 * evidence.
 */
object AuthStub {
  /**
   * Appends a gate release with authorization provenance, bound to [payloadDigest]. The store-level
   * surface for sequential processes such as the lead fixture. A test with a host running uses
   * [injectAuthRelease], which also wakes the loop.
   *
   * A second process appending while a daemon loop is alive on the same workspace is still a
   * violation: nothing beyond SQLite's own locking arbitrates two connections, and the running
   * daemon gets no doorbell for the foreign entry.
   */
  fun appendRelease(store: JournalStore, gateId: String, payloadDigest: String) {
    store.append(
      KIND_GATE_RELEASED,
      buildJsonObject {
        put("gateId", gateId)
        put("payloadDigest", payloadDigest)
      },
      origin = ORIGIN_AUTH_LAYER,
    )
  }
}

/**
 * Approves [gateId] on [payloadDigest] while this host runs: [AuthStub.appendRelease] on the host's
 * journal, then the loop's doorbell (journal-then-doorbell, AGENCY-021), so a crash after the append
 * loses nothing the next adopt does not fold.
 */
fun AgentHost<*>.injectAuthRelease(gateId: String, payloadDigest: String) {
  AuthStub.appendRelease(journal, gateId, payloadDigest)
  ringForRelease(gateId, payloadDigest)
}
