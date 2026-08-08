package com.geekinasuit.agency.lead

import com.geekinasuit.agency.shared.journal.JournalStore
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * STUB — the authorization ceremony placeholder.
 *
 * What is REAL here, and stays: a gate release is honored only via provenance
 * (origin == auth layer — the shared fold rejects everything else visibly) AND digest
 * binding (the lead fold holds a gate pending unless the release names the exact digest
 * the gate was opened on; mismatches are retained visibly as stale). Those teeth are
 * enforced by the folds, not by this class, and no caller can opt out of them.
 *
 * What is STUBBED, and is replaced later: the ceremony that AUTHENTICATES the
 * releasing human — phone notification, authenticated approval surface, nonce,
 * single-use enforcement, and the mechanical re-verification pass. Until then, calling
 * this helper IS the act of approval: it is a test/CLI hook that appends the release
 * entry with authorization provenance. There is no capability check, principal, or nonce
 * on the call itself — reaching this surface, or
 * [LeadDaemon.injectAuthRelease], IS authorizing a release. So neither may be exposed to a
 * network surface, a mailbox handler, or anything a pod or cognition strategy can reach
 * before the real ceremony lands; that is what keeps "proposer never releases" true here.
 *
 * Note on echoing: current callers copy [payloadDigest] from the pending gate, which would
 * be circular if cognition controlled gate digests — it does not: the substrate opens
 * gates only on its own recorded evidence (see LeadDaemon.executeProposals), so what the
 * echo confirms is substrate evidence. The real ceremony shows the human the digest AND
 * the artifact behind it before they sign.
 */
object AuthStub {
  /**
   * Append a gate release with authorization provenance, bound to [payloadDigest].
   * Store-level surface for SEQUENTIAL processes (fixture subcommands, CLI with no daemon
   * up); in-process approvals while the daemon runs go through
   * [LeadDaemon.injectAuthRelease], which performs THIS SAME append at the accept boundary
   * and then rings the loop's doorbell (journal-then-ack, AGENCY-021).
   *
   * SECOND-WRITER HAZARD, updated by the AGENCY-021 fix: within one
   * process the store serializes appends internally, so a same-process accept-time append
   * no longer races the loop's at the chain level — and a loop refold between a foreign
   * append and its own is now a NORMAL occurrence the folds are designed for (arrival
   * facts land whenever accepted). What REMAINS a violation is a second PROCESS appending
   * while a daemon loop is alive on the same workspace: nothing beyond SQLite's own
   * locking arbitrates two connections, and the running daemon gets no doorbell for the
   * foreign entry (it surfaces only at that daemon's next wake or adopt). A cross-process
   * store lock is the durable fix and belongs with the store layer, not here.
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
