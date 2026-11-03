package com.geekinasuit.agency.lead

import com.geekinasuit.agency.lead.PayloadReaders.jsonStringOrNull
import com.geekinasuit.agency.shared.journal.JournalReader
import com.geekinasuit.agency.shared.journal.ORIGIN_AUTH_LAYER
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.payloadObject
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

/** A gate open in the current scope, as the fold holds it. */
data class GateStatus(
  val gateId: String,
  val gateKind: String,
  val payloadDigest: String,
  val openedSeq: Long,
  /** The `authSpecHash` the gate-open row recorded, or null when it recorded none. */
  val openedUnderSpecHash: String?,
  /** Whether the gate is released on the digest it is open on now. */
  val approvedOnCurrentDigest: Boolean,
  /** The nonce a release of the gate as it stands would name, or null when it has none. */
  val openNonce: String?,
  /** The principals whose verified approval binds the gate as it stands, under [openNonce]. */
  val boundApprovers: Set<String>,
)

/** A nonce issued in the current scope, and whether it is spent. */
data class NonceStatus(val nonce: String, val gateId: String, val payloadDigest: String, val issuedSeq: Long, val consumed: Boolean)

/** An approval row the accept boundary journaled as rejected, with the reason it gave on arrival,
 * under the auth in force then. Under another auth the same row can re-verify, and is then in
 * [LeadStatus.verifiedApprovals] as well. */
data class RejectedApproval(val seq: Long, val gateId: String?, val nonce: String?, val reason: String)

/** The accept boundary's account of the attempts it dropped on one nonce. */
data class DroppedOnNonce(
  val seq: Long,
  val gateId: String?,
  val nonce: String?,
  val duplicates: Long,
  /** Rejected attempts past the allowance, summed over the keys they claimed. */
  val rejectedOverAllowance: Long,
  val rejectedOverAllowanceUnlisted: Long,
  val wrongDigest: Long,
  val oversized: Long,
)

/** The accept boundary's count of attempts that named no open nonce, over one interval. */
data class DroppedNotOpen(val seq: Long, val notOpen: Long, val intervalStart: Long?)

/**
 * What a ticket lead's journal says now, folded as the lead folds it: under [foldedUnderSpecHash]'s
 * allow-list and quorum, with the ticket workflow's kinds. Every string here comes from the journal,
 * and so from whoever wrote it, so a reader shows them made inert.
 *
 * The scoped parts — [gates], [nonces], [verifiedApprovals], [unverifiedApprovals], [rejectedApprovals],
 * [droppedOnNonce] — cover the current scope, from the last ticket done on. [escalations],
 * [misOriginedEntries] and [malformedCognition] are the fold's running tails, which a scope end does
 * not clear, and [droppedNotOpen] names no nonce, so it covers the whole journal.
 */
data class LeadStatus(
  val foldedUnderSpecHash: String,
  /** The seq of the last entry, the chain's head. */
  val headSeq: Long,
  val gates: List<GateStatus>,
  val nonces: List<NonceStatus>,
  val verifiedApprovals: List<VerifiedApproval>,
  /** (seq, reason) for approvals that did not re-verify under [foldedUnderSpecHash]'s auth. */
  val unverifiedApprovals: List<Pair<Long, String>>,
  val rejectedApprovals: List<RejectedApproval>,
  val droppedOnNonce: List<DroppedOnNonce>,
  val droppedNotOpen: List<DroppedNotOpen>,
  val escalations: List<String>,
  /** (seq, kind) for rows of a kind whose author is the substrate or the authorization layer that
   * carried another origin, which the fold never honors. */
  val misOriginedEntries: List<Pair<Long, String>>,
  /** (seq, reason) for cognition turns whose output was unusable. */
  val malformedCognition: List<Pair<Long, String>>,
) {
  /** The open gates whose gate-open row recorded a spec hash other than [foldedUnderSpecHash]: the
   * verdicts here may not be the ones the lead reaches, if it folds under another auth. */
  val gatesOpenedUnderAnotherSpec: List<GateStatus>
    get() = gates.filter { it.openedUnderSpecHash != null && it.openedUnderSpecHash != foldedUnderSpecHash }
}

/**
 * The status of the ticket lead whose journal [reader] reads, folded from genesis under [auth]: the
 * whole chain verified ([JournalReader.readAll]), then folded as [ticketLead]'s host folds it. A chain
 * that does not verify, or an entry the fold refuses, throws as a cold fold does, and nothing is
 * returned.
 */
fun ticketLeadStatus(reader: JournalReader, auth: LeadAuth): LeadStatus {
  val entries = reader.readAll()
  val host = foldHostAndLead(entries, auth, TicketWorkflowFold).first
  // The scope starts after the last scope end the fold honored: the host's provenance gate refuses a
  // workflow kind with any origin but the substrate's before it clears anything ([hostStep]).
  val scope =
    entries.drop(entries.indexOfLast { it.kind in TICKET_WORKFLOW_SCOPE_END_KINDS && it.origin == ORIGIN_SUBSTRATE } + 1)
  val openedUnder = mutableMapOf<String, String?>()
  val rejected = mutableListOf<RejectedApproval>()
  val dropped = mutableListOf<DroppedOnNonce>()
  // Each row read here has the origin its kind's author writes, so it passed the fold's provenance
  // gate, and the fold has parsed its payload as an object. The fields are read leniently: the fold
  // records no state from them, so a field of the wrong type reads as no value, or as a zero count.
  for (e in scope) {
    when {
      e.kind == HostKinds.GATE_OPENED && e.origin == ORIGIN_SUBSTRATE -> {
        val p = payloadObject(e.payloadJson)
        p.jsonStringOrNull("gateId")?.let { openedUnder[it] = p.jsonStringOrNull("authSpecHash") }
      }
      e.kind == HostKinds.APPROVAL_RECORDED && e.origin == ORIGIN_AUTH_LAYER -> {
        val p = payloadObject(e.payloadJson)
        p.jsonStringOrNull("rejectedReason")?.let { rejected += RejectedApproval(e.seq, p.jsonStringOrNull("gateId"), p.jsonStringOrNull("nonce"), it) }
      }
      e.kind == HostKinds.APPROVAL_DROPS_SUMMARIZED && e.origin == ORIGIN_AUTH_LAYER -> {
        val p = payloadObject(e.payloadJson)
        dropped +=
          DroppedOnNonce(
            e.seq,
            p.jsonStringOrNull("gateId"),
            p.jsonStringOrNull("nonce"),
            p.count("duplicates"),
            (p["rejectedOverAllowance"] as? JsonArray).orEmpty().sumOf { ((it as? JsonObject)?.count("count")) ?: 0L },
            p.count("rejectedOverAllowanceUnlisted"),
            p.count("wrongDigest"),
            p.count("oversized"),
          )
      }
    }
  }
  val notOpen =
    entries
      .filter { it.kind == HostKinds.APPROVAL_DROPS_AGGREGATED && it.origin == ORIGIN_AUTH_LAYER }
      .map { e -> payloadObject(e.payloadJson).let { DroppedNotOpen(e.seq, it.count("notOpen"), it.numberOrNull("intervalStart")) } }
  return LeadStatus(
    foldedUnderSpecHash = auth.specHash,
    headSeq = entries.lastOrNull()?.seq ?: 0,
    gates =
      host.openGates.values
        .sortedBy { it.openedSeq }
        .map { g ->
          val nonce = host.openNonceFor(g)?.nonce
          GateStatus(
            g.gateId, g.gateKind, g.payloadDigest, g.openedSeq, openedUnder[g.gateId],
            host.approvedOnCurrentDigest(g.gateId), nonce, nonce?.let { host.boundApprovers(g, it) }.orEmpty(),
          )
        },
    nonces =
      host.issuedNonces.values
        .sortedBy { it.issuedSeq }
        .map { NonceStatus(it.nonce, it.gateId, it.payloadDigest, it.issuedSeq, it.nonce in host.consumedNonces) },
    verifiedApprovals = host.verifiedApprovals.values.flatten().sortedBy { it.seq },
    unverifiedApprovals = host.unverifiedApprovals,
    rejectedApprovals = rejected,
    droppedOnNonce = dropped,
    droppedNotOpen = notOpen,
    escalations = host.escalations,
    misOriginedEntries = host.misOriginedEntries,
    malformedCognition = host.malformedCognition,
  )
}

private fun JsonObject.numberOrNull(k: String): Long? = (this[k] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull

private fun JsonObject.count(k: String): Long = numberOrNull(k) ?: 0
