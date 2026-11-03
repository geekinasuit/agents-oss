package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.lead.LeadFoldException
import com.geekinasuit.agency.lead.LeadStatus
import com.geekinasuit.agency.lead.ticketLeadStatus
import com.geekinasuit.agency.shared.journal.ChainBrokenException
import com.geekinasuit.agency.shared.journal.EpochRuleException
import com.geekinasuit.agency.shared.journal.JournalVersionException
import com.geekinasuit.agency.shared.journal.SqliteJournalReader
import com.geekinasuit.agency.shared.text.inert
import java.io.PrintStream
import kotlin.system.exitProcess

/**
 * The operator's view of a running ticket lead, read from its journal:
 *
 *  `lead_status --journal DIR --component ID --spec F --root PUB`
 *
 * prints the lead's status once ([ticketLeadStatus]): its open gates, nonces, approvals (verified,
 * unverified, and rejected on arrival, with the reason given then), the approval boundary's drop
 * counts, and the fold's escalation, mis-origin and malformed-cognition tails. DIR is the lead's
 * journal directory and ID the component the journal belongs to. F and PUB are the lead's signed
 * spec and pinned root, loaded as the lead loads them ([loadLeadAuth]): the verdicts printed are
 * those reached under that auth, so the output names the spec hash it folded under, and warns of any
 * open gate the lead opened under another.
 *
 * It opens the journal read-only beside the lead ([SqliteJournalReader]), and so runs as the lead's
 * OS user: the journal's directory is the owner's alone, and SQLite needs to write its WAL files
 * there. Every string from the journal is printed inert ([inert]).
 *
 * Exit 0 with the status printed; 1 on a refusal (no journal there, a spec that does not load, a file
 * or database it cannot read); 2 on a usage error, checked before any file is read; 3 when the
 * journal does not verify (a broken chain, a key-epoch violation, a schema version this build does
 * not read); 4 when the fold refuses an entry. Each failure prints one line on stderr saying why. A
 * journal is verified against the component ID names, so a wrong ID reads as a journal that does not
 * verify, exit 3: the line names the context the journal holds.
 */
object LeadStatusTool {
  @JvmStatic
  fun main(args: Array<String>) {
    exitProcess(run(args.toList(), System.out, System.err))
  }

  fun run(args: List<String>, out: PrintStream, err: PrintStream): Int {
    val flags =
      try {
        flagsOf(args, FLAGS).also { f -> FLAGS.forEach { f.required(it) } }
      } catch (x: IllegalArgumentException) {
        return usage(err, x.message ?: "bad arguments")
      }
    return try {
      val auth = loadLeadAuth(flags.required("--spec"), flags.required("--root"))
      val status = SqliteJournalReader(flags.required("--journal"), flags.required("--component")).use { ticketLeadStatus(it, auth) }
      show(status, out)
      0
    } catch (x: ChainBrokenException) {
      refuse(err, x, 3)
    } catch (x: EpochRuleException) {
      refuse(err, x, 3)
    } catch (x: JournalVersionException) {
      refuse(err, x, 3)
    } catch (x: LeadFoldException) {
      refuse(err, x, 4)
    } catch (x: IllegalArgumentException) {
      refuse(err, x, 1)
    } catch (x: java.io.IOException) {
      refuse(err, x, 1)
    } catch (x: java.sql.SQLException) {
      refuse(err, x, 1)
    }
  }

  private fun refuse(err: PrintStream, x: Exception, code: Int): Int {
    err.println("lead_status: ${x.javaClass.simpleName}: ${inert(x.message.orEmpty())}")
    return code
  }

  private fun show(s: LeadStatus, out: PrintStream) {
    out.println("head seq ${s.headSeq}, folded under spec ${s.foldedUnderSpecHash}")
    for (g in s.gatesOpenedUnderAnotherSpec) {
      out.println("WARNING: ${inert(g.gateId)} was opened under spec ${inert(g.openedUnderSpecHash.orEmpty())}; the lead may reach other verdicts")
    }
    section(out, "open gates", s.gates) { g ->
      val released = if (g.approvedOnCurrentDigest) "released" else "not released"
      val approvers = g.boundApprovers.sorted().joinToString(",") { inert(it) }.ifEmpty { "none" }
      "${inert(g.gateId)} (${inert(g.gateKind)}) opened at seq ${g.openedSeq} on ${inert(g.payloadDigest)}: $released, " +
        "nonce ${g.openNonce?.let { inert(it) } ?: "none"}, approvers $approvers"
    }
    section(out, "nonces", s.nonces) { n ->
      "${inert(n.nonce)} for ${inert(n.gateId)} at seq ${n.issuedSeq}${if (n.consumed) ", consumed" else ""}"
    }
    section(out, "verified approvals", s.verifiedApprovals) { a ->
      "seq ${a.seq}: ${inert(a.principalId)} on nonce ${inert(a.nonce)}"
    }
    section(out, "unverified approvals", s.unverifiedApprovals) { (seq, reason) -> "seq $seq: ${inert(reason)}" }
    section(out, "approvals rejected on arrival", s.rejectedApprovals) { r ->
      "seq ${r.seq} on ${inert(r.gateId.orEmpty())} nonce ${inert(r.nonce.orEmpty())}: ${inert(r.reason)}"
    }
    section(out, "attempts dropped on a nonce", s.droppedOnNonce) { d ->
      "seq ${d.seq} on ${inert(d.gateId.orEmpty())} nonce ${inert(d.nonce.orEmpty())}: ${d.duplicates} duplicate(s), " +
        "${d.rejectedOverAllowance + d.rejectedOverAllowanceUnlisted} rejected over the allowance, " +
        "${d.wrongDigest} on a wrong digest, ${d.oversized} oversized"
    }
    val notOpen = s.droppedNotOpen
    out.println("attempts naming no open nonce: ${notOpen.sumOf { it.notOpen }} in ${notOpen.size} row(s)")
    section(out, "escalations", s.escalations) { inert(it) }
    section(out, "mis-origined entries", s.misOriginedEntries) { (seq, kind) -> "seq $seq: ${inert(kind)}" }
    section(out, "malformed cognition turns", s.malformedCognition) { (seq, reason) -> "seq $seq: ${inert(reason)}" }
  }

  private fun <T> section(out: PrintStream, title: String, items: List<T>, line: (T) -> String) {
    out.println("$title (${items.size}):")
    items.forEach { out.println("  ${line(it)}") }
  }

  private fun usage(err: PrintStream, why: String): Int {
    err.println("lead_status: $why")
    err.println("usage: lead_status --journal DIR --component ID --spec F --root PUB")
    return 2
  }

  private val FLAGS = setOf("--journal", "--component", "--spec", "--root")
}
