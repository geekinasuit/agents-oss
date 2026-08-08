package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodCompletion
import com.geekinasuit.agency.pod.PodSpawned
import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.shared.journal.ArgMap
import com.geekinasuit.agency.shared.journal.ChainBrokenException
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.JournalVersionException
import com.geekinasuit.agency.shared.journal.KIND_GATE_RELEASED
// LeadFoldException is in this package (LeadState.kt)
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.SqliteStore
import com.geekinasuit.agency.shared.journal.fold
import java.io.File
import kotlin.system.exitProcess
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Lead scenario fixture — the journal_fixture pattern applied to
 * the whole daemon: one binary, subcommands = lifecycle steps, process death simulated by
 * DETERMINISTIC fault injection (exit 42 at a named instruction boundary inside the
 * daemon, via the [FaultInjector] seam) rather than kill timing. Recovery is always a
 * fresh process adopting by re-folding. LeadScenarioTest spawns this from runfiles and
 * asserts on folded state + effect logs — never on timing.
 *
 * Subcommands (each opens the store exclusively — sequential processes, single writer):
 *   advance      — adopt + drive until quiescent (blocked on a gate, a held pod, or done)
 *   release      — the authorization act: append a release for a pending gate by kind
 *                  ([AuthStub]); `--stale-digest` and `--forge-origin` are the red paths
 *   replay       — print the canonical folded-state line assertions read
 *
 * Exit codes: 0 ok · 42 injected fault death · 4 version gate refused · 5 chain broken ·
 * 6 lead fold failed (malformed payload on a known kind — classified, seq+kind named).
 */
object LeadFixture {

  @JvmStatic
  fun main(args: Array<String>) {
    val a = ArgMap(args)
    val dir = a.req("dir")
    val store = SqliteStore(dir, componentId = "lead")
    try {
      when (a.subcommand) {
        "advance" -> advance(store, dir, a)
        "release" -> release(store, a)
        "replay" -> replay(store, dir)
        else -> {
          System.err.println("unknown subcommand '${a.subcommand}'")
          exitProcess(2)
        }
      }
    } catch (e: JournalVersionException) {
      System.err.println("VERSION-GATE ${e.message}")
      exitProcess(4)
    } catch (e: ChainBrokenException) {
      System.err.println("CHAIN-BROKEN ${e.message}")
      exitProcess(5)
    } catch (e: LeadFoldException) {
      System.err.println("LEAD-FOLD-FAILED ${e.message}")
      exitProcess(6)
    } finally {
      store.close()
    }
  }

  private fun advance(store: SqliteStore, dir: String, a: ArgMap) {
    // Red path (bind-once): obstruct the lead's OWN bound-artifact store by planting a
    // plain FILE where the artifacts-bound/ directory must go — every bound write then
    // fails, the pod is abandoned (bound-write-failed) with no result row, and the
    // re-propose loop runs into the lead-tier attempt cap: the advance goes quiescent on a
    // visible escalation instead of burning spawns. The test clears the obstruction and
    // advances again (a fresh process = a fresh attempt budget) to prove convergence.
    if (a.has("unwritable-bound")) {
      val obstruction = File(dir, "artifacts-bound")
      if (!obstruction.exists()) obstruction.writeText("obstruction: plain file, not a dir\n")
    }
    val runner: PodRunner =
      when {
        a.has("tamper-artifact") -> TamperingPodRunner()
        else -> FakePodRunner(holdCompletions = a.has("hold-pods"))
      }
    val daemon =
      LeadDaemon(
        store = store,
        cognition = ScriptedCognition(),
        podRunner = runner,
        podSpec = PodSpec.fixture(),
        ticketSource = FileTicketSource(File(a.req("ticket-file"))),
        workdir = File(dir),
        effects = EffectReceiver(dir),
        faults = ExitFault(a.opt("fault")),
        dedupEffects = !a.has("no-dedup"),
      )
    val folded = daemon.driveUntilQuiescent()
    println(
      "ADVANCE phase=${folded.lead.phase} ticket=${folded.lead.currentTicket} " +
        "pending=${folded.lead.pendingGates.map { it.gateId }} done=${folded.lead.doneTickets}"
    )
  }

  /**
   * The approval act, store-level (the daemon is not running between advances). Default:
   * a faithful release of the pending gate of `--gate-kind` — auth origin, the digest the
   * gate was opened on. Red paths: `--stale-digest` keeps auth origin but names a wrong
   * digest; `--forge-origin cognition|substrate` forges the provenance instead.
   */
  private fun release(store: SqliteStore, a: ArgMap) {
    val gateKind = a.req("gate-kind")
    val lead = leadFold(store.readAll())
    val gate =
      lead.pendingGates.firstOrNull { it.gateKind == gateKind }
        ?: run {
          System.err.println("no pending gate of kind '$gateKind'")
          exitProcess(2)
        }
    val forgeOrigin = a.opt("forge-origin")
    val digest = if (a.has("stale-digest")) "0".repeat(64) else gate.payloadDigest
    if (forgeOrigin != null) {
      val origin =
        when (forgeOrigin) {
          "cognition" -> ORIGIN_COGNITION
          "substrate" -> ORIGIN_SUBSTRATE
          else -> {
            System.err.println("unknown --forge-origin '$forgeOrigin'")
            exitProcess(2)
          }
        }
      store.append(
        KIND_GATE_RELEASED,
        buildJsonObject {
          put("gateId", gate.gateId)
          put("payloadDigest", digest)
        },
        origin = origin,
      )
      println("RELEASE gate=${gate.gateId} FORGED origin=$origin")
    } else {
      AuthStub.appendRelease(store, gate.gateId, digest)
      println("RELEASE gate=${gate.gateId} digest=${digest.take(12)} stale=${a.has("stale-digest")}")
    }
  }

  private fun replay(store: SqliteStore, dir: String) {
    val entries = store.readAll()
    val lead = leadFold(entries)
    val shared = fold(entries)
    val effectLines =
      lead.doneTickets.plus(listOfNotNull(lead.currentTicket)).associateWith {
        EffectReceiver(dir).lineCountFor("apply-commit:$it")
      }
    println(
      "REPLAY phase=${lead.phase} ticket=${lead.currentTicket} runs=${lead.runsStarted} " +
        "pending=${lead.pendingGates.map { it.gateId }.sorted()} " +
        "released=${lead.releasedGates.sorted()} stale=${lead.staleReleases.size} " +
        "rejected=${shared.rejectedGateReleases.size} escalations=${lead.escalations.size} " +
        "activePods=${lead.activePods.size} doneTickets=${lead.doneTickets} " +
        "pendingEffects=${shared.pendingEffectKeys} effects=$effectLines"
    )
  }
}

/** Exit-42 fault injection at a named daemon boundary (fixture-grade). */
class ExitFault(private val faultAt: String?) : FaultInjector {
  override fun at(boundary: String) {
    if (faultAt != null && boundary == faultAt) {
      System.err.println("FAULT injected: dying at boundary '$boundary'")
      exitProcess(42)
    }
  }
}

/**
 * A pod that writes a real artifact but reports a WRONG digest — the lying-pod red path at
 * the fixture level: the daemon recomputes from the completion SNAPSHOT at result-record
 * time (bind-once), escalates the mismatch, and binds the recomputed digest — so the
 * pipeline still completes on real content, with the lie on the record. Distinct pod ids
 * per spawn: podId names the bound-artifact object, so two tampering pods (planner, then
 * executor) must not collide in the bound store.
 */
class TamperingPodRunner : PodRunner {
  private var spawnCount = 0

  override fun spawn(
    spec: PodSpec,
    taskRef: String,
    workdir: File,
    artifactPath: String,
    onComplete: (PodCompletion) -> Unit,
  ): PodSpawned {
    val podId = "pod-tamper-${++spawnCount}"
    val content =
      if (taskRef.startsWith("plan:")) "tampered plan for $taskRef\n"
      else "{\"fileset\":[\"x\"],\"summary\":\"tampered $taskRef\"}\n"
    File(artifactPath).also { it.parentFile?.mkdirs() }.writeText(content)
    onComplete(
      PodCompletion(podId, artifactPath, "0".repeat(64), 0.0, content.toByteArray()) // the lie
    )
    return PodSpawned(podId, "sess-tamper-$spawnCount")
  }
}
