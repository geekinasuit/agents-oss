package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodCompletion
import com.geekinasuit.agency.pod.PodEvent
import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.pod.sha256HexBytes
import com.geekinasuit.agency.shared.journal.ArmedTimer
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.JournalState
import com.geekinasuit.agency.shared.journal.JournalStore
import com.geekinasuit.agency.shared.journal.ORIGIN_COGNITION
import com.geekinasuit.agency.shared.journal.ORIGIN_SUBSTRATE
import com.geekinasuit.agency.shared.journal.fold
import java.io.File
import java.util.concurrent.LinkedBlockingQueue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * The lead daemon: a model-free durable substrate HOSTING an event-driven,
 * model-bearing cognition loop. One instance owns one workspace and one
 * journal chain (`agency/lead/main/v3`); everything it knows is derived by
 * folding that chain — kill it at any instruction boundary and a fresh process
 * adopts by re-folding.
 *
 * THREADING (the single-writer discipline made concrete): one PROCESS writes the store,
 * and within it every store op is serialized by the store's internal lock. ARRIVAL facts
 * — injected mail, the auth stub's releases — are journaled AT THE ACCEPT BOUNDARY by the
 * accepting thread (journal-then-doorbell, AGENCY-021): the entry is durable before
 * the inject call returns, and the queued [WakeEvent] is only a doorbell. DERIVED facts —
 * everything the pipeline concludes — are journaled by the loop thread, which refolds,
 * advances the mechanical pipeline, consults cognition once per wake, and executes its
 * proposals. The queue carries NO durable state: a fact journaled but not yet woken (a
 * crash in that window) is swept by the next adopt, whose Adopted wake re-folds and acts
 * on everything undelivered or unacted — so an accepted event can no longer be lost
 * silently. Timer fires and pod completions remain enqueue-only, journaled on the loop
 * thread: a lost timer doorbell re-derives (armed and not fired → re-armed at adopt), and
 * a pod completion must never be journaled ahead of the loop's own POD_SPAWNED append
 * (see [injectPodCompletion]). Between wakes the loop BLOCKS on the queue: idle is
 * structural, and a model-backed strategy costs nothing while nothing happens.
 *
 * DIVISION OF LABOR: the substrate mechanically advances what needs no judgment —
 * claiming an offered ticket, recording a finished pod's artifact, proposing the commit
 * manifest from the execute result, driving the post-approval commit effect
 * exactly-once, marking mail delivered. Cognition supplies judgment as typed proposals
 * (pod spawns, gate opens, status, escalation), journaled with origin = cognition before
 * execution. Gate releases enter only through the authorization seam ([AuthStub] until
 * the real ceremony) and are honored by the folds' provenance + digest checks, never by
 * this class's control flow.
 */
class LeadDaemon(
  private val store: JournalStore,
  private val cognition: CognitionStrategy,
  private val podRunner: PodRunner,
  /** The pod profile this lead spawns — LEAD-OWNED config (substrate-constructed;
   * cognition proposes a task, never a descriptor). REQUIRED, no default: which profile a
   * daemon launches is a deliberate configuration act, and a silently-defaulted profile
   * would be a footgun in either direction. Fence-checked at the spawn site. */
  private val podSpec: PodSpec,
  private val ticketSource: TicketSource,
  private val workdir: File,
  private val effects: EffectReceiver,
  private val timers: TimerService = TimerService.NOOP,
  private val faults: FaultInjector = FaultInjector.NONE,
  private val dedupEffects: Boolean = true,
  private val capabilityDesc: String = "scripted/none",
  private val leadVersion: String = "dev",
  /** Backoff between malformed-output retries within one wake, multiplied by the attempt
   * number. Blocks the single loop thread by design — the wake is not finished, and a
   * second concurrent cognition call would break the single-writer rule. */
  private val cognitionRetryBackoffMs: Long = 500,
  /** Cognition calls allowed per wake before the wake escalates and idles. Whether a
   * retry can help at all is a property of the STRATEGY, not of the substrate: a strategy
   * that samples deterministically re-emits the same near-miss, so retrying it only doubles
   * the bill. Such a strategy is wired with 1. */
  private val maxCognitionAttempts: Int = 2,
) {

  init {
    // A cap below 1 would skip cognition entirely and then escalate claiming it had asked,
    // which is a silently model-free daemon reporting a model failure. The ceiling is the
    // same guard from the other side: every attempt blocks the single loop thread for a
    // whole harness turn plus its backoff, and shutdown only takes effect between wakes, so
    // a large value is not "more thorough" — it is a daemon that stops answering. Past a
    // handful of tries a strategy is not being re-sampled, it is being hammered for a shape
    // it cannot produce, which is what the escalation exists to report.
    require(maxCognitionAttempts in 1..MAX_COGNITION_ATTEMPTS_CEILING) {
      "maxCognitionAttempts must be in 1..$MAX_COGNITION_ATTEMPTS_CEILING, " +
        "was $maxCognitionAttempts"
    }
  }

  sealed interface WakeEvent {
    data object Adopted : WakeEvent

    data class MailInject(val message: String) : WakeEvent

    data class TimerDue(val timerId: String) : WakeEvent

    data class PodDone(val completion: PodCompletion) : WakeEvent

    /** A terminal engine disposition for [podId] (preflight/artifact refusal, restart
     * exhaustion, wall-clock kill): the pod is dead and no completion will arrive. The
     * loop reacts by abandoning it from folded state — see [injectPodEvent]. */
    data class PodDisposed(val podId: String, val disposition: String) : WakeEvent

    data class AuthRelease(val gateId: String, val payloadDigest: String) : WakeEvent

    data object Shutdown : WakeEvent
  }

  private val queue = LinkedBlockingQueue<WakeEvent>()

  /** Structural single-run guard: the single-writer/single-loop-thread rule is enforced,
   * not just documented — a second concurrent run mode throws instead of racing the store. */
  private val active = java.util.concurrent.atomic.AtomicBoolean(false)

  /**
   * Process-scoped FAILURE-abandon counts by taskRef — the lead-tier mirror of the
   * engine's per-pod restart cap, one tier up. Terminal dispositions and bound-store
   * failures abandon a pod, and the evidence-based playbook re-proposes; now that those
   * dispositions WAKE the loop, a persistent fault would otherwise livelock:
   * spawn → die → abandon → re-propose, as fast as the engine can refuse. After
   * [MAX_TASK_ATTEMPTS_PER_PROCESS] failure-abandons for one taskRef the spawn site
   * refuses further attempts and escalates. Deliberately in-memory backpressure, NOT
   * folded state: every abandon is individually journaled (the record stays complete),
   * and a supervisor restart is the reset act — matching the loop's stop-for-restart
   * recovery model, and giving "operator fixed the fault, restarted the daemon" a clean
   * fresh budget without an acknowledgment surface (that seam belongs to the
   * authorization ceremony). Housekeeping
   * abandons (lead-restart respawn, orphaned spawn intents) never count: they are adopt
   * acting on a healthy record, not evidence the task keeps failing. Loop-thread only.
   */
  private val failureAbandons = mutableMapOf<String, Int>()

  private fun noteFailureAbandon(taskRef: String) {
    failureAbandons[taskRef] = (failureAbandons[taskRef] ?: 0) + 1
  }

  /** taskRefs whose cap refusal has already been escalated — loop-thread only, process-
   * scoped exactly like [failureAbandons] (one restart resets both together). The refusal
   * itself replays on EVERY proposing wake, deterministically from the counts; the
   * escalation row announcing the wedge is appended once per taskRef, because an
   * identical row per wake would accrete journal (and every future re-fold's memory)
   * without adding information. */
  private val capRefusalsEscalated = mutableSetOf<String>()

  /** taskRefs whose redundant-respawn refusal has already been escalated — the
   * success-side sibling of [capRefusalsEscalated], same scope and same reasoning: the
   * refusal itself replays on every proposing wake, deterministically from folded
   * evidence alone; the row announcing that the strategy keeps re-proposing completed
   * work is appended once per taskRef. Loop-thread only. */
  private val redundantSpawnEscalated = mutableSetOf<String>()

  // ---- external input surface (safe from any thread) ----

  /**
   * Accept mail: journal-then-doorbell (AGENCY-021). The mailbox-appended entry is
   * durable before this returns, so an accepted message can no longer be lost silently to
   * a crash before its wake — the fold's undelivered set is the real work queue, and the
   * next adopt sweeps anything whose doorbell died with the process. A failed append
   * throws to the caller: accept means durable, so failure is refusal, never a silent
   * maybe. As a bonus the entry now records true arrival order, not wake order — the
   * auditable record AGENCY-021's batching design needs.
   */
  fun injectMail(message: String) {
    // Admission bound BEFORE the append: oversize is refused whole —
    // thrown to the caller, nothing journaled — never truncated, because accept means
    // durable AND intact. Substrate admission control in the AGENCY-021 direction; the
    // real mailbox surface revisits the bound with the channel model.
    require(message.length <= MAX_ACCEPTED_MAIL_CHARS) {
      "mail refused: ${message.length} chars exceeds the accept bound of $MAX_ACCEPTED_MAIL_CHARS"
    }
    store.append(
      "mailbox-appended",
      buildJsonObject { put("message", message) },
      origin = ORIGIN_SUBSTRATE,
    )
    // offer, not put: the queue is unbounded so this never blocks, and unlike put it does
    // not throw on a pre-interrupted caller — a throw AFTER the append committed would be
    // a false refusal of a durably-accepted event (retry → duplicate), and in a live
    // daemon the fact would sit doorbell-less until an unrelated wake.
    queue.offer(WakeEvent.MailInject(message))
  }

  /**
   * The in-process half of [AuthStub]: approval while the daemon runs (the real ceremony
   * replaces this). Journal-then-ack (AGENCY-021): the release is appended — authorization
   * provenance, via the same [AuthStub.appendRelease] the store-level surface uses —
   * before this returns; the queued wake is only a doorbell, and a crash after accept no
   * longer loses the approval (the next adopt re-folds it and the pipeline advances). The
   * folds' teeth are unchanged: provenance + digest binding decide whether the release is
   * honored, and a release accepted before its gate opened lands VISIBLY in
   * [LeadState.staleReleases] — re-approving remains safe.
   */
  fun injectAuthRelease(gateId: String, payloadDigest: String) {
    AuthStub.appendRelease(store, gateId, payloadDigest)
    faults.at("after-gate-released")
    // offer, not put — same false-refusal reasoning as injectMail's doorbell.
    queue.offer(WakeEvent.AuthRelease(gateId, payloadDigest))
  }

  /** Timer fires stay enqueue-only (no accept-append, deliberately): a timer is
   * self-scheduled re-derivable state — armed and not fired re-arms at adopt — so a lost
   * doorbell loses nothing, and "timer-fired" keeps meaning CONSUMED by the loop, which
   * is what the duplicate-fire guard in [journalEventFacts] keys on. */
  fun injectTimerDue(timerId: String) {
    queue.put(WakeEvent.TimerDue(timerId))
  }

  /** Pod completions stay enqueue-only (no accept-append, deliberately): fake pods
   * complete synchronously INSIDE spawn — before the loop journals POD_SPAWNED — so an
   * accept-side append would write POD_RESULT_RECORDED ahead of its pod's spawn record
   * and the fold would drop it. Loss here is already non-silent: adopt abandons the
   * still-active pod visibly and the playbook re-proposes. Real-pod completion
   * durability (artifact on disk + --resume re-attach) is later work. */
  fun injectPodCompletion(completion: PodCompletion) {
    queue.put(WakeEvent.PodDone(completion))
  }

  /**
   * Accept a pod-engine supervisory fact and JOURNAL IT — ask/decision durability,
   * refusal visibility, restart and deadline visibility. Accept-boundary
   * append on whichever thread the engine reports from — usually its supervisor pool, but
   * the FIRST attempt's facts arrive on the caller's (the loop) thread, because the first
   * handshake is synchronous by design. Same journal-then-return discipline mail and auth
   * releases use (AGENCY-021): these are ARRIVALS from outside the pipeline, and a fact
   * that only reached a callback is a fact the record does not have.
   *
   * A FAILED append still throws here, per the accept convention — but the engine treats
   * this seam as fallible and defends every call, so a refusal costs a journal row, never a
   * live untrusted process or an undelivered completion. The row-side answer is
   * AGENCY-028: the append stays synchronous (a queue would re-open the exact
   * accepted-but-not-durable window AGENCY-021 closed), and the counters the engine
   * keeps for refused reports are READ — [handleWake] drains [PodRunner.drainHealthFaults]
   * every wake and escalates each fault, so a record with holes announces itself.
   *
   * NON-terminal events are deliberately not doorbells: an ask, a decision, a restart
   * attempt never advances the pipeline, so no wake is owed. TERMINAL dispositions
   * (preflight/artifact refusal, restart exhaustion, wall-clock kill) DO enqueue a
   * [WakeEvent.PodDisposed] (the reaction now that a real engine constructs real
   * corpses): the pod is dead and no completion will ever arrive, so waiting for the next
   * adopt — the adopt-only shape — wedges the pipeline on a corpse for the daemon's lifetime.
   * The loop abandons it from FOLDED state on its own thread (ordering: the spawning wake
   * journals POD_SPAWNED before the queue hands the loop this doorbell, so the abandon
   * always finds its spawn record).
   *
   * Terminal dispositions ALSO escalate: a refused
   * artifact or an exhausted restart cap must be legible without reading pod-event rows.
   * The doorbell is offered BEFORE that escalation append: the POD_EVENT row alone is the
   * durable fact journal-then-doorbell requires (the disposition derives from the event
   * type, and the escalation row is a legibility duplicate of it), so a refused escalation
   * append — any append may throw, per the accept convention — costs a journal row, never
   * the reaction. [PodEvent.CompletionDiscarded] deliberately does not escalate — it is
   * the downstream consequence of a terminal event that already escalated, and escalating
   * both reports one incident twice.
   */
  fun injectPodEvent(event: PodEvent) {
    store.append(LeadKinds.POD_EVENT, podEventPayload(event), origin = ORIGIN_SUBSTRATE)
    terminalDisposition(event)?.let { disposition ->
      // offer, not put — same false-refusal reasoning as injectMail's doorbell.
      queue.offer(WakeEvent.PodDisposed(event.podId, disposition))
    }
    podEventEscalation(event)?.let { escalate(it) }
  }

  /** The dispositions that end a pod at the engine with NO completion to follow — the set
   * [WakeEvent.PodDisposed] reacts to. [PodEvent.GroupKillDegraded] is excluded (a
   * degraded kill is a fact about HOW a pod died, not a death); so is
   * [PodEvent.CompletionDiscarded] (its pod was already claimed by one of these). */
  private fun terminalDisposition(e: PodEvent): String? =
    when (e) {
      is PodEvent.PreflightRefused -> "preflight-refused"
      is PodEvent.ArtifactRefused -> "artifact-refused"
      is PodEvent.RestartsExhausted -> "restarts-exhausted"
      is PodEvent.DeadlineKilled -> "deadline-killed"
      is PodEvent.SessionEstablished,
      is PodEvent.PermissionAsked,
      is PodEvent.PermissionDecided,
      is PodEvent.RestartAttempted,
      is PodEvent.CompletionDiscarded,
      is PodEvent.GroupKillDegraded -> null
    }

  fun shutdown() {
    queue.put(WakeEvent.Shutdown)
  }

  // ---- run modes ----

  /** Adopt, then block on the wake queue until [shutdown]. The production shape. */
  fun runLoop() {
    check(active.compareAndSet(false, true)) { "lead daemon is already running (single loop rule)" }
    try {
      adopt()
      while (true) {
        val ev = queue.take()
        if (ev is WakeEvent.Shutdown) return
        try {
          handleWake(ev)
        } catch (t: Throwable) {
          // A wake handler threw (a pod launcher failing mid-spawn, a transient store error,
          // an unexpected fold state). The recovery model is already "kill at any
          // boundary → a fresh process re-folds and adopts"; the one thing missing on this
          // path was VISIBILITY — the loop would die silently. Journal the
          // fault, then rethrow so the loop stops for a supervisor to restart. adopt() on the
          // next process abandons any spawn intent orphaned by the half-finished wake
          // (it becomes a visible POD_SPAWN_ABANDONED, re-proposed cleanly,
          // not a silent second launch) and re-drives pending effects — exactly what every
          // other kill boundary does. We deliberately do NOT self-heal in place: re-adopting
          // here would re-enqueue Adopted and, on a persistent fault, spin the full pipeline
          // (and real model turns) in a tight loop.
          try {
            escalate(
              "wake-fault on ${ev::class.simpleName}: " +
                (t.message ?: t::class.qualifiedName ?: "unknown") +
                " — stopping loop for restart"
            )
          } catch (journalFailure: Throwable) {
            // The store itself is unwritable, so the fault can't be recorded. Attach it and
            // let the ORIGINAL cause propagate — a dead journal has no honest recovery, and
            // the triggering fault is the one worth surfacing.
            t.addSuppressed(journalFailure)
          }
          throw t
        }
      }
    } finally {
      active.set(false)
    }
  }

  /**
   * Adopt, then process events until the queue drains (fixture/test shape — fake pod
   * completions arrive through the queue, so "drained" means the pipeline is blocked on
   * outside input: a pending gate, a held pod, or nothing to do).
   */
  fun driveUntilQuiescent(): Folded {
    check(active.compareAndSet(false, true)) { "lead daemon is already running (single loop rule)" }
    try {
      adopt()
      while (true) {
        val ev = queue.poll() ?: break
        if (ev is WakeEvent.Shutdown) break
        handleWake(ev)
      }
      return refold()
    } finally {
      active.set(false)
    }
  }

  data class Folded(val entriesSize: Int, val shared: JournalState, val lead: LeadState)

  fun refold(): Folded {
    val entries = store.readAll()
    return Folded(entries.size, fold(entries), leadFold(entries))
  }

  // ---- adopt ----

  private fun adopt() {
    val folded = refold() // readAll verifies the chain; both folds derive state
    faults.at("mid-adopt")
    for (t in folded.shared.pendingTimers) {
      timers.arm(t) { id -> queue.put(WakeEvent.TimerDue(id)) }
    }
    redrivePendingEffects(folded.shared)
    respawnActivePods(folded.lead)
    abandonOrphanedSpawnIntents(folded.lead)
    store.append(
      LeadKinds.RUN_STARTED,
      buildJsonObject {
        put("workspacePath", workdir.absolutePath)
        put("capabilityDesc", capabilityDesc)
        put("leadVersion", leadVersion)
        put("cognition", cognition.name)
        put("adoptedFromSeq", folded.entriesSize.toLong())
      },
      origin = ORIGIN_SUBSTRATE,
    )
    queue.put(WakeEvent.Adopted)
  }

  /** Exactly-once inheritance from the journal layer: re-fire every intent without a done entry; the
   * receiver dedups on the idempotency key (attempt 2 mirrors the journal fixture). */
  private fun redrivePendingEffects(shared: JournalState) {
    for (key in shared.pendingEffectKeys) {
      val message = shared.intents[key]?.strOrNull("message") ?: key
      val result = effects.fire(key, message, dedupEffects)
      store.append(
        "effect-done",
        buildJsonObject {
          put("key", key)
          put("attempt", 2)
          put("result", result.toString())
        },
        origin = ORIGIN_SUBSTRATE,
      )
    }
  }

  /** Fake pods re-spawn, not resume — abandon the in-flight record visibly; the
   * playbook re-proposes from the missing evidence. Real re-attach (--resume) is later work. */
  private fun respawnActivePods(lead: LeadState) {
    for (pod in lead.activePods) {
      store.append(
        LeadKinds.POD_ABANDONED,
        buildJsonObject {
          put("podId", pod.podId)
          put("reason", "lead-restart")
        },
        origin = ORIGIN_SUBSTRATE,
      )
    }
  }

  /**
   * Dispose of spawn intents orphaned by a kill between POD_SPAWN_INTENDED and
   * POD_SPAWNED. The pod may or may not have started — the substrate cannot know —
   * so it records the intent abandoned (which surfaces a visible escalation) and lets the
   * evidence-based playbook re-propose. Reclaiming a real orphaned OS process is the
   * engine's kill-tree job; this keeps the substrate's OWN record honest after any kill in
   * that window, regardless of pod realism (a record-integrity obligation: a fresh
   * re-fold must not report "nothing happened" when a spawn was in flight).
   */
  private fun abandonOrphanedSpawnIntents(lead: LeadState) {
    for ((taskRef, _) in lead.pendingSpawnIntents) {
      store.append(
        LeadKinds.POD_SPAWN_ABANDONED,
        buildJsonObject {
          put("taskRef", taskRef)
          put(
            "reason",
            "spawn intent orphaned at restart (pod may or may not have started; re-proposing)",
          )
        },
        origin = ORIGIN_SUBSTRATE,
      )
    }
  }

  // ---- one wake ----

  private fun handleWake(ev: WakeEvent) {
    // AGENCY-028: the engine and bridge COUNT reports their event
    // sink refused; a counter nobody reads is the same silence with extra steps. Drain the
    // NEW faults every wake and escalate each — the journal's holes announce themselves at
    // the next wake (bounded staleness; an idle daemon also generates no reportable facts
    // beyond what its own last wake swept). Runners without health surfaces return empty.
    for (fault in podRunner.drainHealthFaults()) escalate(fault)
    journalEventFacts(ev)
    var folded = refold()

    // Mechanical pipeline to fixpoint: each pass appends at most one batch of facts.
    var guard = 0
    while (mechanicalPass(folded)) {
      folded = refold()
      check(++guard < 25) { "mechanical pipeline did not reach fixpoint" }
    }

    // The decision and the state it is executed against come from ONE fold, even when a
    // retry re-folded mid-wake: executing a proposal against a state cognition never saw
    // would judge it on different evidence than the judgment was made on.
    //
    // No decision at all is not the same as a decision to idle, and the difference is the
    // mail. An idle turn was SHOWN this wake's mail and chose not to act, so retiring it is
    // right. A wake whose cognition never produced usable output chose nothing — marking its
    // mail delivered would retire a work item on behalf of a turn that never judged it, and
    // the delivered set has no inverse, so it would never be offered again.
    val decision = decideWithRetry(reasonOf(ev), folded) ?: return
    val out = decision.out
    // Journal every decision that either proposes or carries strategy provenance (a
    // model-backed idle turn has meta: its sessionId and cost belong in the record, and
    // the spend fold depends on it). A scripted idle carries neither — no entry.
    if (out.proposals.isNotEmpty() || out.meta.isNotEmpty()) {
      journalCognitionOutput(out)
    }
    if (out.proposals.isNotEmpty()) {
      executeProposals(out, decision.folded.lead)
    }
    markMailDelivered(decision.folded.shared.undeliveredMail)
  }

  /** A wake's cognition result together with the fold it was decided on — see
   * [decideWithRetry], which may re-fold between attempts. */
  private class Decision(val out: CognitionOutput, val folded: Folded)

  /**
   * One wake's cognition call, retried a bounded number of times while the output is
   * unusable. Every attempt is journaled BEFORE the next one runs: an unlogged retry
   * would hide both the model's degradation rate and the spend each attempt costs, and
   * "does not silently retry" is the property that makes a small model's near-misses
   * visible instead of merely slow.
   *
   * On exhaustion the wake escalates and this returns null, which the caller treats as "this
   * wake does nothing" rather than as an idle decision. It does NOT fall through to executing
   * the last attempt's proposals — a batch that failed structural validation is untrusted
   * input — and it leaves the wake's mail undelivered, so the next wake still offers it. A
   * wake that does nothing is always a safe outcome here (the next wake re-derives from
   * evidence, exactly as the playbook does after any abandoned attempt); a wake that quietly
   * drains its own work queue without judging it is not.
   *
   * A returned [Decision] carries the fold its winning attempt actually saw, not merely the
   * output: a retry re-folds, and the caller must execute and mark mail against that state.
   */
  private fun decideWithRetry(reason: WakeReason, initial: Folded): Decision? {
    var folded = initial
    for (attempt in 1..maxCognitionAttempts) {
      val wc = WakeContext(reason, folded.lead, folded.shared, folded.shared.undeliveredMail)
      val out = cognition.decide(wc)
      if (out.malformed == null) return Decision(out, folded)
      journalMalformedCognition(out, attempt)
      if (attempt < maxCognitionAttempts) {
        Thread.sleep(cognitionRetryBackoffMs * attempt)
        // The failed attempt was billed, and that cost is in the journal now. A retry handed
        // the pre-attempt state would re-read a spend total that predates its own predecessor,
        // letting one wake bill past a strategy's budget cap once per attempt.
        folded = refold()
      }
    }
    escalate(
      "cognition produced unusable output $maxCognitionAttempts time(s) this wake; " +
        "the wake does nothing — nothing it proposed was executed, and this wake's mail " +
        "stays undelivered for the next one"
    )
    return null
  }

  /**
   * The malformed-turn row: SUBSTRATE origin, carrying our classification and the call's own
   * provenance (model, session, cost) — never the model's text. There is no decision in a
   * malformed turn to attribute to cognition, and recording the raw output here would put
   * unbounded model-controlled content into a substrate-authored row.
   */
  private fun journalMalformedCognition(out: CognitionOutput, attempt: Int) {
    store.append(
      LeadKinds.COGNITION_MALFORMED,
      buildJsonObject {
        // Provenance first, our classification last: a meta key colliding with one of ours
        // must not be able to overwrite the substrate's own account of what happened.
        for ((k, v) in out.meta) put(k, v.take(MAX_JOURNALED_STRING))
        put("strategy", cognition.name)
        put("reason", (out.malformed ?: "unclassified").take(MAX_JOURNALED_STRING))
        put("attempt", attempt)
      },
      origin = ORIGIN_SUBSTRATE,
    )
  }

  private fun journalEventFacts(ev: WakeEvent) {
    when (ev) {
      // Mail + auth releases are ARRIVAL facts, journaled at the accept boundary
      // (journal-then-doorbell, AGENCY-021); their tokens are doorbells only. By the
      // time a token wakes the loop, an earlier wake may already have swept the fact —
      // the refold in handleWake, not the token, decides what still needs attention.
      is WakeEvent.MailInject, is WakeEvent.AuthRelease -> Unit
      is WakeEvent.TimerDue -> {
        val shared = refold().shared
        if (ev.timerId in shared.armedTimers && ev.timerId !in shared.firedTimers) {
          store.append(
            "timer-fired",
            buildJsonObject { put("id", ev.timerId) },
            origin = ORIGIN_SUBSTRATE,
          )
        }
      }
      is WakeEvent.PodDone -> {
        val c = ev.completion
        // Runner-supplied completion fields are semi-trusted infrastructure input (the
        // engine parses them out of adapter output): strings are bounded like every other
        // externally-fed journaled value, and the cost is journaled only when finite and
        // non-negative. A non-finite Double would serialize as a
        // literal NaN/Infinity token — MALFORMED JSON committed irrevocably to the
        // append-only chain — and a negative cost is nonsense; both are journaled as
        // UNMEASURED (field absent) with the rejection escalated visibly, never recorded.
        val cost = c.costUsd?.takeIf { it.isFinite() && it >= 0.0 }
        if (c.costUsd != null && cost == null) {
          escalate(
            "pod-completion costUsd rejected for pod '${c.podId.take(80)}': ${c.costUsd} " +
              "is non-finite or negative — journaling the result as unmeasured"
          )
        }
        // BIND-ONCE: the digest the record binds is recomputed HERE from the
        // snapshot the engine's single disciplined read produced — never from a re-read of
        // the pod's path (a second read is the swap window the whole discipline closes).
        // A runner whose self-reported digest disagrees with its own bytes is escalated
        // and OVERRIDDEN: gates bind to the bytes as they exist, not as described.
        val digest = sha256HexBytes(c.snapshot)
        if (digest != c.resultDigest) {
          escalate(
            "pod-completion digest mismatch for pod '${c.podId.take(80)}': runner reported " +
              "${c.resultDigest.take(16)}, snapshot hashes to ${digest.take(16)} — binding the recomputed digest"
          )
        }
        // Persist the snapshot to the LEAD's own bound-artifact store BEFORE the journal
        // row that references it (artifact-before-record: the record must never name a
        // path that does not exist). Named by podId — unique per pod, so a re-proposed
        // task never collides with an abandoned attempt's bytes. A failed write means the
        // result CANNOT be recorded (fail closed: no digest without a durable consumable
        // object); the pod is abandoned visibly and the playbook re-proposes. No fsync on
        // purpose: a host crash between this write and consumption is caught by the
        // mechanical pass's existence + integrity check, which abandons and re-proposes.
        val bound =
          try {
            writeBoundArtifact(c.podId, c.snapshot)
          } catch (e: java.io.IOException) {
            escalate(
              "bound-artifact write failed for pod '${c.podId.take(80)}': " +
                "${e.message?.take(200) ?: e::class.simpleName} — abandoning the pod (no result " +
                "without a durable bound copy); the playbook re-proposes"
            )
            refold().lead.pods[c.podId]?.let { noteFailureAbandon(it.taskRef) }
            store.append(
              LeadKinds.POD_ABANDONED,
              buildJsonObject {
                put("podId", c.podId.take(MAX_JOURNALED_STRING))
                put("reason", "bound-write-failed")
              },
              origin = ORIGIN_SUBSTRATE,
            )
            return
          }
        store.append(
          LeadKinds.POD_RESULT_RECORDED,
          buildJsonObject {
            put("podId", c.podId.take(MAX_JOURNALED_STRING))
            // The pod's write target, journaled as PROVENANCE only — never read again.
            put("artifactPath", c.artifactPath.take(MAX_JOURNALED_STRING))
            // The lead-owned immutable copy every downstream consumer uses.
            put("boundPath", bound.take(MAX_JOURNALED_STRING))
            put("resultDigest", digest)
            // null-not-zero: an unmeasured cost journals as ABSENT — the record must
            // distinguish "the transport surfaced no measurement" from a measured $0.
            cost?.let { put("costUsd", it) }
          },
          origin = ORIGIN_SUBSTRATE,
        )
        faults.at("after-pod-result")
      }
      is WakeEvent.PodDisposed -> {
        // The REACTION to a terminal engine disposition (see [injectPodEvent]): the
        // pod is dead at the engine — no completion will ever arrive — so waiting for the
        // next adopt to notice (the adopt-only shape) leaves the pipeline wedged on a corpse for
        // the daemon's whole lifetime. Abandon it NOW, on the loop thread, from folded
        // state: the pod must exist and still be active (a completion, an earlier abandon,
        // or adopt may have won — all fine, the POD_EVENT row already records the fact).
        val pod = refold().lead.pods[ev.podId]
        if (pod != null && pod.active) {
          noteFailureAbandon(pod.taskRef)
          store.append(
            LeadKinds.POD_ABANDONED,
            buildJsonObject {
              put("podId", ev.podId)
              put("reason", "engine-terminal: ${ev.disposition.take(200)}")
            },
            origin = ORIGIN_SUBSTRATE,
          )
        }
      }
      WakeEvent.Adopted, WakeEvent.Shutdown -> Unit
    }
  }

  /** Advance everything that needs no judgment. Returns true if anything was appended. */
  private fun mechanicalPass(folded: Folded): Boolean {
    val lead = folded.lead
    val shared = folded.shared

    // Claim an offered ticket when idle. The done-filter repeats here even though the
    // source receives the same set: the source is a seam an adopter implements, and a
    // completed ticket must stay completed regardless of what any implementation re-offers.
    if (lead.currentTicket == null) {
      val offered = ticketSource.next(lead.doneTickets.toSet())
      if (offered != null && offered !in lead.doneTickets) {
        // The ticket ref is UNTRUSTED input: a fixture
        // line today, a real ticket-index row later. It flows into this ticket's plan:/execute:
        // task refs, gate ids, and effect keys. Validate charset + length at the claim boundary
        // — ':' and '/' excluded so a ref can neither forge a task namespace (`plan:` prefix)
        // nor traverse a path — so a malformed ref is escalated visibly and NOT claimed, rather
        // than silently wedging every later plan/execute spawn against TASK_REF_RE. Returns
        // false (not true): the pass makes no progress on a bad ref instead of re-looping on it.
        if (!TICKET_REF_RE.matches(offered) || offered.length > MAX_TICKET_REF_LEN) {
          escalate("ticket claim rejected: malformed ticket ref '${offered.take(80)}' (charset/length)")
          return false
        }
        store.append(
          LeadKinds.TICKET_CLAIMED,
          buildJsonObject { put("ticketRef", offered) },
          origin = ORIGIN_SUBSTRATE,
        )
        faults.at("after-claim")
        store.append(LeadKinds.PLAN_REQUESTED, buildJsonObject {}, origin = ORIGIN_SUBSTRATE)
        faults.at("after-plan-requested")
        return true
      }
      return false
    }
    val ticket = lead.currentTicket

    // Kill-recovery for the claim window: death between ticket-claimed and plan-requested
    // leaves the phase at CLAIMED; finish the hop so the phase record stays honest.
    if (lead.phase == TicketPhase.CLAIMED) {
      store.append(LeadKinds.PLAN_REQUESTED, buildJsonObject {}, origin = ORIGIN_SUBSTRATE)
      faults.at("after-plan-requested")
      return true
    }

    // Record a finished planner pod's artifact as THE plan. Bind-once: the evidence
    // is the pod's BOUND copy — the lead-owned immutable object written from the engine's
    // single disciplined read — verified against the journaled digest before any gate
    // binds to it. The pod's own artifactPath is provenance only and is never read here.
    // A missing or integrity-failed bound copy abandons the pod, and the evidence-based
    // playbook re-proposes the work.
    if (lead.planArtifactSha == null) {
      val planner = lead.podFor("plan:$ticket")
      if (planner?.resultDigest != null) {
        val verified = verifiedBoundArtifact(planner) ?: return true // pod abandoned
        store.append(
          LeadKinds.PLAN_ARTIFACT_RECORDED,
          buildJsonObject {
            put("path", verified.boundPath)
            put("sha256", verified.digest)
          },
          origin = ORIGIN_SUBSTRATE,
        )
        faults.at("after-plan-recorded")
        return true
      }
    }

    // Propose the commit from a finished execute pod's manifest — same bound-copy rule.
    val planGateReleased =
      gateIdFor(GateKinds.PLAN_APPROVAL, ticket) in lead.releasedGates
    if (planGateReleased && lead.commitManifestDigest == null) {
      val executor = lead.podFor("execute:$ticket")
      if (executor?.resultDigest != null) {
        val verified = verifiedBoundArtifact(executor) ?: return true // pod abandoned
        store.append(
          LeadKinds.COMMIT_PROPOSED,
          buildJsonObject {
            put("manifestPath", verified.boundPath)
            put("manifestDigest", verified.digest)
          },
          origin = ORIGIN_SUBSTRATE,
        )
        faults.at("after-commit-proposed")
        return true
      }
    }

    // Commit approved → drive the apply-commit effect exactly-once, then finish the
    // ticket. Gate membership alone is NOT the precondition: the approved evidence must
    // exist — plan approved and manifest recorded — so a release for a gate that
    // somehow opened out of order can never fire an effect on absent evidence.
    val commitReleased =
      gateIdFor(GateKinds.COMMIT_APPROVAL, ticket) in lead.releasedGates &&
        planGateReleased &&
        lead.commitManifestDigest != null
    if (commitReleased) {
      val effectKey = "apply-commit:$ticket"
      if (effectKey !in shared.intents) {
        store.append(
          "effect-intent",
          buildJsonObject {
            put("message", "apply-commit ticket=$ticket manifest=${lead.commitManifestDigest}")
          },
          origin = ORIGIN_SUBSTRATE,
          idempotencyKey = effectKey,
        )
        faults.at("after-commit-intent")
        val result =
          effects.fire(
            effectKey,
            "apply-commit ticket=$ticket manifest=${lead.commitManifestDigest}",
            dedupEffects,
          )
        faults.at("after-commit-effect")
        store.append(
          "effect-done",
          buildJsonObject {
            put("key", effectKey)
            put("attempt", 1)
            put("result", result.toString())
          },
          origin = ORIGIN_SUBSTRATE,
        )
        return true
      }
      if (effectKey in shared.doneKeys) {
        store.append(
          LeadKinds.TICKET_DONE,
          buildJsonObject { put("ticketRef", ticket) },
          origin = ORIGIN_SUBSTRATE,
        )
        faults.at("after-ticket-done")
        return true
      }
      // intent exists but no done entry: adopt's re-drive owns that window
    }
    return false
  }

  /** A bound artifact that passed verification: the lead-owned path consumers use and the
   * digest gates bind to. */
  private data class VerifiedArtifact(val boundPath: String, val digest: String)

  /**
   * Verify a finished pod's BOUND artifact — the lead-owned immutable copy written at
   * result-record time from the engine's single disciplined read (bind-once). The
   * pod's own artifactPath is deliberately never touched here: re-reading the pod's path
   * after the digest was taken is the swap window the discipline exists to close.
   *
   * Missing bound copy (no boundPath recorded — a pre-bind-once row — or the file is gone:
   * host crash before the page flushed, external deletion) → the pod is abandoned (reason
   * journaled) and null returns; the playbook re-proposes from the missing evidence.
   * Integrity mismatch — the lead's OWN storage disagreeing with the journaled digest — is
   * NOT a lying pod (that cross-check happened at result-record time, against the
   * snapshot): it means the bound store itself was disturbed, so the pod is abandoned and
   * the mismatch escalated; nothing binds to bytes the record cannot vouch for.
   */
  private fun verifiedBoundArtifact(pod: PodRecord): VerifiedArtifact? {
    val bound = pod.boundPath?.let { File(it) }
    if (bound == null || !bound.exists()) {
      noteFailureAbandon(pod.taskRef)
      store.append(
        LeadKinds.POD_ABANDONED,
        buildJsonObject {
          put("podId", pod.podId)
          put("reason", "bound-artifact-missing at ${pod.boundPath ?: "(none recorded)"}")
        },
        origin = ORIGIN_SUBSTRATE,
      )
      return null
    }
    val recomputed = sha256HexBytes(bound.readBytes())
    if (recomputed != pod.resultDigest) {
      escalate(
        "bound-artifact integrity failure pod=${pod.podId}: journaled ${pod.resultDigest.orEmpty().take(16)} " +
          "vs on-disk ${recomputed.take(16)} at ${pod.boundPath} — abandoning; nothing binds to it"
      )
      noteFailureAbandon(pod.taskRef)
      store.append(
        LeadKinds.POD_ABANDONED,
        buildJsonObject {
          put("podId", pod.podId)
          put("reason", "bound-artifact-integrity-failure")
        },
        origin = ORIGIN_SUBSTRATE,
      )
      return null
    }
    return VerifiedArtifact(bound.path, recomputed)
  }

  /**
   * Persist a completion's snapshot as the pod's BOUND artifact: temp write, then an
   * atomic rename into place — consumers can never observe a torn file, and the pod (dead
   * by the time a completion is handled, and never handed this path) cannot reopen it.
   * Named by podId: unique per pod, so a re-proposed task's fresh pod never collides with
   * an abandoned attempt's bytes. Placement residual, stated plainly: artifacts-bound/
   * lives under the lead's workdir, which today IS the pod workspace root — a LATER pod
   * of the same lead could name this path. Today no consumer reads a bound
   * copy after its gate binds while a hostile pod runs, and the real fence is the pod
   * filesystem boundary (AGENCY-005 container floor), same as the engine's stat-open race
   * residual. Throws IOException to the caller, which abandons the pod (fail closed).
   */
  private fun writeBoundArtifact(podId: String, snapshot: ByteArray): String {
    val dir = File(workdir, "artifacts-bound")
    dir.mkdirs()
    val target = File(dir, podId)
    val tmp = File(dir, "$podId.tmp")
    tmp.writeBytes(snapshot)
    java.nio.file.Files.move(
      tmp.toPath(),
      target.toPath(),
      java.nio.file.StandardCopyOption.ATOMIC_MOVE,
    )
    return target.path
  }

  /**
   * The audit record of a cognition turn (origin = cognition). Every field is UNTRUSTED,
   * model-controlled input, so it is bounded exactly as the execution path
   * is: the reasoning, each meta value, and each proposal string are
   * truncated to [MAX_JOURNALED_STRING], and only the [MAX_PROPOSALS_PER_WAKE] proposals that
   * actually execute are audited. Without the count cap a hostile or buggy strategy returning
   * thousands of proposals (or a multi-megabyte reasoning string) would bloat the journal —
   * and every future re-fold's memory through it — even though execution already discards
   * everything past [MAX_PROPOSALS_PER_WAKE]. The audit must not record more than the substrate
   * would act on.
   */
  private fun journalCognitionOutput(out: CognitionOutput) {
    store.append(
      LeadKinds.COGNITION_PROPOSED,
      buildJsonObject {
        // Provenance meta first, our structured account last: strategy / reasoning / proposals
        // are the substrate's own record of the turn, and a meta key colliding with one of ours
        // must not be able to overwrite them. Mirrors journalMalformedCognition.
        for ((k, v) in out.meta) put(k, v.take(MAX_JOURNALED_STRING))
        put("strategy", cognition.name)
        put("reasoning", out.reasoning.take(MAX_JOURNALED_STRING))
        put(
          "proposals",
          buildJsonArray {
            for (p in out.proposals.take(MAX_PROPOSALS_PER_WAKE)) add(
              buildJsonObject {
                when (p) {
                  is Proposal.ProposeGateOpen -> {
                    put("type", "gate-open")
                    put("gateKind", p.gateKind.take(MAX_JOURNALED_STRING))
                    put("payloadDigest", p.payloadDigest.take(MAX_JOURNALED_STRING))
                  }
                  is Proposal.ProposePodSpawn -> {
                    put("type", "pod-spawn")
                    put("taskRef", p.taskRef.take(MAX_JOURNALED_STRING))
                  }
                  is Proposal.ProposeStatus -> {
                    put("type", "status")
                    put("status", p.status.take(MAX_JOURNALED_STRING))
                  }
                  is Proposal.ProposeEscalate -> {
                    put("type", "escalate")
                    put("reason", p.reason.take(MAX_JOURNALED_STRING))
                  }
                }
              }
            )
          },
        )
      },
      origin = ORIGIN_COGNITION,
    )
  }

  /**
   * Execute cognition's proposals — treating them as UNTRUSTED input, not commands.
   * Cognition supplies judgment (when to gate, what task to run); the substrate holds the
   * evidence and enforces it here:
   *  - a gate opens only on the digest the SUBSTRATE recorded for that gate kind
   *    (cognition cannot re-bind approval to evidence that does not exist — a mismatch is
   *    escalated visibly, never opened);
   *  - a task ref must be well-formed and its artifact path must resolve inside the
   *    lead's artifacts directory (no traversal via model-controlled names);
   *  - a task whose evidence is already recorded is refused a fresh pod (re-proposing
   *    completed work would otherwise buy one real pod per wake through the
   *    wait-on-human gate phases);
   *  - duplicates WITHIN one output batch execute once (the snapshot guards alone cannot
   *    see intra-batch repeats).
   */
  private fun executeProposals(out: CognitionOutput, leadAtDecision: LeadState) {
    val ticket = leadAtDecision.currentTicket
    val seenGateIds = mutableSetOf<String>()
    val seenTaskRefs = mutableSetOf<String>()
    // Cardinality guard: a wake executes a bounded number of proposals,
    // so a prompt-injected / buggy strategy cannot amplify one output into unbounded journal
    // writes. The drop is escalated, never silent.
    if (out.proposals.size > MAX_PROPOSALS_PER_WAKE) {
      escalate(
        "cognition output truncated: ${out.proposals.size} proposals exceed the per-wake " +
          "cap of $MAX_PROPOSALS_PER_WAKE; executing the first $MAX_PROPOSALS_PER_WAKE"
      )
    }
    for (p in out.proposals.take(MAX_PROPOSALS_PER_WAKE)) {
      when (p) {
        is Proposal.ProposeGateOpen -> {
          if (ticket == null) continue
          val gateId = gateIdFor(p.gateKind, ticket)
          if (gateId in leadAtDecision.openGates || !seenGateIds.add(gateId)) continue
          val expected =
            when (p.gateKind) {
              GateKinds.PLAN_APPROVAL -> leadAtDecision.planArtifactSha
              GateKinds.COMMIT_APPROVAL -> leadAtDecision.commitManifestDigest
              else -> null
            }
          if (expected == null || p.payloadDigest != expected) {
            escalate(
              "gate-open rejected for $gateId: proposed digest ${p.payloadDigest.take(16)} " +
                "does not match substrate evidence ${expected?.take(16) ?: "(none recorded)"}"
            )
            continue
          }
          store.append(
            LeadKinds.GATE_OPENED,
            buildJsonObject {
              put("gateId", gateId)
              put("gateKind", p.gateKind)
              put("payloadDigest", expected)
            },
            origin = ORIGIN_SUBSTRATE,
          )
          faults.at("after-gate-opened-${p.gateKind}")
        }
        is Proposal.ProposePodSpawn -> {
          if (ticket == null) continue
          // Bind the spawn to the CURRENT ticket and a known kind:
          // cognition decides WHEN to run a pod, never an arbitrary task namespace. The only
          // legal refs are this ticket's plan/execute; a foreign ticket, an unknown kind, or
          // a traversal attempt is escalated, never spawned — so untrusted judgment cannot
          // amplify into unbounded distinct spawns.
          if (p.taskRef != "plan:$ticket" && p.taskRef != "execute:$ticket") {
            escalate(
              "pod-spawn rejected: taskRef '${p.taskRef.take(80)}' is not plan:/execute: " +
                "for the current ticket '$ticket'"
            )
            continue
          }
          // Pipeline ordering has teeth: an execute pod
          // is real work ON the plan, so it may launch only AFTER the plan-approval gate is
          // released. The mechanical pass already refuses to PROPOSE a commit before plan
          // approval; without this, cognition — by bug or prompt injection — could still get
          // the substrate to LAUNCH the execute session on an unapproved (or unrecorded) plan,
          // and the human's plan gate would gate nothing. Escalated, never spawned.
          if (
            p.taskRef == "execute:$ticket" &&
              gateIdFor(GateKinds.PLAN_APPROVAL, ticket) !in leadAtDecision.releasedGates
          ) {
            escalate(
              "pod-spawn rejected: execute pod for '$ticket' proposed before the plan-approval " +
                "gate is released — the plan must be approved before execution runs"
            )
            continue
          }
          if (leadAtDecision.activePods.any { it.taskRef == p.taskRef }) continue
          if (!seenTaskRefs.add(p.taskRef)) continue
          // Success-side twin of the failure cap below: a task whose EVIDENCE is already
          // recorded gets no fresh pod. Successful completions never touch
          // [failureAbandons] and clear the active-pod guard, and a completion is itself
          // the next wake — so without this check a strategy re-proposing the same legal
          // ref would buy one real pod (and its real model spend) per wake,
          // self-sustaining through the wait-on-human gate phases, with nothing
          // escalated. Refused on every wake, escalated once per taskRef per process
          // (see [redundantSpawnEscalated]). No legitimate replan is refused here: no
          // fold transition clears plan/manifest evidence within a ticket cycle
          // (TICKET_DONE resets the whole cycle), so a replan mechanism, if one ever
          // exists, must introduce a cleared-evidence transition — which re-legalizes
          // the spawn here by itself.
          // The namespace guard above admits exactly plan:/execute:, so the else branch
          // IS execute:. Deliberately not an exhaustive `when` with `else -> null`: if
          // the legal namespace is ever widened without this selector keeping pace, a
          // new kind inherits the manifest-evidence refusal (escalated, visible) rather
          // than skipping a spend guard silently — over-refusal is the recoverable
          // failure direction here.
          val recorded =
            if (p.taskRef == "plan:$ticket") leadAtDecision.planArtifactSha
            else leadAtDecision.commitManifestDigest
          if (recorded != null) {
            if (redundantSpawnEscalated.add(p.taskRef)) {
              escalate(
                "pod-spawn refused for taskRef '${p.taskRef.take(80)}': the evidence it " +
                  "exists to produce is already recorded (${recorded.take(16)}) — completed " +
                  "work is not re-run, and further redundant proposals are refused without " +
                  "a repeat escalation"
              )
            }
            continue
          }
          // Lead-tier attempt cap (see [failureAbandons]): a taskRef that keeps producing
          // failure-abandons stops getting fresh pods — refused on every wake, escalated
          // once per taskRef (see [capRefusalsEscalated]) — so the pipeline wedges VISIBLY
          // instead of burning spawns (and real model spend) in a re-propose livelock
          // against a persistent fault.
          val attempts = failureAbandons[p.taskRef] ?: 0
          if (attempts >= MAX_TASK_ATTEMPTS_PER_PROCESS) {
            if (capRefusalsEscalated.add(p.taskRef)) {
              escalate(
                "pod-spawn refused for taskRef '${p.taskRef.take(80)}': $attempts failed " +
                  "attempts this process (cap $MAX_TASK_ATTEMPTS_PER_PROCESS) — not " +
                  "re-proposing; fix the fault and restart the lead"
              )
            }
            continue
          }
          // Defense-in-depth backstops the now-ticket-bound ref: a ticket that itself carried
          // odd characters would still be caught by the charset + canonical-containment checks.
          if (!TASK_REF_RE.matches(p.taskRef)) {
            escalate("pod-spawn rejected: malformed taskRef '${p.taskRef.take(80)}'")
            continue
          }
          val artifactsDir = File(workdir, "artifacts").canonicalFile
          val artifactFile = File(artifactsDir, p.taskRef.replace(':', '-')).canonicalFile
          if (!artifactFile.path.startsWith(artifactsDir.path + File.separator)) {
            escalate("pod-spawn rejected: artifact path escapes the artifacts dir for taskRef '${p.taskRef.take(80)}'")
            continue
          }
          // The fail-closed fence, LAST before the substrate commits to the
          // launch: a fenced profile (transport=acp, provider≠claude, no egress-enforcement
          // capability — and none is constructible today) THROWS here, before the intent is
          // journaled and before any side effect. A throw is deliberate, not an escalation:
          // a fenced profile is a configuration fault, and the daemon must stop (the loop's
          // wake-fault path journals it and halts for a supervisor), never proceed.
          podSpec.requireSpawnable()
          // Intent BEFORE the side-effect: a pod launch is a side-effect
          // on the world, so it obeys the same intent-before-effect discipline as an effect
          // fire. Journaling POD_SPAWN_INTENDED first means a kill before POD_SPAWNED leaves a
          // RECORDED orphan (adopt abandons it and re-proposes), never an invisible one that a
          // fresh re-fold would wrongly report as "nothing happened".
          store.append(
            LeadKinds.POD_SPAWN_INTENDED,
            buildJsonObject {
              put("taskRef", p.taskRef)
              put("artifactPath", artifactFile.path)
            },
            origin = ORIGIN_SUBSTRATE,
          )
          faults.at("after-spawn-intended")
          val spawned =
            podRunner.spawn(podSpec, p.taskRef, workdir, artifactFile.path) { completion ->
              queue.put(WakeEvent.PodDone(completion))
            }
          faults.at("between-spawn-and-journal")
          store.append(
            LeadKinds.POD_SPAWNED,
            buildJsonObject {
              put("podId", spawned.podId.take(MAX_JOURNALED_STRING))
              put("sessionId", spawned.sessionId.take(MAX_JOURNALED_STRING))
              put("taskRef", p.taskRef)
              put("artifactPath", artifactFile.path)
              // Profile provenance: the chain records WHAT launched —
              // provider/transport/model/pin — because append-only means this cannot be
              // backfilled once profile switching exists. Fold-invisible today (extra keys
              // are ignored); the audit value is the record itself.
              put("provider", podSpec.provider.name)
              put("transport", podSpec.transport.name)
              put("model", podSpec.model)
              put("pinnedVersion", podSpec.pinnedVersion)
            },
            origin = ORIGIN_SUBSTRATE,
          )
          faults.at("after-pod-spawned")
        }
        is Proposal.ProposeStatus ->
          store.append(
            LeadKinds.STATUS_WRITTEN,
            buildJsonObject { put("status", p.status.take(MAX_JOURNALED_STRING)) },
            origin = ORIGIN_SUBSTRATE,
          )
        is Proposal.ProposeEscalate -> escalate(p.reason)
      }
    }
  }

  /**
   * Render one engine event as a journal payload. An exhaustive `when` over the sealed
   * [PodEvent] on purpose: a new engine event then fails to COMPILE here rather than
   * silently landing in the journal as an unlabelled row — the record's schema is decided
   * at this seam, not by whatever the engine happened to emit.
   *
   * Every free-text field is UNTRUSTED (agent-authored ask titles; restart causes that carry
   * the pod's own stderr tail) and is bounded by [MAX_JOURNALED_STRING] — the journal is
   * append-only and re-folded into memory forever, so a chatty pod must not be able to grow
   * it (the same bound the cognition path applies to model output).
   */
  private fun podEventPayload(e: PodEvent): JsonObject = buildJsonObject {
    put("podId", e.podId)
    when (e) {
      is PodEvent.SessionEstablished -> {
        put("event", "session-established")
        put("sessionId", e.sessionId.take(MAX_JOURNALED_STRING))
        put("attempt", e.attempt)
      }
      is PodEvent.PermissionAsked -> {
        put("event", "permission-asked")
        put("sessionId", e.sessionId.take(MAX_JOURNALED_STRING))
        put("toolCallId", e.toolCallId.take(MAX_JOURNALED_STRING))
        put("title", e.title.take(MAX_JOURNALED_STRING))
        put("toolKind", e.toolKind.take(MAX_JOURNALED_STRING))
      }
      is PodEvent.PermissionDecided -> {
        put("event", "permission-decided")
        put("sessionId", e.sessionId.take(MAX_JOURNALED_STRING))
        put("toolCallId", e.toolCallId.take(MAX_JOURNALED_STRING))
        put("decision", e.decision.take(MAX_JOURNALED_STRING))
        put("elapsedMs", e.elapsedMs)
        // The answer arrived after our fail-closed deadline had already rejected on the
        // wire: it authorized NOTHING, and the record has to say which of the two it was.
        put("lateAfterDeadline", e.lateAfterDeadline)
      }
      is PodEvent.PreflightRefused -> {
        put("event", "preflight-refused")
        put("sessionId", e.sessionId.take(MAX_JOURNALED_STRING))
        put("reason", e.reason.take(MAX_JOURNALED_STRING))
      }
      is PodEvent.ArtifactRefused -> {
        put("event", "artifact-refused")
        put("artifactPath", e.artifactPath.take(MAX_JOURNALED_STRING))
        put("reason", e.reason.take(MAX_JOURNALED_STRING))
      }
      is PodEvent.RestartAttempted -> {
        put("event", "restart-attempted")
        put("attempt", e.attempt)
        put("backoffMs", e.backoffMs)
        put("cause", e.cause.take(MAX_JOURNALED_STRING))
      }
      is PodEvent.RestartsExhausted -> {
        put("event", "restarts-exhausted")
        put("attempts", e.attempts)
        put("cause", e.cause.take(MAX_JOURNALED_STRING))
      }
      is PodEvent.DeadlineKilled -> {
        put("event", "deadline-killed")
        put("afterMs", e.afterMs)
      }
      is PodEvent.CompletionDiscarded -> {
        put("event", "completion-discarded")
        put("reason", e.reason.take(MAX_JOURNALED_STRING))
      }
      is PodEvent.GroupKillDegraded -> {
        put("event", "group-kill-degraded")
        put("reason", e.reason.take(MAX_JOURNALED_STRING))
        put("detail", e.detail.take(MAX_JOURNALED_STRING))
      }
    }
  }

  /** The engine events that deserve an escalation row beside their pod-event row (see
   * [injectPodEvent]): the pod is dead, or its tree was not group-killable. */
  private fun podEventEscalation(e: PodEvent): String? =
    when (e) {
      is PodEvent.PreflightRefused ->
        "pod ${e.podId} refused by rp-liveness preflight: ${e.reason}"
      is PodEvent.ArtifactRefused ->
        "pod ${e.podId} artifact refused at ${e.artifactPath}: ${e.reason}"
      is PodEvent.RestartsExhausted ->
        "pod ${e.podId} exhausted its restart cap after ${e.attempts} attempts: ${e.cause}"
      is PodEvent.DeadlineKilled ->
        "pod ${e.podId} killed on its wall clock after ${e.afterMs}ms"
      is PodEvent.GroupKillDegraded ->
        "pod ${e.podId} was not group-killable (${e.reason}): ${e.detail} — descendants may survive"
      is PodEvent.SessionEstablished,
      is PodEvent.PermissionAsked,
      is PodEvent.PermissionDecided,
      is PodEvent.RestartAttempted,
      is PodEvent.CompletionDiscarded -> null
    }

  private fun escalate(reason: String) {
    store.append(
      LeadKinds.ESCALATED,
      buildJsonObject { put("reason", reason.take(MAX_JOURNALED_STRING)) },
      origin = ORIGIN_SUBSTRATE,
    )
  }

  private fun markMailDelivered(undelivered: List<Pair<Long, String>>) {
    for ((seq, _) in undelivered) {
      store.append(
        "mailbox-delivered",
        buildJsonObject { put("appendSeq", seq) },
        origin = ORIGIN_SUBSTRATE,
      )
    }
  }

  private fun reasonOf(ev: WakeEvent): WakeReason =
    when (ev) {
      WakeEvent.Adopted -> WakeReason.Adopted
      is WakeEvent.MailInject -> WakeReason.MailArrived(ev.message)
      is WakeEvent.TimerDue -> WakeReason.TimerFired(ev.timerId)
      is WakeEvent.PodDone -> WakeReason.PodCompleted(ev.completion.podId)
      is WakeEvent.PodDisposed -> WakeReason.PodDisposed(ev.podId, ev.disposition)
      is WakeEvent.AuthRelease -> WakeReason.GateReleased(ev.gateId)
      WakeEvent.Shutdown -> WakeReason.Adopted // unreachable: shutdown never reaches handleWake
    }
}

/** Ticket offer seam: a fixture file today; real ticket-index ops come later. */
fun interface TicketSource {
  /** The next ticket ref on offer that is not in [done], or null when the source is
   * exhausted. [done] is the fold's completed-ticket set — passing it in keeps the source
   * stateless and the offer replay-deterministic (same journal, same offer), and is what
   * lets a multi-ticket source progress: without it, a source has no way to stop
   * re-offering a completed ref. Progression covers refs that complete, deliberately: a
   * ref the claim boundary rejects is escalated and never claimed, so it never enters
   * [done] and stays the head offer — a malformed line parks the source visibly (one
   * escalation per idle wake) until the operator fixes it, rather than being silently
   * skipped. Offering is idempotent, and the source stays untrusted:
   * the daemon still filters done refs and claims at most one at a time. */
  fun next(done: Set<String>): String?
}

class FileTicketSource(private val file: File) : TicketSource {
  override fun next(done: Set<String>): String? =
    if (file.exists()) {
      file.readLines().map { it.trim() }.firstOrNull { it.isNotEmpty() && it !in done }
    } else null
}

/** Timer seam: adopt re-arms pending timers through this; firing enqueues a wake. */
fun interface TimerService {
  fun arm(timer: ArmedTimer, onDue: (String) -> Unit)

  companion object {
    /** Tests fire manually via [LeadDaemon.injectTimerDue]. */
    val NOOP = TimerService { _, _ -> }
  }
}

/** Wall-clock timer service for real runs: schedules the wake at fireAtEpochMs. */
class ThreadTimerService : TimerService {
  private val wallTimer = java.util.Timer("lead-timers", true)

  override fun arm(timer: ArmedTimer, onDue: (String) -> Unit) {
    val delay = (timer.fireAtEpochMs - System.currentTimeMillis()).coerceAtLeast(0)
    wallTimer.schedule(
      object : java.util.TimerTask() {
        override fun run() = onDue(timer.id)
      },
      delay,
    )
  }
}

/** Well-formed task refs: kind:name in a conservative charset ('/' excluded, so a
 * model-controlled ref cannot traverse; the canonical containment check backstops it). */
private val TASK_REF_RE = Regex("[A-Za-z0-9:._-]+")

/** Bounds on untrusted, cognition-controlled values the substrate
 * journals: a wake executes at most [MAX_PROPOSALS_PER_WAKE] proposals, and each journaled
 * status / escalation string is truncated to [MAX_JOURNALED_STRING] chars — so neither
 * proposal cardinality nor string size can bloat the journal or grow re-fold memory. */
private const val MAX_PROPOSALS_PER_WAKE = 16
private const val MAX_JOURNALED_STRING = 4000

/** Lead-tier attempt cap (see [LeadDaemon] failureAbandons): failure-abandons per taskRef
 * per PROCESS before the spawn site stops re-proposing and escalates. Three genuine
 * attempts before wedging visibly; a restart grants three more. */
private const val MAX_TASK_ATTEMPTS_PER_PROCESS = 3

/** Upper bound on a strategy's per-wake cognition attempts. Bounds how long one wake
 * can hold the loop thread: attempts run in series, each costing a whole harness turn plus
 * its backoff, and shutdown is only observed between wakes. */
private const val MAX_COGNITION_ATTEMPTS_CEILING = 5

/** Admission bound on one accepted mail message (AGENCY-021): the
 * accept boundary is any-thread and durable-on-return, so caller-controlled bytes flow
 * straight into the journal — and through it into every future re-fold's memory. Oversize
 * is REFUSED, never truncated (accept means durable and intact). Generous for
 * fixture traffic; the real mailbox surface revisits it with the channel model. */
private const val MAX_ACCEPTED_MAIL_CHARS = 64_000

/** Well-formed ticket refs: a ticket ref is untrusted
 * input (a fixture line today, a real ticket-index row later) that flows into task refs, gate
 * ids, and effect keys. A conservative charset — ':' and '/' excluded, so it can forge neither
 * a task namespace nor a path — plus a length bound, validated at the claim boundary, keeps a
 * malformed ref from wedging the pipeline or polluting a namespace. */
private val TICKET_REF_RE = Regex("[A-Za-z0-9._-]+")
private const val MAX_TICKET_REF_LEN = 128

/** Deterministic fault seam: the fixture exits 42 at a named instruction boundary. */
fun interface FaultInjector {
  fun at(boundary: String)

  companion object {
    val NONE = FaultInjector { }
  }
}

private fun JsonObject.strOrNull(k: String): String? = this[k]?.jsonPrimitive?.content
