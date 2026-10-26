package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.JournalStore
import java.io.File

/** A lead running the ticket workflow: the host, with the ticket lead's state. */
typealias LeadDaemon = AgentHost<LeadState>

/**
 * A lead running the ticket workflow on tickets from [ticketSource]. Every other parameter is
 * [AgentHost]'s, with its default restated here: a function cannot inherit another's defaults, so
 * the two must be kept in step.
 */
fun LeadDaemon(
  store: JournalStore,
  cognition: CognitionStrategy,
  podRunner: PodRunner,
  podSpec: PodSpec,
  ticketSource: TicketSource,
  workdir: File,
  effects: EffectReceiver,
  leadAuth: LeadAuth,
  timers: TimerService,
  faults: FaultInjector = FaultInjector.NONE,
  gateOpenSink: GateOpenSink = NoOpGateOpenSink,
  dedupEffects: Boolean = true,
  capabilityDesc: String = "scripted/none",
  leadVersion: String = "dev",
  cognitionRetryBackoffMs: Long = 500,
  maxCognitionAttempts: Int = 2,
  boundReadDeadlineMs: Long = AgentHost.DEFAULT_BOUND_READ_DEADLINE_MS,
  maxParkedBoundReads: Int = AgentHost.DEFAULT_MAX_PARKED_BOUND_READS,
): LeadDaemon =
  AgentHost(
    store = store,
    cognition = cognition,
    podRunner = podRunner,
    podSpec = podSpec,
    workflow = TicketWorkflow(ticketSource),
    workdir = workdir,
    effects = effects,
    leadAuth = leadAuth,
    timers = timers,
    faults = faults,
    gateOpenSink = gateOpenSink,
    dedupEffects = dedupEffects,
    capabilityDesc = capabilityDesc,
    leadVersion = leadVersion,
    cognitionRetryBackoffMs = cognitionRetryBackoffMs,
    maxCognitionAttempts = maxCognitionAttempts,
    boundReadDeadlineMs = boundReadDeadlineMs,
    maxParkedBoundReads = maxParkedBoundReads,
  )
