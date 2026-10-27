package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.JournalStore
import java.io.File

/**
 * A lead running the ticket workflow on tickets from [ticketSource]: the host, with the ticket
 * lead's state. Every other parameter is [AgentHost]'s. A function cannot inherit another's
 * defaults, so each default here names the constant [AgentHost]'s constructor uses, and the two
 * cannot drift.
 */
fun ticketLead(
  store: JournalStore,
  cognition: AgentCognition<LeadState>,
  podRunner: PodRunner,
  podSpec: PodSpec,
  ticketSource: TicketSource,
  workdir: File,
  effects: EffectReceiver,
  leadAuth: LeadAuth,
  timers: TimerService,
  faults: FaultInjector = AgentHost.DEFAULT_FAULTS,
  gateOpenSink: GateOpenSink = AgentHost.DEFAULT_GATE_OPEN_SINK,
  dedupEffects: Boolean = AgentHost.DEFAULT_DEDUP_EFFECTS,
  capabilityDesc: String = AgentHost.DEFAULT_CAPABILITY_DESC,
  leadVersion: String = AgentHost.DEFAULT_LEAD_VERSION,
  cognitionRetryBackoffMs: Long = AgentHost.DEFAULT_COGNITION_RETRY_BACKOFF_MS,
  maxCognitionAttempts: Int = AgentHost.DEFAULT_MAX_COGNITION_ATTEMPTS,
  boundReadDeadlineMs: Long = AgentHost.DEFAULT_BOUND_READ_DEADLINE_MS,
  maxParkedBoundReads: Int = AgentHost.DEFAULT_MAX_PARKED_BOUND_READS,
): AgentHost<LeadState> =
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
