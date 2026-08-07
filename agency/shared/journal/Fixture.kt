package com.geekinasuit.agency.shared.journal

import kotlin.system.exitProcess
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Scenario fixture binary: one binary, subcommands = workflow
 * steps. Process death is simulated by DETERMINISTIC fault injection (`--fault` exits at
 * the exact instruction boundary under test, exit 42) rather than external kill timing —
 * deterministic kill points, not sleeps. Recovery is always a fresh process re-folding
 * the journal. ScenarioTest spawns this binary from runfiles and asserts on observable
 * outputs (journal state + receiver logs).
 *
 * Exit codes: 0 ok · 42 injected fault death · 3 timer-did-not-fire ·
 * 4 version gate refused · 5 chain broken.
 */
object Fixture {

  @JvmStatic
  fun main(args: Array<String>) {
    val a = ArgMap(args)
    val store = SqliteStore(a.req("dir"), componentId = "fixture")
    val receiver = EffectReceiver(a.req("dir"))
    try {
      when (a.subcommand) {
        "step-effect" -> stepEffect(store, receiver, a)
        "resume" -> resume(store, receiver, a)
        "arm-timer" -> armTimer(store, a)
        "serve-timers" -> serveTimers(store, a)
        "replay" -> replay(store)
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
    } finally {
      store.close()
    }
  }

  /**
   * One workflow step firing an external effect exactly-once: journal intent (carrying
   * the idempotency key) BEFORE the effect, fire the effect, journal done.
   * `--fault after-effect` dies between fire and done — the classic double-fire window.
   */
  private fun stepEffect(store: JournalStore, receiver: EffectReceiver, a: ArgMap) {
    val key = a.req("key")
    val dedup = !a.has("no-dedup")
    store.append(
      "effect-intent",
      buildJsonObject { put("message", "hello-effect") },
      origin = ORIGIN_SUBSTRATE,
      idempotencyKey = key,
    )
    if (a.opt("fault") == "after-intent") {
      System.err.println("FAULT injected: dying after intent journal entry, before the effect fires")
      exitProcess(42)
    }
    val result = receiver.fire(key, "hello-effect", dedup)
    if (a.opt("fault") == "after-effect") {
      System.err.println("FAULT injected: dying after effect, before effect-done journal entry")
      exitProcess(42)
    }
    store.append(
      "effect-done",
      buildJsonObject {
        put("key", key)
        put("attempt", 1)
        put("result", result.toString())
      },
      origin = ORIGIN_SUBSTRATE,
    )
    println("STEP-EFFECT key=$key attempt=1 result=$result")
  }

  /** Recovery pass: re-fire every intent without a done entry; the receiver dedups. */
  private fun resume(store: JournalStore, receiver: EffectReceiver, a: ArgMap) {
    val dedup = !a.has("no-dedup")
    val state = fold(store.readAll())
    for (key in state.pendingEffectKeys) {
      val result = receiver.fire(key, "hello-effect", dedup)
      store.append(
        "effect-done",
        buildJsonObject {
          put("key", key)
          put("attempt", 2)
          put("result", result.toString())
        },
        origin = ORIGIN_SUBSTRATE,
      )
      println("RESUME effect key=$key attempt=2 result=$result")
    }
    if (state.pendingEffectKeys.isEmpty()) println("RESUME nothing-pending")
  }

  /** Arms a durable timer (journal entry only — no live timer exists at fault time). */
  private fun armTimer(store: JournalStore, a: ArgMap) {
    val id = a.req("id")
    val fireAt = System.currentTimeMillis() + a.req("fire-in-ms").toLong()
    store.append(
      "timer-armed",
      buildJsonObject {
        put("id", id)
        put("fireAtEpochMs", fireAt)
        put("action", "write-timers-log")
      },
      origin = ORIGIN_SUBSTRATE,
    )
    if (a.opt("fault") == "after-arm") {
      System.err.println("FAULT injected: dying after arming timer (timer exists only in the journal)")
      exitProcess(42)
    }
    println("ARM-TIMER id=$id fireAtEpochMs=$fireAt")
  }

  /**
   * Adopt-and-serve: re-arm pending timers from the journal fold, poll until each fires
   * (observable: timers.log line + timer-fired entry) or the wait budget ends.
   * `--skip-rearm` is the positive-control cell: prove the harness observes a missing fire.
   */
  private fun serveTimers(store: JournalStore, a: ArgMap) {
    val waitMs = a.req("wait-ms").toLong()
    val deadline = System.currentTimeMillis() + waitMs
    val remaining =
      if (a.has("skip-rearm")) mutableListOf() else fold(store.readAll()).pendingTimers.toMutableList()
    val timerLog = EffectReceiver(a.req("dir"), fileName = "timers.log")
    println("SERVE-TIMERS rearmed=${remaining.size}")
    while (remaining.isNotEmpty() && System.currentTimeMillis() < deadline) {
      val now = System.currentTimeMillis()
      val due = remaining.filter { it.fireAtEpochMs <= now }
      for (t in due) {
        timerLog.fire("timer-${t.id}", "fired", dedup = true)
        store.append("timer-fired", buildJsonObject { put("id", t.id) }, origin = ORIGIN_SUBSTRATE)
        println("TIMER-FIRED id=${t.id}")
        remaining.remove(t)
      }
      Thread.sleep(25)
    }
    if (a.has("skip-rearm")) {
      println("SERVE-TIMERS skip-rearm cell complete (nothing re-armed by design)")
      return
    }
    if (remaining.isNotEmpty()) {
      System.err.println("TIMER-NOT-FIRED ids=${remaining.map { it.id }}")
      exitProcess(3)
    }
  }

  /** Verify + upcast + fold; print the canonical state line scenario assertions read. */
  private fun replay(store: JournalStore) {
    val entries = store.readAll()
    val state = fold(entries)
    println(
      "REPLAY entries=${entries.size} pendingEffects=${state.pendingEffectKeys} " +
        "done=${state.doneKeys.keys.sorted()} pendingTimers=${state.pendingTimers.map { it.id }}"
    )
  }
}

/** Tiny arg parser: `subcommand --k v --flag` (no external deps; fixture-grade). */
class ArgMap(args: Array<String>) {
  val subcommand: String = args.firstOrNull() ?: ""
  private val map = mutableMapOf<String, String>()

  init {
    var i = 1
    while (i < args.size) {
      val a = args[i]
      require(a.startsWith("--")) { "expected --flag, got '$a'" }
      val k = a.removePrefix("--")
      if (i + 1 < args.size && !args[i + 1].startsWith("--")) {
        map[k] = args[i + 1]
        i += 2
      } else {
        map[k] = "true"
        i += 1
      }
    }
  }

  fun req(k: String): String = map[k] ?: error("missing required --$k")
  fun opt(k: String): String? = map[k]
  fun has(k: String): Boolean = map.containsKey(k)
}
