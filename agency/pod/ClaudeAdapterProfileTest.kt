package com.geekinasuit.agency.pod

import com.agentclientprotocol.model.Cost
import com.agentclientprotocol.model.SessionUpdate
import java.io.File
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [ClaudeAdapterProfile] unit cells: every control the profile expresses
 * against the adapter's seams — argv/env shape, the `_meta` options object
 * (settingSources: [] + workspace-independent config dir), the turn/spend bounds, the
 * phone-home denial riding BOTH channels, the protocol pin, and the cost extractor's
 * null-not-zero rules. These pin the CONSTRUCTION; the wire behavior is the
 * canary's and the env-gated smoke's job.
 */
class ClaudeAdapterProfileTest {

  private val node = File("/abs/node")
  private val entry = File("/abs/adapter/dist/index.js")
  private val cfg = File("/abs/lead-config")

  private fun profile(claudeExecutable: File? = null) =
    ClaudeAdapterProfile(node, entry, cfg, claudeExecutable)

  private fun spec(maxTurns: Int? = 7, maxBudgetUsd: Double? = 2.5) =
    PodSpec(
      provider = PodProvider.CLAUDE,
      model = "model-x",
      authMode = PodAuthMode.MACHINE_CREDENTIAL,
      transport = PodTransport.ACP,
      pinnedVersion = ClaudeAdapterPin.VERSION,
      maxTurns = maxTurns,
      maxBudgetUsd = maxBudgetUsd,
    )

  @Test
  fun argvExecsNodeOnTheAdapterEntry() {
    assertEquals(listOf("/abs/node", "/abs/adapter/dist/index.js"), profile().argv(spec(), File("/w")))
  }

  @Test
  fun envCarriesConfigDirAndEveryPhoneHomeDenyVar() {
    val env = profile().env(spec())
    assertEquals("/abs/lead-config", env["CLAUDE_CONFIG_DIR"])
    assertTrue("no executable pin unless supplied", "CLAUDE_CODE_EXECUTABLE" !in env)
    for ((k, v) in ClaudeAdapterProfile.PHONE_HOME_DENY_ENV) {
      assertEquals("deny var $k rides the process env", v, env[k])
    }
  }

  @Test
  fun claudeExecutablePinRidesEnvWhenSupplied() {
    val env = profile(claudeExecutable = File("/abs/claude")).env(spec())
    assertEquals("/abs/claude", env["CLAUDE_CODE_EXECUTABLE"])
  }

  @Test
  fun sessionMetaCarriesWorkspaceIndependentOptionsAndBounds() {
    val options =
      profile().sessionMeta(spec())!!
        .jsonObject["claudeCode"]!!
        .jsonObject["options"]!!
        .jsonObject
    // The cold-config control: NO settings discovery — empty list, present.
    assertEquals(0, options["settingSources"]!!.jsonArray.size)
    assertEquals("model-x", options["model"]!!.jsonPrimitive.content)
    assertEquals(7, options["maxTurns"]!!.jsonPrimitive.content.toInt())
    assertEquals(2.5, options["maxBudgetUsd"]!!.jsonPrimitive.content.toDouble(), 0.0)
    // The deny vars ride the OPTIONS env too (the spread-order channel that survives an
    // adapter release that stops inheriting process env).
    val optEnv = options["env"]!!.jsonObject
    assertEquals("/abs/lead-config", optEnv["CLAUDE_CONFIG_DIR"]!!.jsonPrimitive.content)
    for ((k, v) in ClaudeAdapterProfile.PHONE_HOME_DENY_ENV) {
      assertEquals("deny var $k rides options.env", v, optEnv[k]!!.jsonPrimitive.content)
    }
  }

  @Test
  fun sessionMetaOmitsAbsentBoundsRatherThanInventingThem() {
    val options =
      profile().sessionMeta(spec(maxTurns = null, maxBudgetUsd = null))!!
        .jsonObject["claudeCode"]!!
        .jsonObject["options"]!!
        .jsonObject
    assertTrue("maxTurns" !in options)
    assertTrue("maxBudgetUsd" !in options)
  }

  @Test
  fun protocolPinMatchesTheCodeConstant() {
    assertEquals(ClaudeAdapterPin.PROTOCOL_VERSION, profile().expectedProtocolVersion())
  }

  @Test
  fun allPathsMustBeAbsolute() {
    fun throws(block: () -> Unit): Boolean =
      try {
        block()
        false
      } catch (_: IllegalArgumentException) {
        true
      }
    assertTrue(throws { ClaudeAdapterProfile(File("node"), entry, cfg) })
    assertTrue(throws { ClaudeAdapterProfile(node, File("dist/index.js"), cfg) })
    assertTrue(throws { ClaudeAdapterProfile(node, entry, File("cfg")) })
    assertTrue(throws { ClaudeAdapterProfile(node, entry, cfg, File("claude")) })
  }

  // ---- costUsdFrom (null-not-zero) ----

  private fun usage(amount: Double?, currency: String = "USD") =
    SessionUpdate.UsageUpdate(
      used = 1,
      size = 100,
      cost = amount?.let { Cost(amount = it, currency = currency) },
    )

  @Test
  fun costIsTheLastCostBearingUpdateOfTheTurn() {
    val cost =
      profile()
        .costUsdFrom(listOf(usage(0.10), usage(null), usage(0.42), usage(null)))
    assertEquals(0.42, cost!!, 0.0)
  }

  @Test
  fun turnWithNoCostBearingUpdateIsUnmeasuredNull() {
    assertNull(profile().costUsdFrom(emptyList()))
    assertNull(profile().costUsdFrom(listOf(usage(null), usage(null))))
  }

  @Test
  fun nonUsdCostIsUnmeasuredNeverGuessedIntoDollars() {
    assertNull(profile().costUsdFrom(listOf(usage(0.42, currency = "EUR"))))
  }
}
