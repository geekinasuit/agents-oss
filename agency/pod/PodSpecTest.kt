package com.geekinasuit.agency.pod

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The descriptor fence, unit level: transport=ACP with a non-Claude provider
 * throws at [PodSpec.requireSpawnable] — unconditionally, because [EgressEnforcement] has
 * a private constructor and no factory, so no caller can present the capability that
 * would open the fence. (That unconstructibility is a compile-time property: a test that
 * tried to construct one would not build.) The daemon-level half — the fence fires before
 * any spawn side effect — lives in the lead's GuardsTest.
 */
class PodSpecTest {

  private fun spec(provider: PodProvider, transport: PodTransport) =
    PodSpec(
      provider = provider,
      model = "m",
      authMode = PodAuthMode.NONE,
      transport = transport,
      pinnedVersion = "test",
    )

  private fun fenceThrows(s: PodSpec): Boolean =
    try {
      s.requireSpawnable()
      false
    } catch (e: IllegalStateException) {
      e.message?.contains("fenced pod profile") == true
    }

  @Test
  fun acpWithNonClaudeProviderIsFencedAndThrows() {
    assertTrue(fenceThrows(spec(PodProvider.GROK, PodTransport.ACP)))
    assertTrue(fenceThrows(spec(PodProvider.LOCAL, PodTransport.ACP)))
  }

  @Test
  fun acpWithClaudeProviderIsSpawnable() {
    spec(PodProvider.CLAUDE, PodTransport.ACP).requireSpawnable() // must not throw
  }

  @Test
  fun httpTransportIsNotFencedForAnyProvider() {
    // HTTP carries prompts to an endpoint the lead chose — not a tool-wielding agent
    // process — so the ACP fence does not apply (the OpenAiCompatHarness/grok
    // COGNITION channel).
    spec(PodProvider.GROK, PodTransport.HTTP).requireSpawnable()
    spec(PodProvider.LOCAL, PodTransport.HTTP).requireSpawnable()
    spec(PodProvider.CLAUDE, PodTransport.HTTP).requireSpawnable()
  }

  @Test
  fun fixtureProfileIsSpawnableByConstruction() {
    PodSpec.fixture().requireSpawnable() // fixture rigs must never trip the fence
  }

  // ---- the claudeAdapter factory ----

  @Test
  fun claudeAdapterFactoryPinsTheAdapterVersionAndIsSpawnable() {
    val s = PodSpec.claudeAdapter(model = "m", maxTurns = 5, maxBudgetUsd = 1.0)
    s.requireSpawnable() // the live profile must never trip the fence
    org.junit.Assert.assertEquals(ClaudeAdapterPin.VERSION, s.pinnedVersion)
    org.junit.Assert.assertEquals(PodProvider.CLAUDE, s.provider)
    org.junit.Assert.assertEquals(PodTransport.ACP, s.transport)
    org.junit.Assert.assertEquals(PodAuthMode.MACHINE_CREDENTIAL, s.authMode)
    org.junit.Assert.assertEquals(5, s.maxTurns)
    org.junit.Assert.assertEquals(1.0, s.maxBudgetUsd!!, 0.0)
  }

  // Both runaway knobs are REQUIRED-valid, no defaults (the no-default rule on safety
  // toggles): zero, negative, and non-finite bounds are refused at construction.
  @Test
  fun claudeAdapterFactoryRefusesUnusableBounds() {
    fun throws(block: () -> Unit): Boolean =
      try {
        block()
        false
      } catch (_: IllegalArgumentException) {
        true
      }
    assertTrue(throws { PodSpec.claudeAdapter("m", maxTurns = 0, maxBudgetUsd = 1.0) })
    assertTrue(throws { PodSpec.claudeAdapter("m", maxTurns = -1, maxBudgetUsd = 1.0) })
    assertTrue(throws { PodSpec.claudeAdapter("m", maxTurns = 5, maxBudgetUsd = 0.0) })
    assertTrue(throws { PodSpec.claudeAdapter("m", maxTurns = 5, maxBudgetUsd = -0.5) })
    assertTrue(
      throws { PodSpec.claudeAdapter("m", maxTurns = 5, maxBudgetUsd = Double.POSITIVE_INFINITY) }
    )
    assertTrue(throws { PodSpec.claudeAdapter("m", maxTurns = 5, maxBudgetUsd = Double.NaN) })
  }
}
