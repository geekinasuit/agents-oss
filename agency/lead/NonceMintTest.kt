package com.geekinasuit.agency.lead

import com.geekinasuit.agency.pod.PodSpec
import com.geekinasuit.agency.shared.auth.AllowList
import com.geekinasuit.agency.shared.auth.ApprovalVerifier
import com.geekinasuit.agency.shared.auth.Principal
import com.geekinasuit.agency.shared.auth.SchemeKey
import com.geekinasuit.agency.shared.auth.oneOfOne
import com.geekinasuit.agency.shared.journal.EffectReceiver
import com.geekinasuit.agency.shared.journal.SqliteStore
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The gate-open nonce mint (2a.4 step A): the substrate mints a single-use nonce the moment
 * it journals a gate-open, but ONLY under a ceremony auth. The predicate is
 * [LeadAuth.hasApprovers] — the same one the release fold reads to refuse a nonce-less
 * release ([LeadState.foldRelease]); one predicate, read at both the write and the fold. The
 * honest [ScriptedCognition] walk drives a real plan-gate-open, so these cells exercise the
 * write path end to end rather than a hand-appended event.
 */
class NonceMintTest {

  @get:Rule val tmp = TemporaryFolder()

  /** The minimal ceremony auth: one allow-listed principal is enough for [LeadAuth.hasApprovers]
   * to hold, which is all the mint reads. The verifier and quorum are not exercised here — a
   * release's verification is the fold's concern (AuthFoldTest), not the mint's. */
  private fun ceremonyAuth(): LeadAuth =
    LeadAuth(
      allowList =
        AllowList(
          listOf(Principal("operator", role = "authorizer", keys = listOf(SchemeKey("test", "pk-operator"))))
        ),
      verifier = ApprovalVerifier { _, _, _, _ -> true },
      quorum = oneOfOne("operator"),
    )

  private fun daemon(
    dir: File,
    store: SqliteStore,
    auth: LeadAuth,
    cognition: CognitionStrategy = ScriptedCognition(),
    runner: PodRunner = FakePodRunner(),
    faults: FaultInjector = FaultInjector.NONE,
  ): LeadDaemon {
    File(dir, "ticket.txt").also { if (!it.exists()) it.writeText("t1\n") }
    return LeadDaemon(
      store = store,
      cognition = cognition,
      podRunner = runner,
      podSpec = PodSpec.fixture(),
      ticketSource = FileTicketSource(File(dir, "ticket.txt")),
      workdir = dir,
      effects = EffectReceiver(dir.absolutePath),
      leadAuth = auth,
      faults = faults,
    )
  }

  @Test
  fun aCeremonyDaemonMintsANonceBoundToTheOpenedGateAndItsDigest() {
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f = daemon(dir, store, ceremonyAuth()).driveUntilQuiescent()

    val planGateId = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    val digest = f.lead.planArtifactSha
    assertNotNull("the honest walk recorded a plan-artifact digest", digest)

    // Exactly one nonce, bound to the gate that opened AND the digest it opened on. Asserting
    // BOTH bindings against distinct recorded values (planGateId vs the plan-artifact sha) is
    // what makes this non-vacuous: a mint that wrote the wrong field, or an empty nonce, fails.
    assertEquals("one nonce minted at gate-open under a ceremony auth", 1, f.lead.issuedNonces.size)
    val nonce = f.lead.issuedNonces.values.single()
    assertEquals("nonce bound to the opened gate", planGateId, nonce.gateId)
    assertEquals("nonce bound to the gate's digest", digest, nonce.payloadDigest)
    assertTrue("the minted nonce is a non-blank value", nonce.nonce.isNotBlank())

    // The notifier's accessor resolves it: bound to the gate's CURRENT digest, unconsumed.
    val open = f.lead.openGates[planGateId]
    assertNotNull("the plan gate is open", open)
    assertEquals("openNonceFor resolves the minted nonce", nonce, f.lead.openNonceFor(open!!))
    store.close()
  }

  @Test
  fun aPreCeremonyDenyAllDaemonMintsNoNonceThoughItOpensTheGate() {
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val f = daemon(dir, store, LeadAuth.DENY_ALL).driveUntilQuiescent()

    val planGateId = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")
    // Non-vacuous: the gate DID open, so "no nonce" is a real negative and not an empty
    // pipeline that never reached the mint site at all.
    assertTrue("the plan gate opened", planGateId in f.lead.openGates)
    assertTrue("DENY_ALL mints no nonce", f.lead.issuedNonces.isEmpty())
    store.close()
  }

  @Test
  fun aCrashBetweenGateOpenAndMintLeavesTheGateStuckNonceLessNotBypassable() {
    val dir = tmp.newFolder()
    val store = SqliteStore(dir.absolutePath, componentId = "lead")
    val planGateId = gateIdFor(GateKinds.PLAN_APPROVAL, "t1")

    // GATE_OPENED and NONCE_ISSUED are two sequential appends. Crash at the seam between them:
    // the fault fires right after GATE_OPENED, before the mint runs.
    val crash =
      FaultInjector {
        if (it == "after-gate-opened-${GateKinds.PLAN_APPROVAL}") {
          throw RuntimeException("crash after gate-opened, before mint")
        }
      }
    val d1 = daemon(dir, store, ceremonyAuth(), faults = crash)
    var threw = false
    try {
      d1.driveUntilQuiescent()
    } catch (e: RuntimeException) {
      threw = true
    }
    assertTrue("the injected crash fired at the post-gate-open seam", threw)

    // The daemon reached the orphan state: gate open, NO nonce.
    val afterCrash = d1.refold()
    assertTrue("the gate opened before the crash", planGateId in afterCrash.lead.openGates)
    assertTrue("the crash left the gate nonce-less", afterCrash.lead.issuedNonces.isEmpty())

    // A fresh process adopts the orphaned journal and a ceremony release is attempted. Two teeth
    // hold: the seen-gate guard means the honest walk does NOT re-mint the orphan (it stays
    // nonce-less — the liveness gap), and the release fold refuses a nonce-less release under a
    // ceremony auth. Stuck, never bypassable.
    val d2 = daemon(dir, store, ceremonyAuth())
    d2.injectAuthRelease(planGateId, afterCrash.lead.planArtifactSha!!)
    val f = d2.driveUntilQuiescent()
    assertTrue("a restart does not re-mint the orphan", f.lead.issuedNonces.isEmpty())
    assertFalse("the orphan gate is NOT released", planGateId in f.lead.releasedGates)
    assertTrue(
      "the nonce-less release folded stale",
      f.lead.staleReleases.any { it.second == planGateId },
    )
    store.close()
  }
}
