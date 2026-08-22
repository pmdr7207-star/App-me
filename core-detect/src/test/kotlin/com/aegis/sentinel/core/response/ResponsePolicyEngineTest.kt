package com.aegis.sentinel.core.response

import com.aegis.sentinel.core.model.AccessClass
import com.aegis.sentinel.core.model.Capability
import com.aegis.sentinel.core.model.CapabilityRegistry
import com.aegis.sentinel.core.model.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ResponsePolicyEngineTest {

    private fun registry(forceStopUsable: Boolean = false) = CapabilityRegistry(
        listOf(
            Capability(
                ResponsePolicyEngine.CAP_APP_SETTINGS,
                "Open system app details",
                AccessClass.NORMAL_APP,
                productionEnabled = true,
            ),
            Capability(
                ResponsePolicyEngine.CAP_REQUEST_UNINSTALL,
                "Request package uninstall via system dialog",
                AccessClass.NORMAL_APP,
                productionEnabled = true,
            ),
            Capability(
                ResponsePolicyEngine.CAP_EVIDENCE_STORE,
                "Write incident evidence to app-private storage",
                AccessClass.NORMAL_APP,
                productionEnabled = true,
            ),
            Capability(
                ResponsePolicyEngine.CAP_FORCE_STOP,
                "Force stop another app",
                AccessClass.DEVICE_OWNER,
                productionEnabled = forceStopUsable,
            ),
        )
    )

    @Test
    fun `benign verdict only observes`() {
        val d = ResponsePolicyEngine(registry()).decide("pkg", Verdict.BENIGN, 0.9)
        assertEquals(listOf("observe"), d.actions.map { it.id })
    }

    /** The central honesty rule: unsupported actions are reported as unavailable, never faked. */
    @Test
    fun `force stop is reported unavailable rather than offered`() {
        val d = ResponsePolicyEngine(registry(forceStopUsable = false))
            .decide("pkg", Verdict.LIKELY_MALICIOUS, 0.9)

        assertFalse("force_stop must not be offered", d.actions.any { it.id == "force_stop" })
        val blocked = d.blocked.single { it.id == "force_stop" }
        assertEquals(ActionClass.SPECIAL_PRIVILEGE, blocked.actionClass)
        assertTrue(blocked.rationale.contains("device owner"))
        assertTrue(d.explanation.contains("unavailable"))
    }

    @Test
    fun `uninstall is offered only as a user confirmed action`() {
        val d = ResponsePolicyEngine(registry()).decide("pkg", Verdict.LIKELY_MALICIOUS, 0.9)
        val uninstall = d.actions.single { it.id == "request_uninstall" }
        assertEquals(
            "uninstall must never be automatic",
            ActionClass.USER_CONFIRM,
            uninstall.actionClass,
        )
    }

    @Test
    fun `automatic actions are reversible only`() {
        val d = ResponsePolicyEngine(registry()).decide("pkg", Verdict.LIKELY_MALICIOUS, 0.9)
        d.actions.filter { it.actionClass == ActionClass.SAFE_AUTOMATIC }.forEach {
            assertTrue("automatic action ${it.id} must be reversible", it.reversible)
        }
    }

    @Test
    fun `unknown capability is never usable`() {
        val reg = CapabilityRegistry(
            listOf(
                Capability("x.unknown", "unverified", AccessClass.UNKNOWN, productionEnabled = false),
            )
        )
        assertFalse(reg.isUsable("x.unknown"))
        assertFalse(reg.isUsable("does.not.exist"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `unknown capability cannot be marked production enabled`() {
        Capability("x", "d", AccessClass.UNKNOWN, productionEnabled = true)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `root only capability cannot be marked production enabled`() {
        Capability("x", "d", AccessClass.ROOT_ONLY, productionEnabled = true)
    }

    @Test
    fun `suspicious verdict escalates gradually with confidence`() {
        val engine = ResponsePolicyEngine(registry())
        val low = engine.decide("pkg", Verdict.SUSPICIOUS, 0.2)
        val high = engine.decide("pkg", Verdict.SUSPICIOUS, 0.8)
        assertTrue(high.actions.size >= low.actions.size)
        assertFalse(
            "suspicious must never propose uninstall",
            high.actions.any { it.id == "request_uninstall" },
        )
    }
}
