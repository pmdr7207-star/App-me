package com.aegis.sentinel.core.fusion

import com.aegis.sentinel.core.model.Confidence
import com.aegis.sentinel.core.model.Evidence
import com.aegis.sentinel.core.model.Observability
import com.aegis.sentinel.core.model.Reliability
import com.aegis.sentinel.core.model.Severity
import com.aegis.sentinel.core.model.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EvidenceFusionTest {

    private val now = 1_000_000L

    private fun ev(
        id: String,
        detector: String,
        severity: Severity = Severity.HIGH,
        confidence: Double = 0.9,
        reliability: Double = 0.9,
        observability: Observability = Observability.PLATFORM_DIRECT,
        supports: Boolean = true,
        ts: Long = now,
    ) = Evidence(
        id = id,
        detector = detector,
        packageName = "com.example.suspect",
        timestamp = ts,
        severity = severity,
        confidence = Confidence(confidence),
        reliability = Reliability(reliability),
        observability = observability,
        summary = "test evidence $id",
        supportsMalicious = supports,
    )

    @Test
    fun `no evidence yields unknown and never a malicious verdict`() {
        val a = EvidenceFusion().assess("com.example.suspect", emptyList(), now)
        assertEquals(Verdict.UNKNOWN, a.verdict)
        assertEquals(0.0, a.score, 1e-9)
    }

    /** Core requirement: a single weak event must not produce a definitive verdict. */
    @Test
    fun `single low severity item cannot exceed unknown`() {
        val a = EvidenceFusion().assess(
            "com.example.suspect",
            listOf(ev("e1", "d1", severity = Severity.LOW, confidence = 1.0, reliability = 1.0)),
            now,
        )
        assertEquals(Verdict.UNKNOWN, a.verdict)
    }

    /** A single detector, however loud, must never reach LIKELY_MALICIOUS on its own. */
    @Test
    fun `one detector alone cannot reach likely malicious`() {
        val many = (1..12).map {
            ev("e$it", "single.detector", severity = Severity.CRITICAL, confidence = 1.0, reliability = 1.0)
        }
        val a = EvidenceFusion().assess("com.example.suspect", many, now)
        assertNotEquals(Verdict.LIKELY_MALICIOUS, a.verdict)
        assertTrue(
            "expected capping rationale, got ${a.rationale}",
            a.rationale.any { it.contains("capped", ignoreCase = true) },
        )
    }

    /** Independent, high-quality corroboration is what earns a malicious verdict. */
    @Test
    fun `three independent high quality detectors reach likely malicious`() {
        val e = listOf(
            ev("e1", "file.transformation", severity = Severity.CRITICAL, confidence = 0.95, reliability = 0.95),
            ev("e2", "network.behavior", severity = Severity.HIGH, confidence = 0.9, reliability = 0.9),
            ev("e3", "correlate.attackchain", severity = Severity.CRITICAL, confidence = 0.9, reliability = 0.9),
        )
        val a = EvidenceFusion().assess("com.example.suspect", e, now)
        assertEquals(Verdict.LIKELY_MALICIOUS, a.verdict)
        assertTrue(a.confidence > 0.5)
    }

    /** Evidence sourced from attacker-controlled text must be structurally weak. */
    @Test
    fun `untrusted content evidence is heavily discounted`() {
        val trusted = listOf(
            ev("t1", "d1", observability = Observability.PLATFORM_DIRECT),
            ev("t2", "d2", observability = Observability.PLATFORM_DIRECT),
            ev("t3", "d3", observability = Observability.PLATFORM_DIRECT),
        )
        val untrusted = listOf(
            ev("u1", "d1", observability = Observability.UNTRUSTED_CONTENT),
            ev("u2", "d2", observability = Observability.UNTRUSTED_CONTENT),
            ev("u3", "d3", observability = Observability.UNTRUSTED_CONTENT),
        )
        val fusion = EvidenceFusion()
        val hi = fusion.assess("com.example.suspect", trusted, now)
        val lo = fusion.assess("com.example.suspect", untrusted, now)
        assertTrue("untrusted (${lo.score}) must score below trusted (${hi.score})", lo.score < hi.score)
    }

    /** Contradictions must lower the score and remain visible in the output. */
    @Test
    fun `exculpatory evidence lowers score and is reported`() {
        val supporting = listOf(
            ev("e1", "d1", severity = Severity.HIGH),
            ev("e2", "d2", severity = Severity.HIGH),
            ev("e3", "d3", severity = Severity.HIGH),
        )
        val fusion = EvidenceFusion()
        val without = fusion.assess("com.example.suspect", supporting, now)
        val with = fusion.assess(
            "com.example.suspect",
            supporting + ev("x1", "d4", severity = Severity.HIGH, supports = false),
            now,
        )
        assertTrue("contradiction must reduce score", with.score < without.score)
        assertEquals(1, with.contradictions.size)
    }

    /** Old evidence must decay so a stale finding cannot dominate forever. */
    @Test
    fun `recency decay reduces the weight of old evidence`() {
        val fresh = listOf(
            ev("e1", "d1", ts = now),
            ev("e2", "d2", ts = now),
            ev("e3", "d3", ts = now),
        )
        val old = listOf(
            ev("e1", "d1", ts = now - 30L * 24 * 3600 * 1000),
            ev("e2", "d2", ts = now - 30L * 24 * 3600 * 1000),
            ev("e3", "d3", ts = now - 30L * 24 * 3600 * 1000),
        )
        val fusion = EvidenceFusion()
        assertTrue(fusion.assess("com.example.suspect", old, now).score <
            fusion.assess("com.example.suspect", fresh, now).score)
    }

    /** Every assessment must be traceable back to concrete evidence. */
    @Test
    fun `assessment retains full evidence trace`() {
        val e = listOf(ev("e1", "d1"), ev("e2", "d2"), ev("e3", "d3"))
        val a = EvidenceFusion().assess("com.example.suspect", e, now)
        assertEquals(setOf("e1", "e2", "e3"), a.supporting.map { it.id }.toSet())
        assertTrue(a.rationale.isNotEmpty())
    }

    /** The policy itself must make single-detector dominance impossible. */
    @Test(expected = IllegalArgumentException::class)
    fun `policy rejects a detector cap that could alone reach malicious`() {
        FusionPolicy(maliciousThreshold = 0.5, maxMassPerDetector = 0.6)
    }
}
