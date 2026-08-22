package com.aegis.sentinel.core.fusion

import com.aegis.sentinel.core.model.Assessment
import com.aegis.sentinel.core.model.EpochMillis
import com.aegis.sentinel.core.model.Evidence
import com.aegis.sentinel.core.model.Observability
import com.aegis.sentinel.core.model.Severity
import com.aegis.sentinel.core.model.Verdict
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min

/**
 * Fuses independent evidence into a single auditable assessment.
 *
 * Properties this implementation guarantees, and that are covered by unit tests:
 *
 *  1. A single low-severity item can never reach a malicious verdict, regardless of its confidence.
 *  2. Corroboration must be *independent*: several items from one detector are heavily discounted,
 *     so a single noisy or compromised detector cannot drive a verdict on its own.
 *  3. Evidence derived from attacker-controlled content is capped in influence.
 *  4. Contradicting (exculpatory) evidence actively reduces the score and is always reported.
 */
class EvidenceFusion(private val policy: FusionPolicy = FusionPolicy()) {

    fun assess(subject: String, evidence: List<Evidence>, now: EpochMillis): Assessment {
        val relevant = evidence.filter { it.packageName == null || it.packageName == subject }
        val supporting = relevant.filter { it.supportsMalicious }
        val contradicting = relevant.filter { !it.supportsMalicious }

        if (supporting.isEmpty()) {
            return Assessment(
                subject = subject,
                verdict = Verdict.BENIGN.takeIf { contradicting.isNotEmpty() } ?: Verdict.UNKNOWN,
                score = 0.0,
                confidence = if (contradicting.isEmpty()) 0.0 else 0.4,
                supporting = emptyList(),
                contradictions = contradicting,
                rationale = listOf(
                    if (contradicting.isEmpty()) "No evidence collected for $subject."
                    else "Only exculpatory evidence present for $subject.",
                ),
                timestamp = now,
            )
        }

        val rationale = mutableListOf<String>()

        // --- Weight each item, discounting by recency, observability and severity. -------------
        val weighted = supporting.map { e -> e to itemWeight(e, now) }

        // --- Independence: group by detector, apply diminishing returns within a group. --------
        val byDetector = weighted.groupBy { it.first.detector }
        var maliciousMass = 0.0
        for ((detector, items) in byDetector) {
            val sorted = items.sortedByDescending { it.second }
            var groupMass = 0.0
            sorted.forEachIndexed { index, (_, w) ->
                // First item counts fully; each subsequent item from the SAME detector is
                // discounted geometrically. Independent corroboration is what earns score.
                groupMass += w * Math.pow(policy.sameDetectorDecay, index.toDouble())
            }
            val capped = min(groupMass, policy.maxMassPerDetector)
            if (capped < groupMass) {
                rationale += "Detector '$detector' contribution capped at ${fmt(capped)}."
            }
            maliciousMass += capped
        }

        val distinctDetectors = byDetector.keys.size
        val distinctHighQuality = supporting.count {
            it.observability != Observability.UNTRUSTED_CONTENT &&
                it.severity >= Severity.MEDIUM
        }

        // --- Exculpatory evidence subtracts. ---------------------------------------------------
        val exculpatoryMass = contradicting.sumOf { itemWeight(it, now) }
        if (exculpatoryMass > 0.0) {
            rationale += "Exculpatory evidence reduced score by ${fmt(exculpatoryMass)}."
        }

        val rawScore = maliciousMass - policy.contradictionWeight * exculpatoryMass
        val score = clamp(rawScore, 0.0, 1.0)

        // --- Verdict gating. Structural rules, not just a threshold. ---------------------------
        val maxSeverity = supporting.maxOf { it.severity }
        val verdict = decideVerdict(
            score = score,
            distinctDetectors = distinctDetectors,
            distinctHighQuality = distinctHighQuality,
            maxSeverity = maxSeverity,
            rationale = rationale,
        )

        val confidence = computeConfidence(supporting, distinctDetectors, exculpatoryMass)

        rationale += "Fused ${supporting.size} supporting item(s) from $distinctDetectors " +
            "detector(s); score=${fmt(score)}, confidence=${fmt(confidence)}."

        return Assessment(
            subject = subject,
            verdict = verdict,
            score = score,
            confidence = confidence,
            supporting = supporting.sortedByDescending { itemWeight(it, now) },
            contradictions = contradicting,
            rationale = rationale,
            timestamp = now,
        )
    }

    private fun decideVerdict(
        score: Double,
        distinctDetectors: Int,
        distinctHighQuality: Int,
        maxSeverity: Severity,
        rationale: MutableList<String>,
    ): Verdict {
        // Rule 1: a lone weak signal is never conclusive.
        if (maxSeverity <= Severity.LOW) {
            rationale += "Max severity is $maxSeverity; capped below SUSPICIOUS."
            return if (score >= policy.suspiciousThreshold && distinctDetectors >= 2) {
                Verdict.SUSPICIOUS
            } else {
                Verdict.UNKNOWN
            }
        }

        // Rule 2: a malicious verdict requires independent, high-quality corroboration.
        if (score >= policy.maliciousThreshold) {
            if (distinctDetectors >= policy.minDetectorsForMalicious &&
                distinctHighQuality >= policy.minHighQualityForMalicious
            ) {
                return Verdict.LIKELY_MALICIOUS
            }
            rationale += "Score reached ${fmt(score)} but corroboration was insufficient " +
                "($distinctDetectors detector(s), $distinctHighQuality high-quality item(s)); " +
                "capped at SUSPICIOUS."
            return Verdict.SUSPICIOUS
        }

        if (score >= policy.suspiciousThreshold) return Verdict.SUSPICIOUS
        return Verdict.UNKNOWN
    }

    private fun computeConfidence(
        supporting: List<Evidence>,
        distinctDetectors: Int,
        exculpatoryMass: Double,
    ): Double {
        val meanQuality = supporting.sumOf { it.confidence.value * it.reliability.value } /
            supporting.size
        val corroboration = min(1.0, distinctDetectors / policy.minDetectorsForMalicious.toDouble())
        val ambiguityPenalty = min(policy.maxAmbiguityPenalty, exculpatoryMass)
        return clamp(meanQuality * (0.5 + 0.5 * corroboration) - ambiguityPenalty, 0.0, 1.0)
    }

    private fun itemWeight(e: Evidence, now: EpochMillis): Double {
        val sev = policy.severityWeight(e.severity)
        val obs = policy.observabilityWeight(e.observability)
        val recency = recencyFactor(e.timestamp, now)
        return sev * obs * recency * e.confidence.value * e.reliability.value
    }

    private fun recencyFactor(ts: EpochMillis, now: EpochMillis): Double {
        val ageMs = max(0L, now - ts)
        if (policy.halfLifeMs <= 0L) return 1.0
        val halfLives = ageMs.toDouble() / policy.halfLifeMs.toDouble()
        return max(policy.minRecencyFactor, Math.pow(0.5, halfLives))
    }

    private fun fmt(d: Double): String = String.format("%.3f", d)

    private fun clamp(v: Double, lo: Double, hi: Double) = min(hi, max(lo, v))
}

data class FusionPolicy(
    val suspiciousThreshold: Double = 0.35,
    val maliciousThreshold: Double = 0.70,
    /** Independent detectors required before a LIKELY_MALICIOUS verdict is permitted. */
    val minDetectorsForMalicious: Int = 3,
    val minHighQualityForMalicious: Int = 2,
    /** Geometric discount applied to repeated findings from the same detector. */
    val sameDetectorDecay: Double = 0.35,
    /** No single detector may contribute more than this to the score. */
    val maxMassPerDetector: Double = 0.45,
    val contradictionWeight: Double = 1.0,
    val maxAmbiguityPenalty: Double = 0.3,
    val halfLifeMs: Long = 72L * 60 * 60 * 1000,
    val minRecencyFactor: Double = 0.15,
) {
    init {
        require(maliciousThreshold > suspiciousThreshold) { "thresholds must be ordered" }
        require(sameDetectorDecay in 0.0..1.0) { "decay must be a fraction" }
        // Structural guarantee: no single detector can single-handedly reach the malicious
        // threshold, which is what makes rule 2 meaningful rather than cosmetic.
        require(maxMassPerDetector < maliciousThreshold) {
            "a single detector must not be able to reach the malicious threshold"
        }
    }

    fun severityWeight(s: Severity): Double = when (s) {
        Severity.INFO -> 0.05
        Severity.LOW -> 0.12
        Severity.MEDIUM -> 0.30
        Severity.HIGH -> 0.50
        Severity.CRITICAL -> 0.70
    }

    fun observabilityWeight(o: Observability): Double = when (o) {
        Observability.PLATFORM_DIRECT -> 1.0
        Observability.DERIVED -> 0.8
        // Attacker-influenceable content is intentionally weak evidence.
        Observability.UNTRUSTED_CONTENT -> 0.35
    }
}

internal fun approxEquals(a: Double, b: Double, eps: Double = 1e-9) = abs(a - b) < eps
