package com.aegis.sentinel.core.model

/**
 * Normalized, platform-agnostic event model.
 *
 * Every event that enters the detection pipeline MUST be expressible here. The Android layer is
 * responsible for translating platform observations into these types and for attaching an honest
 * [Observability] marker describing how the data was obtained. Nothing in this module assumes a
 * capability that the platform layer has not actually verified at runtime.
 */

/** Monotonic-ish wall clock in epoch milliseconds. */
typealias EpochMillis = Long

/**
 * How a signal was obtained. Used by the fusion layer to weight evidence: directly observed
 * platform facts outrank inferred ones, and inferred outranks reported-by-untrusted-content.
 */
enum class Observability {
    /** Read from a first-party Android API with a granted permission. */
    PLATFORM_DIRECT,

    /** Derived by correlating several direct observations. */
    DERIVED,

    /** Parsed out of attacker-influenceable content (APK strings, filenames, URLs, page content). */
    UNTRUSTED_CONTENT,
}

enum class EventType {
    APP_INSTALLED,
    APP_UPDATED,
    APP_REMOVED,
    APP_FOREGROUND,
    APP_BACKGROUND,
    PERMISSION_GRANTED,
    PERMISSION_REVOKED,
    SPECIAL_ACCESS_CHANGED,
    NETWORK_FLOW,
    DNS_QUERY,
    FILE_WRITE,
    FILE_DELETE,
    FILE_RENAME,
    DOWNLOAD_COMPLETED,
    INSTALL_SOURCE_OBSERVED,
    APP_SIGNING_OBSERVED,
    SYSTEM_STATE,
}

/**
 * A single normalized observation.
 *
 * [attributes] carries detector-specific detail. Keys are stable identifiers; values are already
 * sanitized by the platform layer when they originate from untrusted content.
 */
data class Event(
    val id: String,
    val type: EventType,
    val timestamp: EpochMillis,
    val packageName: String?,
    val observability: Observability,
    val attributes: Map<String, String> = emptyMap(),
    val numeric: Map<String, Double> = emptyMap(),
) {
    fun num(key: String): Double? = numeric[key]
    fun attr(key: String): String? = attributes[key]
}

/** Confidence in a detector's own output, before cross-signal fusion. */
@JvmInline
value class Confidence(val value: Double) {
    init {
        require(value in 0.0..1.0) { "confidence out of range: $value" }
    }

    companion object {
        val ZERO = Confidence(0.0)
    }
}

/**
 * How much the pipeline trusts a detector as a source, independent of any single result.
 * Reliability is a property of the *detector and its data source*; confidence is a property of the
 * individual observation.
 */
@JvmInline
value class Reliability(val value: Double) {
    init {
        require(value in 0.0..1.0) { "reliability out of range: $value" }
    }
}

enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

/**
 * A traceable unit of evidence. Every verdict must be reducible to a set of these.
 *
 * [supportsMalicious] distinguishes incriminating evidence from exculpatory evidence, so the
 * fusion layer can represent contradictions rather than silently dropping them.
 */
data class Evidence(
    val id: String,
    val detector: String,
    val packageName: String?,
    val timestamp: EpochMillis,
    val severity: Severity,
    val confidence: Confidence,
    val reliability: Reliability,
    val observability: Observability,
    val summary: String,
    val sourceEventIds: List<String> = emptyList(),
    val supportsMalicious: Boolean = true,
    val attributes: Map<String, String> = emptyMap(),
)

/** Terminal classification for a subject (usually a package). */
enum class Verdict { BENIGN, UNKNOWN, SUSPICIOUS, LIKELY_MALICIOUS }

/**
 * Result of fusing evidence for one subject.
 *
 * [contradictions] is deliberately part of the output: an assessment that cannot show what argued
 * against it is not auditable.
 */
data class Assessment(
    val subject: String,
    val verdict: Verdict,
    val score: Double,
    val confidence: Double,
    val supporting: List<Evidence>,
    val contradictions: List<Evidence>,
    val rationale: List<String>,
    val timestamp: EpochMillis,
)
