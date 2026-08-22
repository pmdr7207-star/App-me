package com.aegis.sentinel.core.safety

import com.aegis.sentinel.core.model.Evidence
import com.aegis.sentinel.core.model.Verdict

/**
 * Security boundary around any LLM-assisted investigation.
 *
 * The model is an *explainer and hypothesis generator*, never an authority. Concretely:
 *
 *  - Untrusted content reaches the model only after [Sanitizer], wrapped in explicit data tags.
 *  - Model output is parsed against a strict schema; anything unparseable is discarded.
 *  - Every claim the model makes must reference evidence IDs that actually exist. Invented
 *    references are dropped and counted as a hallucination signal.
 *  - The model can never raise a verdict beyond what the deterministic pipeline already computed,
 *    and can never authorize a privileged action.
 */
object LlmBoundary {

    /** Actions an LLM may never trigger, directly or indirectly. */
    val FORBIDDEN_ACTIONS: Set<String> = setOf(
        "uninstall",
        "kill_process",
        "grant_permission",
        "revoke_permission",
        "modify_system_setting",
        "replace_dns",
        "modify_protected_file",
        "execute_shell",
        "disable_protection",
        "update_policy",
        "delete_evidence",
    )

    data class ModelFinding(
        val claim: String,
        val evidenceIds: List<String>,
        val suggestedVerdict: Verdict,
        val requestedActions: List<String> = emptyList(),
    )

    data class ValidatedFinding(
        val claim: String,
        val evidenceIds: List<String>,
        val verdict: Verdict,
        val droppedEvidenceIds: List<String>,
        val rejectedActions: List<String>,
    )

    data class ValidationReport(
        val findings: List<ValidatedFinding>,
        val rejected: List<String>,
        val hallucinatedReferences: Int,
        val forbiddenActionAttempts: Int,
    ) {
        val trustworthy: Boolean
            get() = hallucinatedReferences == 0 && forbiddenActionAttempts == 0
    }

    /**
     * Validate model output against the real evidence set and the deterministic verdict ceiling.
     *
     * @param deterministicVerdict verdict computed by the rules/statistics pipeline. The model may
     *   agree or argue *down*, never up.
     */
    fun validate(
        findings: List<ModelFinding>,
        knownEvidence: List<Evidence>,
        deterministicVerdict: Verdict,
    ): ValidationReport {
        val knownIds = knownEvidence.map { it.id }.toSet()
        val validated = mutableListOf<ValidatedFinding>()
        val rejected = mutableListOf<String>()
        var hallucinated = 0
        var forbidden = 0

        for (f in findings) {
            val claim = Sanitizer.sanitize(f.claim, 400).text
            if (claim.isBlank()) {
                rejected += "empty or fully redacted claim"
                continue
            }

            val present = f.evidenceIds.filter { it in knownIds }
            val missing = f.evidenceIds.filterNot { it in knownIds }
            hallucinated += missing.size

            val bad = f.requestedActions.map { it.lowercase().trim() }
                .filter { it in FORBIDDEN_ACTIONS }
            forbidden += bad.size

            // A claim with no verifiable evidence is not admissible.
            if (present.isEmpty()) {
                rejected += "claim without verifiable evidence: $claim"
                continue
            }

            validated += ValidatedFinding(
                claim = claim,
                evidenceIds = present,
                verdict = capVerdict(f.suggestedVerdict, deterministicVerdict),
                droppedEvidenceIds = missing,
                rejectedActions = bad,
            )
        }

        return ValidationReport(
            findings = validated,
            rejected = rejected,
            hallucinatedReferences = hallucinated,
            forbiddenActionAttempts = forbidden,
        )
    }

    /** The model may lower a verdict but never raise it above the deterministic result. */
    fun capVerdict(suggested: Verdict, deterministic: Verdict): Verdict =
        if (suggested.ordinal > deterministic.ordinal) deterministic else suggested

    /**
     * Build the evidence block for a prompt. Only structured, already-sanitized fields are
     * included; raw untrusted content is never concatenated into the instruction section.
     */
    fun buildEvidenceBlock(evidence: List<Evidence>, maxItems: Int = 40): String {
        val sb = StringBuilder()
        sb.append("<evidence_set count=\"").append(minOf(evidence.size, maxItems)).append("\">\n")
        evidence.take(maxItems).forEach { e ->
            sb.append("  <item id=\"").append(sanitizeId(e.id)).append("\"")
                .append(" detector=\"").append(sanitizeId(e.detector)).append("\"")
                .append(" severity=\"").append(e.severity.name).append("\"")
                .append(" confidence=\"").append(String.format("%.2f", e.confidence.value))
                .append("\"")
                .append(" observability=\"").append(e.observability.name).append("\"")
                .append(" supports_malicious=\"").append(e.supportsMalicious).append("\">")
            sb.append(Sanitizer.asUntrustedField("summary", e.summary, 240))
            sb.append("</item>\n")
        }
        sb.append("</evidence_set>")
        return sb.toString()
    }

    private fun sanitizeId(s: String): String = s.replace(Regex("[^A-Za-z0-9_.:\\-]"), "_").take(80)
}
