package com.aegis.sentinel.core.safety

/**
 * Sanitization for attacker-influenceable text.
 *
 * Threat: APK strings, filenames, URLs, page content, logs and network responses are all authored
 * by a potential adversary. If any of that text reaches an LLM prompt verbatim it becomes a prompt
 * injection channel; if it reaches the UI verbatim it becomes a spoofing channel.
 *
 * This sanitizer is deliberately conservative and lossy. It never tries to "understand" the input;
 * it neutralizes structure and truncates. Sanitized text is always labelled UNTRUSTED downstream.
 */
object Sanitizer {

    /** Characters that let text escape a rendering or prompt context. */
    private val CONTROL_CHARS = Regex("[\\p{Cntrl}&&[^\n\t]]")

    /** Bidi/zero-width/format characters used for homograph and display spoofing. */
    private val INVISIBLE_OR_BIDI = Regex(
        "[\\u200B-\\u200F\\u202A-\\u202E\\u2066-\\u2069\\uFEFF\\u00AD]"
    )

    /**
     * Phrases that attempt to redirect an assistant. Matching is done on a normalized copy so
     * spacing and punctuation tricks do not evade it. We redact rather than drop, so an
     * investigator can still see that an injection attempt occurred.
     */
    private val INJECTION_PATTERNS: List<Regex> = listOf(
        "ignore (all )?(previous|prior|above) (instructions?|prompts?|rules?)",
        "disregard (all )?(previous|prior|above|your) (instructions?|rules?|training)",
        "forget (everything|all previous|your instructions)",
        "you are now (a|an) ",
        "new (system )?(instructions?|prompt|role)",
        "system\\s*[:=]\\s*",
        "</?(system|assistant|user|tool)>",
        "\\[/?(inst|sys|system)\\]",
        "<\\|(im_start|im_end|system|user|assistant|endoftext)\\|>",
        "act as (a|an|the) ",
        "developer mode",
        "jailbreak",
        "reveal (your|the) (system )?(prompt|instructions?)",
        "print (your|the) (system )?(prompt|instructions?)",
        "override (the )?(security|safety) (policy|rules?)",
        "mark (this|the) (app|package|file) as (safe|benign|trusted)",
        "set (the )?(verdict|threat score|risk) to ",
        "do not (report|flag|alert)",
        "uninstall ",
        "grant .{0,20}permission",
        "execute (the )?(shell|command)",
    ).map { Regex(it, setOf(RegexOption.IGNORE_CASE)) }

    const val REDACTION = "[REDACTED-INJECTION]"
    const val DEFAULT_MAX_LENGTH = 512

    data class Result(
        val text: String,
        val injectionAttempts: Int,
        val truncated: Boolean,
    ) {
        val suspicious: Boolean get() = injectionAttempts > 0
    }

    /**
     * Neutralize a single untrusted string.
     *
     * Guarantees on the output: no control characters other than tab, no bidi/zero-width
     * characters, no unbounded length, and no recognized instruction-injection phrasing.
     */
    fun sanitize(raw: String?, maxLength: Int = DEFAULT_MAX_LENGTH): Result {
        if (raw.isNullOrEmpty()) return Result("", 0, false)

        var s = raw
        s = INVISIBLE_OR_BIDI.replace(s, "")
        s = CONTROL_CHARS.replace(s, " ")
        s = s.replace('\n', ' ').replace('\t', ' ')

        var attempts = 0
        for (p in INJECTION_PATTERNS) {
            val replaced = p.replace(s) {
                attempts++
                REDACTION
            }
            s = replaced
        }

        // Collapse whitespace last so redactions read cleanly.
        s = s.replace(Regex("\\s{2,}"), " ").trim()

        val truncated = s.length > maxLength
        if (truncated) s = s.substring(0, maxLength) + "…"

        return Result(s, attempts, truncated)
    }

    /**
     * Render an untrusted value for inclusion in a structured evidence field.
     * Always wrapped in explicit delimiters and an untrusted marker so a downstream model cannot
     * confuse data with instructions.
     */
    fun asUntrustedField(name: String, raw: String?, maxLength: Int = DEFAULT_MAX_LENGTH): String {
        val r = sanitize(raw, maxLength)
        val flag = if (r.suspicious) " injection_attempts=${r.injectionAttempts}" else ""
        return "<untrusted name=\"${sanitizeName(name)}\"$flag>${r.text}</untrusted>"
    }

    private fun sanitizeName(name: String): String =
        name.replace(Regex("[^A-Za-z0-9_.\\-]"), "_").take(64)

    /**
     * Extract a registrable-ish host from a URL without executing or resolving anything.
     * Returns null when the input is not a parseable absolute URL, which is itself a signal.
     */
    fun hostOf(url: String?): String? {
        if (url.isNullOrBlank()) return null
        val cleaned = INVISIBLE_OR_BIDI.replace(url.trim(), "")
        val m = Regex("^[A-Za-z][A-Za-z0-9+.\\-]*://([^/?#\\s]+)").find(cleaned) ?: return null
        val authority = m.groupValues[1]
        val hostPort = authority.substringAfterLast('@')
        val host = if (hostPort.startsWith("[")) {
            hostPort.substringAfter('[').substringBefore(']')
        } else {
            hostPort.substringBefore(':')
        }
        val h = host.lowercase()
        return h.ifBlank { null }
    }
}
