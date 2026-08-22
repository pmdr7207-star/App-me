package com.aegis.sentinel.core.response

import com.aegis.sentinel.core.model.AccessClass
import com.aegis.sentinel.core.model.CapabilityRegistry
import com.aegis.sentinel.core.model.Verdict

/**
 * Response policy.
 *
 * The central rule: an action is only ever offered when the platform genuinely supports it on this
 * device. If the capability is missing, the decision is [ActionClass.UNAVAILABLE] together with a
 * user-visible reason — the product never reports success for something it did not do.
 */
enum class ActionClass {
    /** Keep watching; record only. */
    OBSERVE,

    /** Notify the user. Always available. */
    ALERT,

    /** Requires an explicit user confirmation, typically handing off to a system UI. */
    USER_CONFIRM,

    /** Safe to perform automatically: reversible, low risk, deterministic, platform supported. */
    SAFE_AUTOMATIC,

    /** Needs a privilege this app does not hold (device owner / system). */
    SPECIAL_PRIVILEGE,

    /** Verified impossible on this platform. Must be surfaced honestly. */
    UNAVAILABLE,
}

data class ResponseAction(
    val id: String,
    val title: String,
    val actionClass: ActionClass,
    /** Capability that must be usable for this action to be offered. */
    val requiredCapability: String?,
    val reversible: Boolean,
    val rationale: String,
)

data class ResponseDecision(
    val subject: String,
    val actions: List<ResponseAction>,
    val blocked: List<ResponseAction>,
    val explanation: String,
)

class ResponsePolicyEngine(private val capabilities: CapabilityRegistry) {

    /**
     * Decide the response set for a verdict.
     *
     * Automatic actions are permitted only when every one of these holds:
     * reversible, low risk, deterministic, and backed by a verified platform capability.
     */
    fun decide(subject: String, verdict: Verdict, confidence: Double): ResponseDecision {
        val candidates = candidatesFor(verdict, confidence)
        val available = mutableListOf<ResponseAction>()
        val blocked = mutableListOf<ResponseAction>()

        for (a in candidates) {
            val cap = a.requiredCapability
            if (cap == null || capabilities.isUsable(cap)) {
                available += a
            } else {
                val declared = capabilities[cap]
                val why = when (declared?.accessClass) {
                    AccessClass.DEVICE_OWNER ->
                        "requires device owner provisioning, which this app does not have"
                    AccessClass.SYSTEM_OEM ->
                        "requires system or OEM privilege"
                    AccessClass.ROOT_ONLY ->
                        "requires root, which is out of scope"
                    AccessClass.UNAVAILABLE ->
                        "is not possible on this Android version"
                    AccessClass.UNKNOWN, null ->
                        "has not been verified on this device and is therefore disabled"
                    else ->
                        "is not currently granted"
                }
                blocked += a.copy(
                    actionClass = when (declared?.accessClass) {
                        AccessClass.DEVICE_OWNER, AccessClass.SYSTEM_OEM ->
                            ActionClass.SPECIAL_PRIVILEGE
                        AccessClass.ROOT_ONLY, AccessClass.UNAVAILABLE ->
                            ActionClass.UNAVAILABLE
                        else -> ActionClass.UNAVAILABLE
                    },
                    rationale = "Unavailable: ${a.title.lowercase()} $why.",
                )
            }
        }

        return ResponseDecision(
            subject = subject,
            actions = available,
            blocked = blocked,
            explanation = buildExplanation(verdict, confidence, available.size, blocked.size),
        )
    }

    private fun candidatesFor(verdict: Verdict, confidence: Double): List<ResponseAction> =
        when (verdict) {
            Verdict.BENIGN, Verdict.UNKNOWN -> listOf(OBSERVE)

            Verdict.SUSPICIOUS -> buildList {
                add(OBSERVE)
                add(ALERT)
                add(OPEN_APP_SETTINGS)
                if (confidence >= 0.5) add(RESTRICT_BACKGROUND_HINT)
            }

            Verdict.LIKELY_MALICIOUS -> buildList {
                add(ALERT)
                add(OPEN_APP_SETTINGS)
                add(REQUEST_UNINSTALL)
                add(PRESERVE_EVIDENCE)
                add(FORCE_STOP)
            }
        }

    private fun buildExplanation(
        verdict: Verdict,
        confidence: Double,
        availableCount: Int,
        blockedCount: Int,
    ): String {
        val base = when (verdict) {
            Verdict.BENIGN -> "No action required."
            Verdict.UNKNOWN -> "Insufficient evidence; continuing to observe."
            Verdict.SUSPICIOUS ->
                "Suspicious behaviour with ${pct(confidence)} confidence; user review recommended."
            Verdict.LIKELY_MALICIOUS ->
                "Strong multi-source evidence (${pct(confidence)} confidence); removal recommended."
        }
        val blockedNote =
            if (blockedCount > 0) " $blockedCount action(s) are unavailable on this device." else ""
        return "$base $availableCount action(s) available.$blockedNote"
    }

    private fun pct(d: Double) = "${(d * 100).toInt()}%"

    companion object {
        /** Capability IDs referenced by actions; defined by the platform layer at runtime. */
        const val CAP_REQUEST_UNINSTALL = "action.request_uninstall"
        const val CAP_APP_SETTINGS = "action.open_app_settings"
        const val CAP_FORCE_STOP = "action.force_stop"
        const val CAP_EVIDENCE_STORE = "action.preserve_evidence"

        val OBSERVE = ResponseAction(
            id = "observe",
            title = "Continue monitoring",
            actionClass = ActionClass.OBSERVE,
            requiredCapability = null,
            reversible = true,
            rationale = "Keep collecting evidence without interfering with the app.",
        )

        val ALERT = ResponseAction(
            id = "alert",
            title = "Notify the user",
            actionClass = ActionClass.ALERT,
            requiredCapability = null,
            reversible = true,
            rationale = "Raise a notification describing the finding and its evidence.",
        )

        /**
         * Opening the system app-details screen is a normal-app capability and is the supported way
         * to let the user revoke permissions or uninstall.
         */
        val OPEN_APP_SETTINGS = ResponseAction(
            id = "open_app_settings",
            title = "Open system app settings",
            actionClass = ActionClass.USER_CONFIRM,
            requiredCapability = CAP_APP_SETTINGS,
            reversible = true,
            rationale = "Hands off to the system UI where the user can revoke access or uninstall.",
        )

        /**
         * ACTION_DELETE / ACTION_UNINSTALL_PACKAGE shows a system confirmation dialog. The app
         * cannot uninstall silently, and this action never claims otherwise.
         */
        val REQUEST_UNINSTALL = ResponseAction(
            id = "request_uninstall",
            title = "Request uninstall",
            actionClass = ActionClass.USER_CONFIRM,
            requiredCapability = CAP_REQUEST_UNINSTALL,
            reversible = false,
            rationale = "Asks the system to show the uninstall confirmation dialog to the user.",
        )

        val PRESERVE_EVIDENCE = ResponseAction(
            id = "preserve_evidence",
            title = "Preserve forensic evidence",
            actionClass = ActionClass.SAFE_AUTOMATIC,
            requiredCapability = CAP_EVIDENCE_STORE,
            reversible = true,
            rationale = "Writes an integrity-protected copy of the incident record to app storage.",
        )

        /**
         * A non-root, non-device-owner app cannot force-stop another app. Declared so the UI can
         * show it as explicitly unavailable rather than silently omitting it.
         */
        val FORCE_STOP = ResponseAction(
            id = "force_stop",
            title = "Force stop the app",
            actionClass = ActionClass.SPECIAL_PRIVILEGE,
            requiredCapability = CAP_FORCE_STOP,
            reversible = true,
            rationale = "Terminating another app requires device owner or system privilege.",
        )

        val RESTRICT_BACKGROUND_HINT = ResponseAction(
            id = "restrict_background_hint",
            title = "Guide the user to restrict background activity",
            actionClass = ActionClass.USER_CONFIRM,
            requiredCapability = CAP_APP_SETTINGS,
            reversible = true,
            rationale = "Opens the system screen where background use can be limited.",
        )
    }
}
