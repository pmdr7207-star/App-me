# Architecture — Aegis Sentinel X

## Module layout

```
core-detect/     Pure Kotlin/JVM. No Android types. All decision logic lives here,
                 which is what makes the security properties unit-testable.
app/             Android layer: capability discovery, telemetry collection, services,
                 encrypted evidence store, Compose UI.
tools/verify/    Standalone harness executing the same assertions as the JUnit suites.
ci/              CI workflow definition (see README for why it is not in .github/).
```

The dependency direction is strictly `app → core-detect`. The core never imports Android, so a
detector cannot accidentally depend on a platform capability without going through the registry.

## Detection pipeline

```
EVENT → NORMALIZE → FEATURES → TEMPORAL CONTEXT → BASELINE → ANOMALY
      → CROSS-SIGNAL CORRELATION → CONFIDENCE → THREAT SCORE → POLICY
```

Implemented in `DetectionPipeline.ingest`:

1. **Backpressure** — token bucket; excess events are dropped and *counted*.
2. **Detectors** — file defense, network behaviour, attack-chain correlation run over the
   normalized `Event`.
3. **Memory gate** — the behaviour is recorded in `AdaptiveMemory`, flagged suspicious when the
   same event produced evidence. Suspicious samples are refused by `BehaviorBaseline`.
4. **Graph + retention** — evidence is indexed into the bounded `ThreatGraph`; per-subject
   evidence queues are capped.
5. **Fusion on demand** — `assess()` fuses everything known about a subject.

### Why a weak event cannot produce a verdict

`EvidenceFusion` applies four independent structural limits:

| Mechanism | Effect |
|---|---|
| Severity weight | `INFO 0.05 … CRITICAL 0.70` |
| Observability weight | `PLATFORM_DIRECT 1.0`, `DERIVED 0.8`, `UNTRUSTED_CONTENT 0.35` |
| Same-detector decay | Nth finding from one detector counts `0.35^(n-1)` |
| Per-detector cap | No detector contributes more than `0.45` (threshold is `0.70`) |

Plus two gates: max severity `≤ LOW` can never exceed `SUSPICIOUS`, and `LIKELY_MALICIOUS`
requires ≥3 distinct detectors **and** ≥2 high-quality items. Exculpatory evidence subtracts and
is always returned in `Assessment.contradictions`.

`FusionPolicy.init` throws if `maxMassPerDetector >= maliciousThreshold`, so the guarantee cannot
be misconfigured away.

## Adaptive learning

```
OBSERVED ──(count)──► PROVISIONAL ──(count+age+sessions)──► VALIDATED ──(more)──► TRUSTED
    ▲                      │
    └──── suspicion mark ──┘   (TRUSTED/VALIDATED demote immediately; promotion blocked)
```

Stable base rules + per-app baseline + provisional/trusted memory + drift detection
(Page-Hinkley) + versioned snapshots with rollback. No model is retrained on raw telemetry.

## Local AI posture — an explicit engineering decision

The brief asked to prefer deterministic rules, then classical statistics, then compact ML, with an
LLM only for hard reasoning. This release ships **the first two tiers only**, and that is a
deliberate, documented choice rather than an omission:

- Every detection goal in scope is met by deterministic rules plus streaming statistics
  (EWMA, median/MAD robust z-scores, coefficient of variation for beaconing, Page-Hinkley for
  drift, Shannon entropy for ciphertext-likeness).
- Shipping a bundled LLM or TFLite model would add tens/hundreds of MB, a model-integrity and
  model-update attack surface, and battery cost — while the **no-fake rule** forbids claiming an
  accelerator we have not benchmarked on real hardware.
- The `LlmBoundary` security layer is fully implemented and tested, so an investigator LLM can be
  attached later **behind the same constraints** without loosening any guarantee. The governor
  already exposes `llmEnabled`, gated on FULL mode and power state.

No model file is bundled, so no imaginary "on-device AI" is claimed.

## Response policy

Every action is classified `OBSERVE | ALERT | USER_CONFIRM | SAFE_AUTOMATIC | SPECIAL_PRIVILEGE |
UNAVAILABLE`. Automatic execution requires reversible + low-risk + deterministic + a
runtime-verified capability. When a capability is missing the engine returns it in `blocked` with
a plain-language reason — the product never reports a success it did not achieve.

## Performance design (A54 class hardware, 6–8 GB RAM, Exynos 1380)

- Event-driven over polling: package changes arrive by broadcast; the sweep loop is adaptive.
- `ResourceGovernor` maps battery/RAM/thermal/power-save/event-rate to
  `FULL → REDUCED → CONSERVATIVE → SURVIVAL`, adjusting sampling rate, ML/LLM enablement and batch
  window (2s → 60s).
- **Invariant, tested across all 240 state combinations:** sampling never reaches zero, and
  critical event kinds bypass sampling entirely. Degradation is graceful, never a silent shutdown.
- All accumulators are bounded; retention is capped; the threat graph evicts by last-seen.

## Data flow and storage

| Data | Where | Protection |
|---|---|---|
| Incident evidence | `filesDir/evidence/chain.log` | AES-256-GCM (Keystore) + chained HMAC-SHA256 |
| Operational flags | SharedPreferences | Non-sensitive only |
| Learned memory | In-process, versioned | Snapshot/rollback |
| Anything | — | Excluded from cloud backup and device transfer |

No user data leaves the device.
