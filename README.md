# Aegis Sentinel X

On-device, offline-first behavioural security monitor for **Android 16 (API 36), non-root**,
tuned for the Samsung Galaxy A54 5G (SM-A546E).

It looks for *behaviour* rather than signatures: mass file transformation, network beaconing,
suspicious install/permission chains, and behavioural drift — then fuses independent evidence into
an auditable verdict with a full incident timeline.

**Defensive only.** No exploit, offensive interception, privilege escalation or destructive tooling.

## What makes it trustworthy

- **Nothing imaginary ships.** `Capability`'s constructor throws if an `UNKNOWN`, `ROOT_ONLY` or
  `UNAVAILABLE` capability is marked production-enabled. Unsupported actions are reported as
  unavailable with a reason — never faked.
- **No single weak signal convicts.** A `LIKELY_MALICIOUS` verdict structurally requires ≥3
  independent detectors; one detector is capped below the threshold, and the policy object refuses
  a configuration that would break this.
- **Hostile data can't teach the system.** Suspicious observations are refused by the baseline and
  can never be promoted to `TRUSTED`.
- **Untrusted text can't give orders.** APK strings, hostnames and page content are sanitized and
  weighted at 0.35; an LLM can lower a verdict but never raise it, and can never trigger a
  privileged action.
- **Evidence is tamper-evident.** AES-256-GCM under an Android Keystore key, plus an HMAC chain
  that detects deletion and reordering, not just modification.

## Verification status — what was actually run

| Check | Status |
|---|---|
| `core-detect` compiles (Kotlin 2.2.10, JVM target) | **PASS** — 88 classes, 0 errors, executed in this environment |
| Core security assertions executed | **PASS — 76/76** via `tools/verify` (see below) |
| `app` module compile / lint / APK | **NOT RUN HERE** — needs the Android SDK, which is not reachable from this sandbox. CI definition provided. |
| Instrumented tests on an API 36 emulator | **NOT RUN HERE** — same reason; workflow provided. |

The 76 executed assertions cover fusion gating, sanitization, the LLM boundary, memory
anti-poisoning, file-defense detection *and its false-positive guards*, beaconing detection and its
false-positive guard, attack-chain ordering/expiry, the governor's never-stop invariant, response
policy honesty, statistics correctness, and end-to-end pipeline behaviour including flood and
malformed-input handling.

### Reproduce the core verification

Requires only a JDK 17+ and the Kotlin compiler (no Android SDK, no network once tools are present):

```bash
kotlinc -d out-core $(find core-detect/src/main -name '*.kt')
kotlinc -cp out-core -d out-verify tools/verify/Verify.kt
java -cp "out-verify:out-core:$KOTLIN_HOME/lib/kotlin-stdlib.jar" \
     com.aegis.sentinel.verify.VerifyKt
```

Exit code 0 and `RESULT: 76 passed, 0 failed`.

### Full build (needs Android SDK + network)

```bash
gradle wrapper --gradle-version 8.13
./gradlew :core-detect:test          # canonical JUnit suites
./gradlew :app:testDebugUnitTest
./gradlew :app:lintDebug
./gradlew :app:assembleDebug
./gradlew :app:connectedDebugAndroidTest   # API 36 emulator/device
```

> **CI note.** The complete workflow lives at [`ci/github-workflow-build-apk.yml`](ci/github-workflow-build-apk.yml).
> It is not installed at `.github/workflows/` because the credential used for this branch lacks the
> GitHub `workflows` permission, so pushing it was rejected. Copy that file to
> `.github/workflows/build-apk.yml` to enable build, unit tests, lint, both APKs and API 36
> instrumented tests. **No APK is published in this repository, because none was built here.**

## Requirements

- Android 16 (API 36) target; `minSdk 31`
- JDK 17, AGP 8.13.2, Gradle 8.13, Kotlin 2.2.10
- Non-root device

## Permissions, and what is deliberately absent

Requested: `INTERNET`, `ACCESS_NETWORK_STATE`, `POST_NOTIFICATIONS`, `FOREGROUND_SERVICE(+SPECIAL_USE)`,
`RECEIVE_BOOT_COMPLETED`, and `PACKAGE_USAGE_STATS` (special access, optional).

Deliberately **not** requested: `QUERY_ALL_PACKAGES`, any accessibility service, notification
listener access, or broad/`MANAGE_EXTERNAL_STORAGE` storage. See
[`docs/CAPABILITY_MATRIX.md`](docs/CAPABILITY_MATRIX.md) for the consequences, stated plainly.

## Honest limitations

- Only apps with a launcher activity are visible.
- Network analysis is **metadata only** — no TLS/QUIC/DoH payload inspection, no pinning bypass.
- Enabling flow observation interrupts connectivity for the selected app (packets are not forwarded).
- Cannot force-stop or silently uninstall apps (device-owner privilege).
- Cannot decrypt files already encrypted by ransomware; the goal is early detection and evidence.
- Root-level malware defeats all app-layer defences.

## Documentation

- [Capability matrix](docs/CAPABILITY_MATRIX.md) — verified can/cannot, per access class
- [Threat model](docs/THREAT_MODEL.md) — adversaries, mitigations, residual risk
- [Architecture](docs/ARCHITECTURE.md) — pipeline, fusion maths, learning lifecycle, performance
