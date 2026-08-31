# Changelog

## 1.0.0 — 2026-08-31

### Stable release
- Promoted the RC core to 1.0.0 after the final Python 3.11–3.13, Linux/Windows/macOS, packaging, real JADX, real Ghidra, full-stack synthetic APK and ReverseLab → GameSecLab E2E gates passed.
- Marked the package as Production/Stable.
- Hardened release automation so a matching `v*` tag validates the package version, builds wheel/sdist, generates SHA-256 checksums and publishes the artifacts to a GitHub Release.
- No breaking analysis-contract changes were introduced between `1.0.0-rc.1` and `1.0.0`.

## 1.0.0-rc.1 — 2026-08-31

### Added
- Evidence-first multi-layer analysis for Android and native artifacts.
- Real optional JADX and Ghidra Headless adapters.
- Recovery/deobfuscation profiling, reversible literal recovery and protected-content signals.
- Managed class/method/endpoint indexing and JNI cross-reference correlation.
- Native function inventory, fingerprints and cross-version semantic matching.
- Protection/decompiler-hotspot intelligence and EvidenceGraph provenance.
- Persistent workspaces, Universal Search, HTML reports, portable bundles and local read-only IDE.
- Authorized runtime-evidence import and BLCGameSecLab machine-readable integration.
- Python 3.11–3.13 CI, packaging tests, real external-tool smoke tests and cross-repo E2E validation.

### Fixed
- Ghidra Headless project creation when ReverseLab uses hidden work directories by isolating ephemeral Ghidra projects in a safe system-temp location.
- Diagnostic preservation for Ghidra stdout, stderr, application logs and script logs.

### Known limitations
- Obfuscation/stripping may permanently destroy original source-level names and comments.
- Cryptographic plaintext cannot be reconstructed without appropriate authorized evidence.
- Runtime evidence is imported from authorized observations; ReverseLab does not perform stealth or bypass instrumentation.
- Optional JADX/Ghidra binaries are installed separately and are not bundled with the Python package.
