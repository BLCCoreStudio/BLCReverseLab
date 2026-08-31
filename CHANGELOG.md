# Changelog

## 1.1.0 — 2026-08-31

### Added
- Evidence-backed offline Analyst with `blc-reverselab ask`, confidence, supporting hits and explicit insufficient-evidence behavior.
- Cross-layer Graph Explorer with managed class/method, JNI bridge, native function, network, recovery and EvidenceGraph nodes.
- JSON and Graphviz DOT graph export.
- Versioned plugin SDK using the `blc_reverselab.plugins` Python entry-point group.
- Safe plugin discovery that does not import plugin code and explicit-only plugin execution with isolated result contracts.

### Guarantees
- Analyst answers are derived only from the supplied report and never claim missing source names, plaintext or runtime behavior as facts.
- Plugin execution remains opt-in; third-party plugins are treated as trusted local code and are never auto-executed during analysis.
- Existing `blc.reverselab.analysis/v1` report compatibility is preserved.

## 1.0.0 — 2026-08-31

### Stable release
- Promoted the RC core to 1.0.0 after Python 3.11–3.13, Linux/Windows/macOS, packaging, real JADX, real Ghidra, full-stack synthetic APK and ReverseLab → GameSecLab E2E gates passed.
- Marked the package as Production/Stable.
- Hardened release automation with package/tag validation, wheel/sdist builds and SHA-256 checksums.
- Published `v1.0.0` with wheel, source distribution and `SHA256SUMS`.

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
