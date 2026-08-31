# BLCReverseLab

Evidence-first reverse engineering workspace for **authorized application security, debugging, malware research, interoperability and CTF/lab analysis**.

## v0.7 alpha — feature-complete core milestone

The core workflow now covers artifact inventory, managed/native recovery, cross-version intelligence, evidence correlation, project persistence and human/machine reporting.

- `--deep` ordered analysis profile: JADX recovery → decompiler hotspots → Ghidra native analysis → protection profile → JNI correlation.
- `BLCEvidenceGraph` provenance and confidence.
- Safe reversible Base64/hex recovery; protected cryptographic content is not falsely “decrypted.”
- Ghidra function shape fingerprints and cross-version semantic matching.
- Java `native` → JNI export links plus dynamic-registration signals.
- Defensive protector/packer, obfuscation and stripped-symbol inventory.
- Authorized runtime-observation import.
- Persistent workspaces and build history.
- Interactive self-contained HTML workspace with evidence search.
- Portable `.blc.zip` bundles containing machine JSON + HTML + optional version diff.
- `doctor` environment diagnostics.
- Python 3.11/3.12/3.13 CI matrix plus package build smoke tests.
- Tag/manual release-build workflow.

```bash
# Deep authorized analysis
blc-reverselab analyze app.apk --deep --workdir .blc-work --html-report report.html -o analysis.json

# Build-to-build intelligence
blc-reverselab diff old.analysis.json new.analysis.json -o version-diff.json

# Portable review bundle
blc-reverselab bundle analysis.json --version-diff version-diff.json -o app-review.blc.zip

# Import observations collected in an authorized lab
blc-reverselab enrich analysis.json --runtime runtime-observations.json -o enriched.json

# Project history
blc-reverselab workspace init ./project --name MyApp
blc-reverselab workspace add ./project analysis.json

# Tool readiness
blc-reverselab doctor
```

## Recovery limits

Obfuscation may permanently remove original names, comments and high-level structure. Native stripping may also destroy original symbols. ReverseLab produces the most faithful evidence-backed readable model it can; semantic names that cannot be proven are not presented as original source names.

## Scope

BLCReverseLab does not provide anti-cheat bypass, stealth, credential theft, signature/integrity bypass or online-cheating automation. See `SECURITY.md`.
