# BLCReverseLab

Evidence-first reverse engineering workspace for **authorized application security, debugging, malware research, interoperability and CTF/lab analysis**.

## v0.6 alpha — integrated analysis workflow

- Android/native artifact inventory and fingerprints.
- JADX decompilation, deobfuscation/readability recovery and safe Base64/hex normalization.
- Decompiler-failure and control-flow hotspot detection.
- Ghidra Headless native function inventory with shape fingerprints.
- Java `native` → JNI export correlation and dynamic-registration signals.
- Defensive packer/protector and stripped-symbol profiling.
- Cross-version native semantic matching and reuse ratios.
- `BLCEvidenceGraph` provenance.
- Authorized runtime-observation **import** (no hidden execution).
- Persistent project workspace history.
- Tool readiness `doctor` command.
- Self-contained HTML reports.

### Deep mode

```bash
blc-reverselab analyze app.apk --deep --workdir .blc-work --html-report report.html -o analysis.json
```

`--deep` enables managed recovery + decompiler hotspots + Ghidra native analysis + protection profiling + JNI correlation in one ordered pipeline.

### Runtime evidence

Runtime observations collected in an explicitly authorized lab can be attached to an existing report:

```bash
blc-reverselab enrich analysis.json --runtime runtime-observations.json -o enriched.json
```

The importer accepts observations such as JNI registrations, observed calls, plaintext observations and loaded modules. It does not perform stealth, bypasses or unauthorized instrumentation.

### Workspace

```bash
blc-reverselab workspace init ./project --name MyApp
blc-reverselab workspace add ./project analysis.json
blc-reverselab workspace status ./project
```

### Environment check

```bash
blc-reverselab doctor
```

### Version intelligence

```bash
blc-reverselab diff old.analysis.json new.analysis.json -o version-diff.json
```

Stable names are preferred for native matching. Stripped functions are only shape-matched when the shape is unique; those matches are explicitly lower confidence.

## Recovery limits

Obfuscation may permanently remove original names/comments. Cryptographic content without an authorized key or observed plaintext is recorded as protected evidence rather than falsely “decrypted.”

## Scope

BLCReverseLab does not provide anti-cheat bypass, stealth, credential theft, signature/integrity bypass or online-cheating automation.
