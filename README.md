# BLCReverseLab

Evidence-first reverse engineering workspace for **authorized application security, debugging, malware research, interoperability and CTF/lab analysis**.

## v0.5 alpha

The project now connects the managed and native sides of an application instead of treating decompilers as isolated tools.

### Working core

- APK/AAB/APKS/XAPK/DEX/SO/EXE/DLL fingerprinting and Android package inventory.
- `BLCEvidenceGraph` with provenance and confidence.
- Real optional JADX decompilation and readability/deobfuscation recovery.
- Safe Base64/hex normalization plus high-entropy/protected-content signals.
- Real optional Ghidra Headless native analysis.
- Native function inventory with body size, instruction count, parameter count and stable **shape fingerprints**.
- Java `native` declaration discovery and static JNI export correlation.
- Dynamic JNI-registration signal detection (`JNI_OnLoad` / `RegisterNatives` evidence).
- Defensive packer/protector fingerprint inventory and protection scoring.
- Cross-version native semantic matching using stable names and unique function shapes.
- Build-to-build diff with same-name changed file detection and native-function reuse ratios.
- Self-contained HTML analysis report.

### One-command deep analysis

```bash
blc-reverselab analyze app.apk \
  --recover \
  --ghidra \
  --workdir .blc-work \
  --html-report report.html \
  -o analysis.json
```

### Version intelligence

```bash
blc-reverselab diff old.analysis.json new.analysis.json -o version-diff.json
```

When Ghidra fingerprints exist in both reports, the diff can correlate functions even when addresses move. Stable original names are preferred; stripped/generic functions can be correlated only when a function shape is unique, and those matches carry lower confidence.

### Java → JNI → native

ReverseLab indexes decompiled Java `native` declarations, computes their expected static JNI exports and correlates them with Ghidra-discovered symbols. Unresolved declarations remain unresolved rather than being guessed. Dynamic-registration signals are recorded separately.

### Protection model

Protection detection is **defensive inventory**, not bypass logic. The report can record recognizable wrapper/protector fingerprints, strong obfuscation, unresolved high-entropy content and heavily stripped native surfaces so authorized reviewers know where deeper testing is needed.

### Recovery limits

Obfuscation can destroy original names, comments and high-level structure. ReverseLab never claims to reconstruct unavailable original source byte-for-byte. Cryptographic content without an authorized key or observed plaintext is recorded as protected evidence rather than falsely “decrypted.”

### Scope

BLCReverseLab does not provide anti-cheat bypass, stealth, credential theft, signature/integrity bypass or online-cheating automation.
