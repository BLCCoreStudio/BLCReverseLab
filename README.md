# BLCReverseLab

Evidence-first reverse engineering workspace for **authorized analysis, debugging, malware research, CTFs, interoperability, and application security**.

## v0.4 alpha milestone

BLCReverseLab now combines Android decompilation/recovery with the first real native-code analysis layer.

### Current analysis stack

- APK/AAB/APKS/XAPK/DEX/SO/EXE/DLL fingerprinting.
- Android package mapping and tracked-entry fingerprints.
- `BLCEvidenceGraph` provenance graph.
- Build-to-build version intelligence, including same-name changed files.
- Real optional JADX CLI integration.
- JADX recovery mode with deobfuscation, source-name aliases, rename repair, resource-extension recovery, and optional developer mappings.
- Readability/obfuscation scoring.
- Safe reversible Base64/hex literal recovery and high-entropy protected-content signals.
- **Optional Ghidra Headless integration for native `.so`, `.exe`, and `.dll` targets.**
- Native function inventory exported by a bundled read-only Ghidra post-analysis script.
- Counts for discovered functions, generic/unnamed `FUN_*`-style functions, externals, thunks, and JNI export candidates.
- APK native-library extraction with prioritized analysis of common game/native libraries.

## Why the native layer matters

Java/Kotlin decompilation is only part of many Android applications. Important behavior can live behind JNI in native `.so` libraries. A stripped library may have few useful original symbols even though executable functions remain. Ghidra's auto-analysis can identify function boundaries and represent unnamed functions with generated names; BLCReverseLab records these as evidence rather than pretending the original source-level names still exist.

```text
APK / native binary
       |
       +--> Java/Kotlin -> JADX -> recovery
       |
       +--> native .so -> Ghidra Headless -> function inventory
                              |
                              +--> named functions
                              +--> generic/unnamed functions
                              +--> external/thunk functions
                              +--> JNI candidates
       |
       v
BLCEvidenceGraph -> analysis.json -> BLCGameSecLab
```

## Recovery model

BLCReverseLab distinguishes:

1. **Obfuscation** — readability can often be improved, but destroyed source names/comments cannot always be recreated exactly.
2. **Reversible encoding** — representations such as Base64/hex can be normalized automatically when the result is clearly readable.
3. **Cryptographic/runtime protection** — detected and recorded as evidence; no false claim is made that unknown cryptographic keys can always be reconstructed. Authorized keys, developer mappings, or later authorized runtime plaintext can be attached as evidence.
4. **Native/stripped code** — Ghidra can recover a useful function-level model even when original symbol names are missing. Generated names remain explicitly marked as generic rather than being presented as original names.

There is **no guarantee of recovering the original source byte-for-byte**. The goal is the most faithful readable behavior model supported by evidence.

## Quick start

```bash
python -m pip install -e .

# Core inventory
blc-reverselab analyze app.apk -o app.analysis.json

# Java/Kotlin decompile
blc-reverselab analyze app.apk --jadx -o app.analysis.json

# Deobfuscation/readability recovery
blc-reverselab analyze app.apk --recover -o app.analysis.json

# Use an authorized developer mapping when available
blc-reverselab analyze app.apk --recover --mapping mapping.txt -o app.analysis.json

# Native analysis (Ghidra must be installed and analyzeHeadless on PATH)
blc-reverselab analyze app.apk --ghidra -o app.analysis.json

# Combined Android + recovery + native analysis
blc-reverselab analyze app.apk --recover --ghidra --workdir .blc-work -o app.analysis.json

# Compare builds
blc-reverselab diff old.analysis.json new.analysis.json -o version-diff.json
```

`--ghidra-max-native` limits how many native libraries from a package are analyzed, and `--ghidra-timeout` controls the per-target analysis timeout.

## Next layers

- Java/Kotlin -> JNI -> native cross-reference graph.
- Dynamic JNI registration correlation.
- Decompiler-failure and control-flow complexity hotspots.
- Packer/protector fingerprint inventory.
- Cross-version semantic function matching even when addresses/names move.
- Authorized runtime evidence import for values only visible at runtime.
- AI-assisted semantic naming with explicit confidence and EvidenceGraph provenance.
- Premium desktop graph/workspace UI.

## BLCGameSecLab integration

BLCGameSecLab consumes the machine-readable analysis report so later security stages reuse the same artifact fingerprint, recovery evidence, native function inventory, version intelligence, and provenance graph rather than rediscovering the target.

## Scope

BLCReverseLab is for authorized reverse engineering and defensive research. It is not intended to provide anti-cheat bypass, stealth, credential theft, unauthorized access, or online-cheating automation.
