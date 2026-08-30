# BLCReverseLab

Evidence-first reverse engineering workspace for **authorized analysis, debugging, malware research, CTFs, interoperability, and application security**.

## v0.3 alpha milestone

BLCReverseLab now includes an initial **Deobfuscation & Recovery Pipeline** on top of the v0.2 evidence graph and version-intelligence core.

Current capabilities:

- APK/AAB/APKS/XAPK/DEX/SO/EXE/DLL artifact fingerprinting.
- Android package mapping with stable fingerprints for DEX, native libraries, manifests, resource tables, and Unity metadata.
- `BLCEvidenceGraph`: evidence nodes, provenance links, confidence, graph statistics, queries, and unresolved-link checks.
- Build-to-build version intelligence that detects **changed files even when their names stay the same**.
- Analysis reuse ratio for incremental follow-up work.
- Optional real JADX CLI adapter.
- JADX recovery mode using deobfuscation, source-name aliases, identifier repair, and resource-extension recovery.
- Optional developer-supplied rename mappings such as ProGuard/R8 `mapping.txt`.
- Readable-code recovery profiler that measures suspicious/obfuscated identifiers.
- Safe recovery of reversible literal encodings such as Base64 and hex when they decode to readable text.
- High-entropy literal detection to flag likely packed/encrypted/encoded data for deeper authorized analysis.
- Machine-readable schema marker: `blc.reverselab.analysis/v1`.

## Recovery model

```text
Target
  -> Artifact fingerprint
  -> Android/package structure
  -> JADX decompile
  -> JADX deobfuscation / supplied mappings
  -> Identifier recovery profile
  -> Reversible literal recovery
  -> High-entropy / protected-content evidence
  -> EvidenceGraph
  -> analysis.json
```

The recovery layer deliberately distinguishes three cases:

1. **Obfuscation** — names and control flow are made difficult to read. We can often improve readability with decompiler analysis, source metadata, heuristics, mappings, and later cross-version/runtime evidence.
2. **Reversible encoding** — Base64, hex, and similar representations are not cryptographic secrecy. These can be normalized automatically when the decoded result is clearly readable.
3. **Cryptographic encryption / runtime-protected values** — BLCReverseLab records where protection exists, but does not pretend an unknown key can always be reconstructed. Authorized keys, developer mappings, or plaintext observed in an authorized runtime session can later be attached as evidence.

There is **no guarantee of recovering the original source code byte-for-byte**. Compilation and obfuscation can permanently remove original variable names, comments, formatting, generic type information, and other source-level detail. The product goal is the most faithful readable behavior model supported by evidence.

## Architecture

```text
Target
  -> Fingerprint
  -> Android structure / tracked-entry fingerprints
  -> Optional adapters
       -> JADX
       -> Recovery
       -> Ghidra/native analysis (next)
  -> EvidenceGraph
  -> analysis.json
  -> Version Intelligence
  -> BLCGameSecLab / UI / AI adapters
```

## BLCGameSecLab integration

BLCReverseLab is the artifact-analysis layer. Its JSON evidence is consumed by **BLCGameSecLab** so authorized security pipelines can reuse fingerprints, detected engines, DEX/native inventory, recovery signals, adapter results, and the evidence graph rather than starting over.

## Quick start

```bash
python -m pip install -e .

# Core static inventory + evidence graph
blc-reverselab analyze app.apk -o app.analysis.json

# Normal JADX decompilation
blc-reverselab analyze app.apk --jadx --workdir .blc-work -o app.analysis.json

# Deobfuscation + readable-code recovery
blc-reverselab analyze app.apk --recover --workdir .blc-work -o app.analysis.json

# If you own the original mapping file, use it as high-confidence rename evidence
blc-reverselab analyze app.apk --recover --mapping mapping.txt -o app.analysis.json

# Compare two application builds
blc-reverselab diff old.analysis.json new.analysis.json -o version-diff.json
```

The JADX adapter invokes the locally installed `jadx` CLI. BLCReverseLab does not bundle JADX.

## Next native/recovery layers

- Ghidra Headless adapter and native symbol/function inventory.
- Java/Kotlin -> JNI -> native cross-reference graph.
- Control-flow complexity and decompiler-failure hotspot indexing.
- Packer/protector fingerprint inventory.
- Authorized runtime evidence import for values that only become plaintext at runtime.
- Cross-version semantic matching so renamed/shifted functions can still be correlated.
- AI-assisted semantic naming backed by EvidenceGraph provenance.

## Scope

BLCReverseLab is for authorized reverse engineering and defensive research. It is not intended to provide anti-cheat bypass, stealth, credential theft, unauthorized access, or online-cheating automation.
