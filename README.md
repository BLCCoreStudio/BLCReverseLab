# BLCReverseLab

Evidence-first reverse engineering workspace for **authorized analysis, debugging, malware research, CTFs, interoperability, and application security**.

## v0.2 alpha milestone

BLCReverseLab now has a persistent analysis contract instead of being only a file detector:

- APK/AAB/APKS/XAPK/DEX/SO/EXE/DLL artifact fingerprinting.
- Android package mapping with stable fingerprints for DEX, native libraries, manifests, resource tables, and Unity metadata.
- `BLCEvidenceGraph`: evidence nodes, provenance links, confidence, graph statistics, queries, and unresolved-link checks.
- Build-to-build version intelligence that detects **changed files even when their names stay the same**.
- Analysis reuse ratio for incremental follow-up work.
- Optional real JADX CLI adapter (`--jadx`) that records decompilation status and output counts as evidence.
- Optional JADX/Ghidra readiness discovery without making external tools hard dependencies.
- Machine-readable schema marker: `blc.reverselab.analysis/v1`.

## Architecture

```text
Target
  -> Fingerprint
  -> Android structure / tracked-entry fingerprints
  -> EvidenceGraph
  -> Optional adapters (JADX now, more later)
  -> analysis.json
  -> Version Intelligence
  -> BLCGameSecLab / UI / AI adapters
```

Every stage contributes evidence to the same context. Evidence records retain their source, confidence, data, and relationships so downstream tooling does not have to rediscover why a conclusion was reached.

## BLCGameSecLab integration

BLCReverseLab is the artifact-analysis layer. Its JSON evidence can be consumed by **BLCGameSecLab** so an authorized game-security pipeline can reuse the exact target fingerprint, detected engine, DEX/native inventory, tracked-entry fingerprints, graph, adapter results, and upstream evidence instead of starting over.

## Quick start

```bash
python -m pip install -e .

# Core static inventory + evidence graph
blc-reverselab analyze app.apk -o app.analysis.json

# Also run JADX when it is installed
blc-reverselab analyze app.apk --jadx --workdir .blc-work -o app.analysis.json

# Compare two application builds and save reusable version intelligence
blc-reverselab diff old.analysis.json new.analysis.json -o version-diff.json
```

The JADX adapter invokes the locally installed `jadx` CLI using its documented `--output-dir` interface. BLCReverseLab does not bundle JADX.

## Scope

BLCReverseLab is for authorized reverse engineering and defensive research. It is not intended to provide anti-cheat bypass, stealth, integrity-bypass, credential theft, unauthorized access, or online-cheating automation.
