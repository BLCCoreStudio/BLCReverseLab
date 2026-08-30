# BLCReverseLab

Evidence-first reverse engineering workspace for **authorized analysis, debugging, malware research, CTFs, interoperability, and application security**.

## v0.1 goals

- Detect APK/AAB/APKS/XAPK/DEX/SO/EXE/DLL artifacts.
- Build a persistent analysis context so every stage reuses earlier findings.
- Map Android package structure and identify common game-engine fingerprints.
- Record every result as evidence with provenance and confidence.
- Compare analysis snapshots across application versions.
- Discover optional JADX/Ghidra adapters without making them hard dependencies.

## Architecture

`Target -> Pipeline -> AnalysisContext -> EvidenceGraph -> Version Diff -> UI/AI adapters`

The core deliberately separates evidence collection from tool-specific adapters. Future JADX, Ghidra, runtime-observation and visualization integrations feed the same evidence model.

## Quick start

```bash
python -m pip install -e .
blc-reverselab analyze app.apk -o app.analysis.json
blc-reverselab diff old.analysis.json new.analysis.json
```

## Scope

BLCReverseLab is not intended to provide anti-cheat bypass, stealth, integrity-bypass, credential theft, unauthorized access, or online cheating automation.
