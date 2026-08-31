# Architecture

BLCReverseLab is organized as an evidence-first pipeline rather than a collection of unrelated wrappers.

```text
Artifact
  |
  +-- fingerprint / Android inventory
  +-- JADX ----------> managed index / recovery / endpoints
  +-- Ghidra --------> native functions / JNI exports
  +-- protection ----> defensive protection profile
  +-- correlation ---> Java native -> JNI -> native evidence
  +-- runtime import -> authorized observations
  |
  v
BLCEvidenceGraph
  |
  +-- Universal Search
  +-- version intelligence
  +-- HTML / bundle / workspace IDE
  +-- BLCGameSecLab contract
```

## Core contracts

### `AnalysisContext`
Carries facts, evidence and completed steps through the ordered pipeline. A later step consumes already-established context rather than rediscovering the target from scratch.

### `BLCEvidenceGraph`
Turns analysis output into provenance-aware nodes and relationships. This is the shared layer used by reports, search, correlation and downstream GameSecLab stages.

### External adapters
JADX and Ghidra are optional executors. ReverseLab owns orchestration, normalization, evidence creation, correlation, version intelligence and workspace/reporting; it does not fork or silently vendor the upstream tools.

### Recovery
Recovery separates reversible encoding, deobfuscation/readability work, protected/high-entropy content, and native stripped-code analysis. Destroyed source information is never fabricated.

### Version intelligence
Tracked-entry fingerprints detect changed DEX/native/resources even when names are unchanged. Native shape fingerprints provide limited semantic reuse hints across builds while retaining explicit confidence/limitations.

### Local workspace IDE
The server uses the Python standard library, defaults to `127.0.0.1`, serves read-only APIs, and operates on persisted analysis reports rather than modifying target artifacts.

## Downstream integration

BLCGameSecLab imports the normalized ReverseLab report and version diff. The downstream system is responsible for authorization gating, findings, policy, trust observations, regression planning and release-readiness assessment.
