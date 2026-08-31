# BLCReverseLab

Evidence-first reverse-engineering workspace for **authorized application security, debugging, malware research, interoperability and CTF/lab analysis**.

## Current main — unreleased

The current `main` branch adds **Investigation Studio**, a premium local read-only investigation surface on top of the 1.1 analysis core:

- Evidence Analyst and its supporting evidence are visible in the same workspace.
- Managed/JNI/native/network/recovery/evidence nodes are rendered as a cross-layer graph.
- **Build Timeline** lets you move between saved analyses in a persistent workspace.
- **Version Intelligence** compares a baseline with the current build across managed classes/methods, endpoints, JNI bridges, native semantic reuse, DEX/native fingerprints, protection and recovery signals.
- Version Intelligence derives an evidence-backed **re-analysis focus** so changed surfaces are prioritized without treating missing analyzer output as proof of absence.
- Universal Search and raw proven facts remain available beside the graph.
- Studio binds to `127.0.0.1` by default and does not add a paid API dependency.

Launch it with:

```bash
blc-reverselab studio ./my-lab --open
```

## 1.1.0

1.1 keeps the stable 1.0 analysis core and adds a higher-level investigation layer:

- **Evidence Analyst (`ask`)**: deterministic, offline answers grounded only in the supplied analysis. It returns confidence, supporting hits and covered layers instead of inventing missing source details.
- **Cross-layer Graph Explorer (`graph`)**: exports a navigable managed → JNI → native plus network/recovery/evidence graph as JSON or Graphviz DOT.
- **Plugin SDK (`plugins`)**: discovers plugin metadata without importing code and only executes an installed plugin when the user explicitly names it. Plugin outputs are isolated behind a versioned result contract.
- No paid API is required. Optional model-backed analyst plugins can build on the same evidence contract without replacing provenance.

### Stable analysis core

- APK/AAB/APKS/XAPK/DEX/SO/EXE/DLL artifact fingerprinting and Android structure inventory.
- JADX decompilation, recovery/deobfuscation, managed class/method indexing and static endpoint discovery.
- Reversible Base64/hex recovery plus explicit protected/high-entropy signals.
- Ghidra Headless native function inventory, JNI export discovery and diagnostic logs.
- Java `native` → JNI → native correlation with evidence provenance.
- Defensive protection/packer/obfuscation/stripping profiles and decompiler hotspots.
- Build-to-build diff plus native semantic reuse matching.
- `BLCEvidenceGraph`, authorized runtime evidence import and persistent project workspaces.
- Universal Search, self-contained HTML reports, portable `.blc.zip` bundles and a local read-only workspace IDE.
- Python 3.11–3.13 CI, Linux/Windows/macOS smoke tests, real JADX/Ghidra integration tests, full-stack synthetic APK validation and cross-repo validation with BLCGameSecLab.

## Quick start

```bash
python -m pip install -e .

blc-reverselab doctor
blc-reverselab analyze app.apk --deep --workdir .blc-work --html-report report.html -o analysis.json

# Evidence-backed investigation
blc-reverselab search analysis.json "inventory"
blc-reverselab ask analysis.json "where is inventory handled?"
blc-reverselab graph analysis.json --format json -o graph.json
blc-reverselab graph analysis.json --format dot -o graph.dot

# Explicit, trusted plugin execution
blc-reverselab plugins list
blc-reverselab plugins run my-plugin analysis.json --config plugin-config.json -o plugin-result.json

# Version intelligence and workspace history
blc-reverselab diff old.analysis.json new.analysis.json -o version-diff.json
blc-reverselab workspace init ./my-lab --name "My App Lab"
blc-reverselab workspace add ./my-lab old.analysis.json
blc-reverselab workspace add ./my-lab new.analysis.json
blc-reverselab serve ./my-lab --open

# Current main: premium Studio with timeline + Version Intelligence
blc-reverselab studio ./my-lab --open

blc-reverselab bundle analysis.json --version-diff version-diff.json -o review.blc.zip
```

## Evidence contract

ReverseLab keeps uncertainty explicit. Obfuscation or symbol stripping can permanently destroy original source names/comments, so generated or inferred names are never presented as recovered originals. Cryptographic content is not claimed to be decrypted without authorized keys or plaintext evidence.

`ask` is evidence retrieval and synthesis, not a claim that the tool recovered information absent from the report. Third-party plugins execute as local Python code with the user's privileges, so install and run only plugins you trust.

The local IDE and Investigation Studio are read-only and bind to `127.0.0.1` by default.

## Optional tools

JADX and Ghidra are optional external integrations. They are not vendored into the Python package. CI pins and checksum-verifies known-good releases before exercising real DEX and ELF fixtures.

## Scope

Use only on software you own, are explicitly authorized to assess, or are permitted to analyze in a lab/CTF/research context. BLCReverseLab does not provide anti-cheat bypass, stealth/evasion, credential theft, signature/integrity bypass automation or online-cheating automation. See `SECURITY.md`.

See `CHANGELOG.md`, `ARCHITECTURE.md` and `RELEASE_CHECKLIST.md` for implementation and release details.
