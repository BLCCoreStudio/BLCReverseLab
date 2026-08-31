# BLCReverseLab

Evidence-first reverse-engineering workspace for **authorized application security, debugging, malware research, interoperability and CTF/lab analysis**.

## 1.0.0-rc.1

The core workflow is now release-candidate complete:

- APK/AAB/APKS/XAPK/DEX/SO/EXE/DLL artifact fingerprinting and Android structure inventory.
- JADX decompilation, recovery/deobfuscation, managed class/method indexing and static endpoint discovery.
- Reversible Base64/hex recovery plus explicit protected/high-entropy signals.
- Ghidra Headless native function inventory, JNI export discovery and diagnostic logs.
- Java `native` → JNI → native correlation with evidence provenance.
- Defensive protection/packer/obfuscation/stripping profiles and decompiler hotspots.
- Build-to-build diff plus native semantic reuse matching.
- `BLCEvidenceGraph`, authorized runtime evidence import and persistent project workspaces.
- Universal Search across managed, native, JNI, endpoint, recovered-literal and evidence layers.
- Self-contained HTML reports, portable `.blc.zip` bundles and a local read-only workspace IDE.
- Python 3.11–3.13 CI, package smoke tests, real JADX/Ghidra integration tests and cross-repo validation with BLCGameSecLab.

## Quick start

```bash
python -m pip install -e .

# Check optional external tools
blc-reverselab doctor

# Deep analysis
blc-reverselab analyze app.apk --deep --workdir .blc-work --html-report report.html -o analysis.json

# Persistent project history
blc-reverselab workspace init ./my-lab --name "My App Lab"
blc-reverselab workspace add ./my-lab analysis.json
blc-reverselab serve ./my-lab --open

# Search and version intelligence
blc-reverselab search analysis.json "inventory"
blc-reverselab diff old.analysis.json new.analysis.json -o version-diff.json

# Portable review package
blc-reverselab bundle analysis.json --version-diff version-diff.json -o review.blc.zip
```

## Analysis contract

ReverseLab keeps uncertainty explicit. Obfuscation or symbol stripping can permanently destroy original source names/comments, so generated or inferred names are never presented as recovered originals. Cryptographic content is not claimed to be decrypted without authorized keys or plaintext evidence.

The local IDE is read-only and binds to `127.0.0.1` by default.

## Optional tools

JADX and Ghidra are optional external integrations. They are not vendored into the Python package. The repository's integration workflow pins and checksum-verifies known-good releases before exercising real DEX and ELF fixtures.

## Scope

Use only on software you own, are explicitly authorized to assess, or are permitted to analyze in a lab/CTF/research context. BLCReverseLab does not provide anti-cheat bypass, stealth/evasion, credential theft, signature/integrity bypass automation or online-cheating automation. See `SECURITY.md`.

See `CHANGELOG.md` and `RELEASE_CHECKLIST.md` for the RC status.
