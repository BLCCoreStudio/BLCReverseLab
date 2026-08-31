# BLCReverseLab

Evidence-first reverse engineering workspace for **authorized application security, debugging, malware research, interoperability and CTF/lab analysis**.

## v0.9 alpha — local workspace IDE

- Deep ordered pipeline across managed + native layers.
- JADX recovery/deobfuscation and decompiler-hotspot detection.
- Managed class/method index and static endpoint inventory.
- Ghidra Headless function inventory + shape fingerprints.
- Java `native` → JNI → native export correlation.
- Defensive protection/packer/obfuscation/stripping profile.
- Cross-version semantic native matching.
- Universal search across managed classes/methods, endpoints, native functions, JNI links, recovered literals and EvidenceGraph records.
- Authorized runtime evidence import, persistent workspace history, interactive HTML and portable `.blc.zip` bundles.
- **Local read-only workspace IDE** with analysis history, Universal Search, embedded report view and build-to-build diff.
- Local server binds to `127.0.0.1` by default and uses only the Python standard library.
- Python 3.11–3.13 CI and package/release build workflows.

```bash
# Analyze
blc-reverselab analyze app.apk --deep --workdir .blc-work --html-report report.html -o analysis.json

# Persist analyses in a workspace
blc-reverselab workspace init ./my-lab --name "My App Lab"
blc-reverselab workspace add ./my-lab analysis.json

# Open the local IDE
blc-reverselab serve ./my-lab --open

# CLI equivalents
blc-reverselab search analysis.json "inventory"
blc-reverselab diff old.analysis.json new.analysis.json -o version-diff.json
blc-reverselab bundle analysis.json --version-diff version-diff.json -o review.blc.zip
```

ReverseLab does not claim to reconstruct source information that obfuscation or stripping permanently destroyed, and it does not falsely decrypt cryptographic content without authorized key/plaintext evidence.

## Scope

No anti-cheat bypass, stealth, credential theft, signature/integrity bypass or online-cheating automation. See `SECURITY.md`.
