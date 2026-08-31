# Contributing to BLCReverseLab

Thanks for helping improve BLCReverseLab. Contributions should strengthen authorized reverse engineering, application security, interoperability, debugging, malware research, or lab/CTF workflows.

## Before opening a PR

1. Keep analysis evidence-first: never present inferred names or recovered values as ground truth without provenance/confidence.
2. Preserve the project scope in `SECURITY.md`. Anti-cheat bypass, stealth/evasion, credential theft, signature/integrity bypass automation, and online-cheating automation are out of scope.
3. Add or update tests for behavior changes.
4. Run `pytest -q` on Python 3.11+ and make sure `blc-reverselab --help` works after installation.
5. Keep optional tools optional. JADX/Ghidra integrations must fail gracefully when the external binary is unavailable.
6. Do not commit proprietary APKs/binaries, credentials, secrets, or third-party samples without redistribution permission.

## Design rules

- JSON contracts should remain machine-readable and backward-compatible where practical.
- New analyzers should emit evidence with a source, confidence, and relationships instead of only printing text.
- Long-running adapters need timeouts and useful diagnostics.
- Local UI/server features are read-only by default and bind to localhost unless the user explicitly changes it.
- External downloads in CI must be pinned and checksum-verified.

## Pull requests

Keep PRs focused. Describe the problem, implementation, tests, and any report/schema compatibility impact. Security-sensitive bugs in BLCReverseLab itself should be reported privately when possible rather than as public exploit details.
