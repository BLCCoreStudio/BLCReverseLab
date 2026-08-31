# 1.0 Release Candidate Checklist

Status: **RC gate satisfied for the current core feature set.**

- [x] Python 3.11, 3.12 and 3.13 test matrix passes.
- [x] Wheel/sdist build and installed CLI smoke test pass.
- [x] Local workspace IDE/API tests pass.
- [x] Real JADX 1.5.6 integration fixture passes.
- [x] Real Ghidra 12.1.3 Headless integration fixture passes.
- [x] Hidden-workdir Ghidra regression is covered.
- [x] ReverseLab → version diff → GameSecLab E2E contract passes.
- [x] HTML and portable bundle outputs are covered.
- [x] Security scope and known limitations are documented.

Before a final `1.0.0` tag, run the same CI/external-tool/E2E gates against the final commit and review release artifacts/checksums. RC status is not a claim that arbitrary third-party protected software can always be reconstructed to original source.
