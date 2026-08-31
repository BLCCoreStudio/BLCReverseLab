# 1.0 Final Release Checklist

Status: **Final 1.0 core gate satisfied.**

- [x] Python 3.11, 3.12 and 3.13 test matrix passes.
- [x] Linux, Windows and macOS smoke tests pass.
- [x] Wheel/sdist build and installed CLI smoke test pass.
- [x] Local workspace IDE/API tests pass.
- [x] Real JADX 1.5.6 integration fixture passes.
- [x] Real Ghidra 12.1.3 Headless integration fixture passes.
- [x] Hidden-workdir Ghidra regression is covered.
- [x] Full-stack synthetic APK with real DEX + JNI native library passes the deep pipeline.
- [x] ReverseLab → version diff → GameSecLab E2E contract passes.
- [x] HTML and portable bundle outputs are covered.
- [x] Security scope and known limitations are documented.
- [x] Release workflow validates tag/package version and generates SHA-256 checksums.
- [x] Matching release tags publish built artifacts to GitHub Releases.

A final release does not imply arbitrary protected third-party software can always be reconstructed to original source. Obfuscation and symbol stripping may permanently destroy source-level information, and cryptographic plaintext still requires appropriate authorized evidence.
