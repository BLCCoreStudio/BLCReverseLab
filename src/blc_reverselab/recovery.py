from __future__ import annotations

import base64
import binascii
import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_STRING_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\]){8,})"')
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for byte in data if byte in {9, 10, 13} or 32 <= byte <= 126)
    return printable / len(data)


def _preview(data: bytes, limit: int = 160) -> str:
    return data.decode("utf-8", errors="replace")[:limit]


def _decode_reversible(value: str) -> tuple[str, bytes] | None:
    compact = value.strip()
    if len(compact) >= 16 and len(compact) % 2 == 0 and _HEX_RE.fullmatch(compact):
        try:
            decoded = bytes.fromhex(compact)
        except ValueError:
            decoded = b""
        if len(decoded) >= 4 and _printable_ratio(decoded) >= 0.85:
            return "hex", decoded

    if len(compact) >= 16 and len(compact) % 4 == 0 and _BASE64_RE.fullmatch(compact):
        try:
            decoded = base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) >= 4 and _printable_ratio(decoded) >= 0.85:
            return "base64", decoded
    return None


def _looks_obfuscated_identifier(name: str) -> bool:
    if not name:
        return False
    if len(name) <= 2 and name not in {"R", "BuildConfig"}:
        return True
    if len(name) >= 24 and sum(char.isdigit() for char in name) >= 4:
        return True
    return False


@dataclass(slots=True)
class RecoveredLiteral:
    source_file: str
    encoding: str
    encoded_preview: str
    decoded_preview: str
    entropy: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RecoveryReport:
    status: str
    source_root: str | None = None
    java_file_count: int = 0
    scanned_bytes: int = 0
    identifier_count: int = 0
    suspicious_identifier_count: int = 0
    obfuscation_score: float = 0.0
    encoded_literal_candidates: int = 0
    recovered_literal_count: int = 0
    high_entropy_literal_count: int = 0
    recovered_literals: list[RecoveredLiteral] = field(default_factory=list)
    capabilities: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["recovered_literals"] = [item.to_dict() for item in self.recovered_literals]
        return payload


@dataclass(slots=True)
class RecoveryAnalyzer:
    max_source_bytes: int = 8 * 1024 * 1024
    max_recovered_literals: int = 50

    def analyze(self, source_root: str | Path | None) -> RecoveryReport:
        if source_root is None:
            return RecoveryReport(
                status="no-decompiler-output",
                capabilities=self._capabilities(),
            )

        root = Path(source_root)
        if not root.is_dir():
            return RecoveryReport(
                status="no-decompiler-output",
                source_root=str(root),
                capabilities=self._capabilities(),
            )

        java_files = sorted(path for path in root.rglob("*.java") if path.is_file())
        identifiers: list[str] = []
        recovered: list[RecoveredLiteral] = []
        encoded_candidates = 0
        high_entropy = 0
        scanned = 0

        for path in java_files:
            relative = path.relative_to(root)
            identifiers.append(path.stem)
            identifiers.extend(part for part in relative.parts[:-1] if part not in {"sources", "resources"})

            if scanned >= self.max_source_bytes:
                break
            remaining = self.max_source_bytes - scanned
            raw = path.read_bytes()[:remaining]
            scanned += len(raw)
            text = raw.decode("utf-8", errors="replace")

            for match in _STRING_LITERAL_RE.finditer(text):
                value = match.group(1)
                entropy = _entropy(value)
                if len(value) >= 24 and entropy >= 4.2:
                    high_entropy += 1

                decoded = _decode_reversible(value)
                if decoded is None:
                    continue
                encoded_candidates += 1
                if len(recovered) >= self.max_recovered_literals:
                    continue
                encoding, payload = decoded
                recovered.append(
                    RecoveredLiteral(
                        source_file=str(relative),
                        encoding=encoding,
                        encoded_preview=value[:160],
                        decoded_preview=_preview(payload),
                        entropy=round(entropy, 3),
                    )
                )

        normalized_identifiers = [name for name in identifiers if name and not name.startswith(".")]
        suspicious = sum(1 for name in normalized_identifiers if _looks_obfuscated_identifier(name))
        ratio = suspicious / len(normalized_identifiers) if normalized_identifiers else 0.0

        return RecoveryReport(
            status="completed",
            source_root=str(root),
            java_file_count=len(java_files),
            scanned_bytes=scanned,
            identifier_count=len(normalized_identifiers),
            suspicious_identifier_count=suspicious,
            obfuscation_score=round(min(1.0, ratio * 1.6), 3),
            encoded_literal_candidates=encoded_candidates,
            recovered_literal_count=len(recovered),
            high_entropy_literal_count=high_entropy,
            recovered_literals=recovered,
            capabilities=self._capabilities(),
        )

    @staticmethod
    def _capabilities() -> dict[str, Any]:
        return {
            "identifier_recovery": [
                "jadx-auto-deobfuscation",
                "source-name-aliases",
                "developer-supplied-mappings",
            ],
            "reversible_literal_recovery": ["base64", "hex"],
            "high_entropy_detection": True,
            "cryptographic_decryption": "detect-and-evidence-only-without-authorized-key-or-runtime-plaintext",
            "original_source_guarantee": False,
        }
