from __future__ import annotations

import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class JadxResult:
    available: bool
    status: str
    binary: str | None = None
    output_dir: str | None = None
    return_code: int | None = None
    java_file_count: int = 0
    resource_file_count: int = 0
    stderr_tail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class JadxAdapter:
    binary: str | None = None
    timeout_seconds: int = 180

    def resolve(self) -> str | None:
        return self.binary or shutil.which("jadx")

    def build_command(self, binary: str, target: Path, output_dir: Path) -> list[str]:
        return [binary, "--output-dir", str(output_dir), str(target)]

    def analyze(self, target: Path, output_dir: Path) -> JadxResult:
        binary = self.resolve()
        if not binary:
            return JadxResult(available=False, status="unavailable")

        output_dir.mkdir(parents=True, exist_ok=True)
        command = self.build_command(binary, target, output_dir)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return JadxResult(
                available=True,
                status="timeout",
                binary=binary,
                output_dir=str(output_dir),
                stderr_tail=stderr[-2000:],
            )

        java_count = sum(1 for path in output_dir.rglob("*.java") if path.is_file())
        resource_count = sum(
            1
            for path in output_dir.rglob("*")
            if path.is_file() and path.suffix.lower() in {".xml", ".json", ".properties"}
        )
        status = "completed" if completed.returncode == 0 else "completed-with-errors"
        return JadxResult(
            available=True,
            status=status,
            binary=binary,
            output_dir=str(output_dir),
            return_code=completed.returncode,
            java_file_count=java_count,
            resource_file_count=resource_count,
            stderr_tail=(completed.stderr or "")[-2000:],
        )
