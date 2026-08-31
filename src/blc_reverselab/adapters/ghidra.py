from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


def _shape_id(
    body_size: int,
    instruction_count: int,
    parameter_count: int,
    external: bool,
    thunk: bool,
) -> str:
    raw = f"{body_size}:{instruction_count}:{parameter_count}:{int(external)}:{int(thunk)}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _tail(path: Path, limit: int = 6000) -> str:
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-limit:]
    except OSError:
        return ""


@dataclass(slots=True)
class GhidraFunction:
    address: str
    name: str
    external: bool
    thunk: bool
    body_size: int
    instruction_count: int = 0
    parameter_count: int = 0

    @property
    def generic_name(self) -> bool:
        upper = self.name.upper()
        return upper.startswith(("FUN_", "LAB_", "SUB_", "THUNK_"))

    @property
    def jni_candidate(self) -> bool:
        return self.name.startswith("Java_") or self.name in {"JNI_OnLoad", "JNI_OnUnload"}

    @property
    def shape_id(self) -> str:
        return _shape_id(
            self.body_size,
            self.instruction_count,
            self.parameter_count,
            self.external,
            self.thunk,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["generic_name"] = self.generic_name
        payload["jni_candidate"] = self.jni_candidate
        payload["shape_id"] = self.shape_id
        return payload


@dataclass(slots=True)
class GhidraResult:
    available: bool
    status: str
    target: str
    binary: str | None = None
    return_code: int | None = None
    inventory_path: str | None = None
    function_count: int = 0
    generic_function_count: int = 0
    external_function_count: int = 0
    thunk_count: int = 0
    jni_candidate_count: int = 0
    jni_candidates: list[str] = field(default_factory=list)
    function_sample: list[dict[str, Any]] = field(default_factory=list)
    function_fingerprints: list[dict[str, Any]] = field(default_factory=list)
    stdout_tail: str = ""
    stderr_tail: str = ""
    application_log_tail: str = ""
    script_log_tail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_function_inventory(
    path: Path,
    *,
    sample_limit: int = 200,
    fingerprint_limit: int = 5000,
) -> tuple[list[GhidraFunction], list[dict[str, Any]], list[dict[str, Any]]]:
    functions: list[GhidraFunction] = []
    sample: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []
    if not path.is_file():
        return functions, sample, fingerprints

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) not in {5, 7}:
            continue
        address, name, external, thunk, body_size = parts[:5]
        try:
            size = int(body_size)
        except ValueError:
            size = 0
        instruction_count = 0
        parameter_count = 0
        if len(parts) == 7:
            try:
                instruction_count = int(parts[5])
            except ValueError:
                pass
            try:
                parameter_count = int(parts[6])
            except ValueError:
                pass
        function = GhidraFunction(
            address=address,
            name=name,
            external=external.lower() == "true",
            thunk=thunk.lower() == "true",
            body_size=size,
            instruction_count=instruction_count,
            parameter_count=parameter_count,
        )
        functions.append(function)
        payload = function.to_dict()
        if len(sample) < sample_limit:
            sample.append(payload)
        if not function.external and len(fingerprints) < fingerprint_limit:
            fingerprints.append(payload)
    return functions, sample, fingerprints


@dataclass(slots=True)
class GhidraAdapter:
    binary: str | None = None
    timeout_seconds: int = 300
    function_sample_limit: int = 200
    function_fingerprint_limit: int = 5000

    def resolve(self) -> str | None:
        return self.binary or shutil.which("analyzeHeadless")

    @staticmethod
    def script_dir() -> Path:
        return Path(__file__).resolve().parent.parent / "ghidra_scripts"

    def build_command(
        self,
        binary: str,
        target: Path,
        project_dir: Path,
        project_name: str,
        inventory_path: Path,
        *,
        application_log: Path | None = None,
        script_log: Path | None = None,
    ) -> list[str]:
        command = [
            binary,
            str(project_dir),
            project_name,
            "-import",
            str(target),
            "-overwrite",
            "-analysisTimeoutPerFile",
            str(self.timeout_seconds),
            "-scriptPath",
            str(self.script_dir()),
        ]
        if application_log is not None:
            command.extend(["-log", str(application_log)])
        if script_log is not None:
            command.extend(["-scriptlog", str(script_log)])
        command.extend(
            [
                "-postScript",
                "BLCExportFunctions.java",
                str(inventory_path),
                "-deleteProject",
            ]
        )
        return command

    def analyze(self, target: Path, output_root: Path) -> GhidraResult:
        binary = self.resolve()
        if not binary:
            return GhidraResult(available=False, status="unavailable", target=str(target))

        # Ghidra rejects local project paths containing a path element that starts
        # with a dot (for example `.blc-reverselab`). Resolving the adapter root
        # first gives Headless an absolute project location whose elements are
        # valid even when the user intentionally chose a hidden work directory.
        output_root = output_root.expanduser().resolve()
        target = target.expanduser().resolve()

        digest = hashlib.sha256(str(target).encode("utf-8")).hexdigest()[:12]
        project_dir = output_root / "projects"
        project_dir.mkdir(parents=True, exist_ok=True)
        inventory_dir = output_root / "inventories"
        inventory_dir.mkdir(parents=True, exist_ok=True)
        log_dir = output_root / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        inventory_path = inventory_dir / f"{target.name}-{digest}.functions.tsv"
        application_log = log_dir / f"{target.name}-{digest}.application.log"
        script_log = log_dir / f"{target.name}-{digest}.script.log"
        project_name = f"blc_{digest}"

        command = self.build_command(
            binary,
            target,
            project_dir,
            project_name,
            inventory_path,
            application_log=application_log,
            script_log=script_log,
        )
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds + 60,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            return GhidraResult(
                available=True,
                status="timeout",
                target=str(target),
                binary=binary,
                inventory_path=str(inventory_path) if inventory_path.is_file() else None,
                stdout_tail=stdout[-6000:],
                stderr_tail=stderr[-6000:],
                application_log_tail=_tail(application_log),
                script_log_tail=_tail(script_log),
            )

        functions, sample, fingerprints = parse_function_inventory(
            inventory_path,
            sample_limit=self.function_sample_limit,
            fingerprint_limit=self.function_fingerprint_limit,
        )
        jni = sorted({item.name for item in functions if item.jni_candidate})
        status = "completed" if completed.returncode == 0 and inventory_path.is_file() else "completed-with-errors"
        return GhidraResult(
            available=True,
            status=status,
            target=str(target),
            binary=binary,
            return_code=completed.returncode,
            inventory_path=str(inventory_path) if inventory_path.is_file() else None,
            function_count=len(functions),
            generic_function_count=sum(1 for item in functions if item.generic_name),
            external_function_count=sum(1 for item in functions if item.external),
            thunk_count=sum(1 for item in functions if item.thunk),
            jni_candidate_count=len(jni),
            jni_candidates=jni[:100],
            function_sample=sample,
            function_fingerprints=fingerprints,
            stdout_tail=(completed.stdout or "")[-6000:],
            stderr_tail=(completed.stderr or "")[-6000:],
            application_log_tail=_tail(application_log),
            script_log_tail=_tail(script_log),
        )
