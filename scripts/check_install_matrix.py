#!/usr/bin/env python3
"""Run an offline wheel/sdist installation matrix.

The runner never downloads, builds, or imports the source checkout. It only
reads an explicit artifact directory and an explicit interpreter manifest.
Each cell gets a temporary venv outside the repository, then runs the
installed CLI and asset validation with PYTHONPATH removed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PYTHON_RE = re.compile(r"^3\.(?:1[0-4])(?:\.\d+)?$")
SUPPORTED_OS = frozenset({"linux", "windows", "macos"})
STATUSES = frozenset({"pass", "fail", "blocked"})
PROJECT_DISTRIBUTION = "surfacescope"
BUILD_REQUIREMENTS = ("setuptools>=77", "wheel")
RUNTIME_DEPENDENCY_DISTRIBUTIONS = frozenset(
    {"requests", "beautifulsoup4", "pyyaml", "tomli"}
)
BUILD_DEPENDENCY_DISTRIBUTIONS = frozenset({"setuptools", "wheel"})
CELL_KEYS = (
    "artifact",
    "artifact_sha256",
    "candidate_sha",
    "os",
    "python",
    "interpreter",
    "status",
    "commands",
    "exit_codes",
    "uncovered",
)
REPORT_KEYS = (
    "schema_version",
    "generated_at",
    "artifact_dir",
    "dependency_dir",
    "dependency_artifacts",
    "candidate_sha",
    "checksum_file",
    "summary",
    "cells",
)


class MatrixInputError(ValueError):
    """Raised when the matrix inputs cannot produce honest evidence."""


def _outside_repository(path: Path) -> bool:
    try:
        resolved = path.expanduser().resolve()
        root = ROOT.resolve()
    except (OSError, RuntimeError):
        return False
    return resolved != root and root not in resolved.parents


def _safe_temp_parent() -> Path:
    """Return a writable temporary parent outside the source checkout.

    ``tempfile.gettempdir()`` can fall back to the current working directory on
    older Python builds when the user's TEMP path contains non-ASCII characters.
    The install matrix must never create a venv inside the checkout, so probe a
    short list of explicit candidates instead of trusting the default blindly.
    """

    candidates: list[Path] = [Path(tempfile.gettempdir())]
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append(Path(local_app_data) / "Temp")
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        candidates.append(Path(user_profile) / "AppData" / "Local" / "Temp")
    system_root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR")
    if system_root:
        candidates.append(Path(system_root) / "Temp")
    candidates.append(Path.home() / ".cache" / "surfacescope" / "tmp")
    if os.name != "nt":
        candidates.extend((Path("/tmp"), Path("/var/tmp")))
    candidates.append(ROOT.parent)

    for candidate in candidates:
        if not _outside_repository(candidate):
            continue
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            probe = candidate / f".surfacescope-write-{os.getpid()}"
            probe.write_bytes(b"")
            probe.unlink()
        except (OSError, UnicodeError, ValueError):
            continue
        return candidate
    raise MatrixInputError("no writable temporary directory outside the repository")


@dataclass(frozen=True, slots=True)
class InterpreterSpec:
    os_name: str
    python: str
    declared: str
    resolved: str

    def to_dict(self) -> dict[str, str]:
        return {
            "os": self.os_name,
            "python": self.python,
            "interpreter": self.declared,
            "resolved_interpreter": self.resolved,
        }


@dataclass(frozen=True, slots=True)
class ArtifactSpec:
    path: Path
    kind: str
    sha256: str
    expected_sha256: str | None
    checksum_error: str


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": _display_argv(self.argv),
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout": _tail(self.stdout),
            "stderr": _tail(self.stderr),
        }


def _tail(value: str, limit: int = 4000) -> str:
    value = value or ""
    return value if len(value) <= limit else value[-limit:]


def _display_argv(argv: Sequence[str]) -> str:
    return " ".join(str(item) for item in argv)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalise_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _artifact_distribution(path: Path) -> str:
    if path.suffix.lower() == ".whl":
        return _normalise_distribution_name(path.name.split("-", 1)[0])
    name = path.name[:-7] if path.name.lower().endswith(".tar.gz") else path.stem
    return _normalise_distribution_name(name.split("-", 1)[0])


def _is_project_artifact(path: Path) -> bool:
    return _artifact_distribution(path) == PROJECT_DISTRIBUTION


def discover_dependency_artifacts(dependency_dir: str | Path) -> dict[str, str]:
    directory = Path(dependency_dir).expanduser().resolve()
    if not directory.is_dir():
        raise MatrixInputError(f"dependency directory does not exist: {directory}")
    hashes: dict[str, str] = {}
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.name.startswith("."):
            continue
        if path.suffix.lower() == ".whl" and not _is_project_artifact(path):
            hashes[path.name] = _sha256_file(path)
    return hashes


def missing_dependency_distributions(
    dependency_artifacts: dict[str, str],
    artifacts: Sequence[ArtifactSpec],
) -> list[str]:
    """Return direct dependency distributions missing from an offline wheelhouse."""
    available = {
        _artifact_distribution(Path(name))
        for name in dependency_artifacts
    }
    required = set(RUNTIME_DEPENDENCY_DISTRIBUTIONS)
    if any(artifact.kind == "sdist" for artifact in artifacts):
        required.update(BUILD_DEPENDENCY_DISTRIBUTIONS)
    return sorted(required - available)


def _normalise_os(value: str) -> str:
    aliases = {
        "win": "windows",
        "win32": "windows",
        "windows": "windows",
        "linux": "linux",
        "darwin": "macos",
        "mac": "macos",
        "macos": "macos",
    }
    normalised = aliases.get(str(value).strip().lower(), str(value).strip().lower())
    if normalised not in SUPPORTED_OS:
        raise MatrixInputError(f"unsupported interpreter os: {value!r}")
    return normalised


def _resolve_interpreter(value: str) -> str:
    expanded = os.path.expandvars(os.path.expanduser(str(value).strip()))
    path = Path(expanded)
    if path.is_file():
        return str(path.resolve())
    found = shutil.which(expanded)
    return str(Path(found).resolve()) if found else ""


def load_interpreters(path: str | Path) -> list[InterpreterSpec]:
    manifest = Path(path).expanduser()
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MatrixInputError(f"cannot read interpreter manifest {manifest}: {exc}") from exc
    items = payload.get("interpreters") if isinstance(payload, dict) else payload
    if not isinstance(items, list) or not items:
        raise MatrixInputError("interpreter manifest must contain a non-empty list")

    specs: list[InterpreterSpec] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            raise MatrixInputError(f"interpreter entry {index} must be an object")
        for key in ("os", "python", "interpreter"):
            if not str(item.get(key) or "").strip():
                raise MatrixInputError(f"interpreter entry {index} is missing {key}")
        os_name = _normalise_os(str(item["os"]))
        python = str(item["python"]).strip()
        if not PYTHON_RE.fullmatch(python):
            raise MatrixInputError(f"interpreter entry {index} has unsupported Python: {python!r}")
        identity = (os_name, python)
        if identity in seen:
            raise MatrixInputError(f"duplicate interpreter cell: {os_name} / {python}")
        seen.add(identity)
        declared = str(item["interpreter"]).strip()
        specs.append(
            InterpreterSpec(
                os_name=os_name,
                python=python,
                declared=declared,
                resolved=_resolve_interpreter(declared),
            )
        )
    return specs


def _load_checksums(path: Path) -> tuple[dict[str, str], str | None]:
    if not path.is_file():
        return {}, None
    checksums: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return {}, f"cannot read SHA256SUMS: {exc}"
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2 or not SHA256_RE.fullmatch(parts[0].lower()):
            return {}, f"SHA256SUMS line {number} is malformed"
        filename = parts[1].lstrip("*").strip()
        name = Path(filename).name
        if not name:
            return {}, f"SHA256SUMS line {number} has no filename"
        if name in checksums:
            return {}, f"SHA256SUMS contains duplicate filename: {name}"
        checksums[name] = parts[0].lower()
    return checksums, None


def discover_artifacts(artifact_dir: str | Path, *, require_checksums: bool = False) -> tuple[list[ArtifactSpec], Path | None]:
    directory = Path(artifact_dir).expanduser().resolve()
    if not directory.is_dir():
        raise MatrixInputError(f"artifact directory does not exist: {directory}")
    if directory == ROOT.resolve() or (directory / "src" / "surfacescope").is_dir():
        raise MatrixInputError("artifact directory points at a source checkout; pass built wheel/sdist files")

    candidates: list[Path] = []
    for path in sorted(directory.iterdir()):
        if path.name.startswith("."):
            continue
        if path.suffix.lower() == ".whl" and not path.is_file():
            raise MatrixInputError(f"wheel artifact is not a file: {path.name}")
        if path.is_file() and (path.suffix.lower() == ".whl" or path.name.lower().endswith(".tar.gz")):
            if not _is_project_artifact(path):
                continue
            candidates.append(path)
    if not candidates:
        raise MatrixInputError(
            f"no {PROJECT_DISTRIBUTION} wheel or sdist found in {directory}; "
            "put dependency wheels in a separate --dependency-dir"
        )

    sums_path = directory / "SHA256SUMS"
    checksums, checksum_file_error = _load_checksums(sums_path)
    if require_checksums and not sums_path.is_file():
        checksum_file_error = "SHA256SUMS is required but missing"

    artifacts: list[ArtifactSpec] = []
    for path in candidates:
        kind = "wheel" if path.suffix.lower() == ".whl" else "sdist"
        actual = _sha256_file(path)
        expected = checksums.get(path.name)
        error = checksum_file_error or ""
        if not error and checksum_file_error is None and sums_path.is_file():
            if expected is None:
                error = f"{path.name} is not listed in SHA256SUMS"
            elif expected != actual:
                error = f"{path.name} SHA256 mismatch: expected {expected}, got {actual}"
        artifacts.append(
            ArtifactSpec(
                path=path,
                kind=kind,
                sha256=actual,
                expected_sha256=expected,
                checksum_error=error,
            )
        )
    return artifacts, (sums_path if sums_path.is_file() else None)


def _clean_environment() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() not in {"PYTHONPATH", "PYTHONHOME"}
    }
    env.update(
        {
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
            "PIP_NO_INPUT": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PIP_CONFIG_FILE": os.devnull,
        }
    )
    return env


def _execute(argv: Sequence[str], cwd: Path, env: dict[str, str], timeout: float) -> CommandResult:
    try:
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=tuple(argv),
            exit_code=None,
            stdout=exc.stdout if isinstance(exc.stdout, str) else "",
            stderr=exc.stderr if isinstance(exc.stderr, str) else "",
            timed_out=True,
        )
    except OSError as exc:
        return CommandResult(argv=tuple(argv), exit_code=None, stderr=str(exc))
    return CommandResult(
        argv=tuple(argv),
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _venv_python(venv_dir: Path, os_name: str) -> Path:
    if os_name == "windows":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _command_report(result: CommandResult) -> dict[str, Any]:
    return result.to_dict()


def _run_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    execute: Callable[[Sequence[str], Path, dict[str, str], float], CommandResult],
) -> tuple[CommandResult, dict[str, Any]]:
    result = execute(argv, cwd, env, timeout)
    return result, _command_report(result)


def _cell(
    *,
    artifact: ArtifactSpec,
    interpreter: InterpreterSpec,
    candidate_sha: str | None,
    dependency_dir: Path,
    temp_root: Path,
    timeout: float,
    execute: Callable[[Sequence[str], Path, dict[str, str], float], CommandResult],
) -> dict[str, Any]:
    commands: list[dict[str, Any]] = []
    uncovered: list[str] = []
    status = "pass"

    def append(result: CommandResult) -> bool:
        commands.append(_command_report(result))
        if result.exit_code != 0:
            nonlocal status
            status = "fail"
            if result.timed_out:
                uncovered.append("command timed out")
            return False
        return True

    if artifact.checksum_error:
        status = "fail"
        uncovered.append(artifact.checksum_error)
    elif not interpreter.resolved:
        status = "blocked"
        uncovered.append(f"interpreter not found: {interpreter.declared}")
    else:
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{interpreter.os_name}-{interpreter.python}-{artifact.path.stem}")
        venv_dir = temp_root / safe_name
        env = _clean_environment()
        create, _ = _run_command(
            [interpreter.resolved, "-m", "venv", str(venv_dir)],
            cwd=temp_root,
            env=env,
            timeout=timeout,
            execute=execute,
        )
        if not append(create):
            uncovered.append("venv creation failed")
        else:
            python = _venv_python(venv_dir, interpreter.os_name)
            if not python.is_file():
                status = "fail"
                uncovered.append(f"venv interpreter missing: {python}")
            else:
                find_links_args = ["--find-links", str(dependency_dir)]
                if dependency_dir.resolve() != artifact.path.parent.resolve():
                    find_links_args.extend(["--find-links", str(artifact.path.parent)])
                build_install = [
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--find-links",
                    str(dependency_dir),
                    "--no-input",
                    "--disable-pip-version-check",
                    "--no-warn-script-location",
                    *BUILD_REQUIREMENTS,
                ]
                install = [
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    *find_links_args,
                    "--no-input",
                    "--disable-pip-version-check",
                    "--no-warn-script-location",
                    str(artifact.path),
                ]
                build_ok = True
                if artifact.kind == "sdist":
                    build_ok = append(
                        _run_command(
                            build_install,
                            cwd=temp_root,
                            env=env,
                            timeout=timeout,
                            execute=execute,
                        )[0]
                    )
                    if not build_ok:
                        uncovered.append(
                            "offline build requirements unavailable; sdist requires "
                            "setuptools>=77 and wheel in --dependency-dir"
                        )
                if build_ok:
                    install_args = install + ["--no-build-isolation"] if artifact.kind == "sdist" else install
                    result, _ = _run_command(
                        install_args,
                        cwd=temp_root,
                        env=env,
                        timeout=timeout,
                        execute=execute,
                    )
                    if not append(result):
                        uncovered.append("artifact installation failed")
                    else:
                        checks = (
                            [str(python), "-m", "surfacescope", "--version"],
                            [str(python), "-m", "surfacescope", "--dry-run", "--no-env", "http://127.0.0.1:8000/"],
                            [
                                str(python),
                                "-c",
                                "from surfacescope.assets import AssetManifest; "
                                "errors = AssetManifest().validate(); assert not errors, errors",
                            ],
                        )
                        for check in checks:
                            result, _ = _run_command(check, cwd=temp_root, env=env, timeout=timeout, execute=execute)
                            if not append(result):
                                uncovered.append(f"post-install check failed: {' '.join(check[-2:])}")
                                break

    if artifact.checksum_error:
        uncovered.append("artifact hash was not accepted")
    elif artifact.expected_sha256 is None:
        uncovered.append("SHA256SUMS did not bind this artifact")
    return {
        "artifact": artifact.path.name,
        "artifact_type": artifact.kind,
        "artifact_sha256": artifact.sha256,
        "candidate_sha": candidate_sha,
        "os": interpreter.os_name,
        "python": interpreter.python,
        "interpreter": interpreter.resolved or interpreter.declared,
        "declared_interpreter": interpreter.declared,
        "status": status,
        "commands": commands,
        "exit_codes": [item["exit_code"] for item in commands],
        "uncovered": uncovered,
    }


def _summary(cells: Sequence[dict[str, Any]]) -> dict[str, int]:
    counts = {"total": len(cells), "pass": 0, "fail": 0, "blocked": 0}
    for cell in cells:
        status = cell.get("status")
        if status in STATUSES:
            counts[status] += 1
    return counts


def validate_report(report: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in REPORT_KEYS:
        if key not in report:
            errors.append(f"missing report field: {key}")
    cells = report.get("cells")
    if not isinstance(cells, list):
        errors.append("cells must be a list")
        return errors
    for index, cell in enumerate(cells, start=1):
        if not isinstance(cell, dict):
            errors.append(f"cell {index} must be an object")
            continue
        for key in CELL_KEYS:
            if key not in cell:
                errors.append(f"cell {index} missing field: {key}")
        if cell.get("status") not in STATUSES:
            errors.append(f"cell {index} has invalid status: {cell.get('status')!r}")
        digest = str(cell.get("artifact_sha256") or "")
        if not SHA256_RE.fullmatch(digest):
            errors.append(f"cell {index} has invalid artifact_sha256")
        if not isinstance(cell.get("commands"), list):
            errors.append(f"cell {index} commands must be a list")
        if not isinstance(cell.get("exit_codes"), list):
            errors.append(f"cell {index} exit_codes must be a list")
        if cell.get("status") == "pass" and any(code != 0 for code in cell.get("exit_codes", [])):
            errors.append(f"cell {index} is pass with a non-zero exit code")
    summary = report.get("summary")
    if isinstance(summary, dict):
        expected = _summary(cells)
        if summary != expected:
            errors.append(f"summary mismatch: expected {expected}, got {summary}")
    return errors


def run_matrix(
    artifact_dir: str | Path,
    interpreters_path: str | Path,
    *,
    dependency_dir: str | Path | None = None,
    candidate_sha: str | None = None,
    require_checksums: bool = False,
    require_dependencies: bool = False,
    timeout: float = 900.0,
    keep_temp: bool = False,
    execute: Callable[[Sequence[str], Path, dict[str, str], float], CommandResult] = _execute,
) -> dict[str, Any]:
    if candidate_sha is not None and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", candidate_sha):
        raise MatrixInputError("candidate SHA must be 40 or 64 lowercase hexadecimal characters")
    if timeout <= 0:
        raise MatrixInputError("timeout must be positive")
    if require_dependencies and dependency_dir is None:
        raise MatrixInputError("--dependency-dir is required for a real offline install matrix")
    artifacts, checksum_file = discover_artifacts(artifact_dir, require_checksums=require_checksums)
    interpreters = load_interpreters(interpreters_path)
    resolved_dependency_dir = (
        Path(dependency_dir).expanduser().resolve()
        if dependency_dir is not None
        else Path(artifact_dir).expanduser().resolve()
    )
    dependency_artifacts = discover_dependency_artifacts(resolved_dependency_dir)
    if require_dependencies:
        if not dependency_artifacts:
            raise MatrixInputError(
                "dependency wheelhouse is empty; provide runtime and sdist build wheels"
            )
        missing = missing_dependency_distributions(dependency_artifacts, artifacts)
        if missing:
            raise MatrixInputError(
                "dependency wheelhouse is missing required distributions: "
                + ", ".join(missing)
            )

    temp_parent = _safe_temp_parent()
    temp_context: tempfile.TemporaryDirectory[str] | None = None
    if keep_temp:
        temp_root = Path(tempfile.mkdtemp(prefix="surfacescope-install-matrix-", dir=temp_parent))
    else:
        temp_context = tempfile.TemporaryDirectory(
            prefix="surfacescope-install-matrix-",
            dir=temp_parent,
        )
        temp_root = Path(temp_context.name)
    try:
        if temp_root.resolve() == ROOT.resolve() or ROOT.resolve() in temp_root.resolve().parents:
            raise MatrixInputError("temporary venv directory must be outside the repository")
        cells = [
            _cell(
                artifact=artifact,
                interpreter=interpreter,
                candidate_sha=candidate_sha,
                dependency_dir=resolved_dependency_dir,
                temp_root=temp_root,
                timeout=timeout,
                execute=execute,
            )
            for artifact in artifacts
            for interpreter in interpreters
        ]
        report = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "artifact_dir": str(Path(artifact_dir).expanduser().resolve()),
            "dependency_dir": str(resolved_dependency_dir),
            "dependency_artifacts": dependency_artifacts,
            "candidate_sha": candidate_sha,
            "checksum_file": str(checksum_file) if checksum_file else None,
            "summary": _summary(cells),
            "cells": cells,
            "interpreters": [interpreter.to_dict() for interpreter in interpreters],
        }
        errors = validate_report(report)
        if errors:
            raise MatrixInputError("; ".join(errors))
        return report
    finally:
        if temp_context is not None:
            temp_context.cleanup()
        else:
            print(f"kept temporary matrix directory: {temp_root}", file=sys.stderr)


def report_exit_code(report: dict[str, Any]) -> int:
    summary = report.get("summary")
    if not isinstance(summary, dict) or not summary.get("total"):
        return 2
    if (
        summary.get("pass", 0) == summary.get("total", 0)
        and not summary.get("fail", 0)
        and not summary.get("blocked", 0)
    ):
        return 0
    return 1


def format_table(report: dict[str, Any]) -> str:
    rows = [("artifact", "os", "python", "status", "commands", "exit_codes")]
    for cell in report.get("cells", []):
        rows.append(
            (
                str(cell.get("artifact", "")),
                str(cell.get("os", "")),
                str(cell.get("python", "")),
                str(cell.get("status", "")),
                str(len(cell.get("commands", []))),
                ",".join(str(item) for item in cell.get("exit_codes", [])),
            )
        )
    widths = [max(len(row[index]) for row in rows) for index in range(len(rows[0]))]
    lines = ["  ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in rows]
    summary = report.get("summary", {})
    lines.append("")
    lines.append(
        "summary: total={total} pass={pass} fail={fail} blocked={blocked}".format(
            total=summary.get("total", 0),
            **{
                "pass": summary.get("pass", 0),
                "fail": summary.get("fail", 0),
                "blocked": summary.get("blocked", 0),
            },
        )
    )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", required=True, help="directory containing built wheel/sdist artifacts")
    parser.add_argument(
        "--dependency-dir",
        help="offline wheelhouse for runtime and sdist build dependencies",
    )
    parser.add_argument("--interpreters", required=True, help="JSON interpreter manifest or list")
    parser.add_argument("--candidate-sha", help="REL-00/REL-01 candidate SHA for evidence binding")
    parser.add_argument("--require-checksums", action="store_true", help="require SHA256SUMS and an entry per artifact")
    parser.add_argument(
        "--require-dependencies",
        action="store_true",
        help="require an explicit --dependency-dir for a real offline matrix",
    )
    parser.add_argument("--json-out", type=Path, help="write machine-readable JSON to this path")
    parser.add_argument("--timeout", type=float, default=900.0, help="per-command timeout in seconds")
    parser.add_argument("--keep-temp", action="store_true", help="keep temporary venvs for debugging")
    args = parser.parse_args(argv)
    try:
        report = run_matrix(
            args.artifact_dir,
            args.interpreters,
            dependency_dir=args.dependency_dir,
            candidate_sha=args.candidate_sha,
            require_checksums=args.require_checksums,
            require_dependencies=args.require_dependencies,
            timeout=args.timeout,
            keep_temp=args.keep_temp,
        )
    except MatrixInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    table = format_table(report)
    if args.json_out:
        output = args.json_out.expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(table)
    else:
        print(table, file=sys.stderr)
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return report_exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
