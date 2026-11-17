#!/usr/bin/env python3
"""Compute the reproducible ``worktree_sha256`` source snapshot digest.

The digest implements ``worktree_sha256 algorithm v1``. It binds local and matrix
evidence to the tracked and unignored files in the source/test/build scope without
treating a dirty worktree as a Git candidate SHA.

The implementation is intentionally standard-library only and fail-closed: an
empty scope, Git failure, duplicate or malformed path list, symlink,
non-regular file, missing file, or unreadable file is an error rather than an
empty digest that could be mistaken for successful evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = 1
WORKTREE_SCOPE = "source-test-build-v1"
WORKTREE_ALGORITHM = "worktree_sha256 algorithm v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SCOPE_DIRECTORIES = (
    "src/",
    "tests/",
    "scripts/",
    ".github/",
)
SCOPE_FILES = frozenset(
    {
        "pyproject.toml",
        ".gitignore",
        ".gitattributes",
        ".editorconfig",
        "NOTICE.md",
        "dirsearch.py",
        "single_403pass.py",
        "swagger.py",
    }
)
GIT_LIST_COMMAND = (
    "git",
    "ls-files",
    "-z",
    "--cached",
    "--others",
    "--exclude-standard",
)


class WorktreeDigestError(ValueError):
    """Raised when the source snapshot cannot produce honest evidence."""


def normalise_path(value: str) -> str:
    """Validate and return a repository-relative POSIX path."""

    if not value:
        raise WorktreeDigestError("empty path in Git file list")
    if "\x00" in value or "\\" in value:
        raise WorktreeDigestError(f"invalid path separator or NUL in {value!r}")
    if value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise WorktreeDigestError(f"absolute path is not allowed: {value!r}")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise WorktreeDigestError(f"non-canonical path: {value!r}")
    return value


def in_scope(value: str) -> bool:
    """Return whether a validated path belongs to the v1 digest scope."""

    return value in SCOPE_FILES or any(value.startswith(prefix) for prefix in SCOPE_DIRECTORIES)


def _assert_regular_file(root: Path, relative: str) -> Path:
    current = root
    parts = relative.split("/")
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise WorktreeDigestError(f"cannot stat {relative!r}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise WorktreeDigestError(f"symlink is not allowed in scope: {relative!r}")
        if index < len(parts) - 1:
            if not stat.S_ISDIR(info.st_mode):
                raise WorktreeDigestError(
                    f"non-directory parent in scope path: {relative!r}"
                )
        elif not stat.S_ISREG(info.st_mode):
            raise WorktreeDigestError(
                f"non-regular file is not allowed in scope: {relative!r}"
            )
    return current


def _read_bytes(path: Path, relative: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise WorktreeDigestError(f"cannot read {relative!r}: {exc}") from exc


def list_files(
    root: str | Path,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
) -> list[str]:
    """Return the tracked and unignored Git file list, or fail closed."""

    base = Path(root).expanduser()
    if not base.is_dir():
        raise WorktreeDigestError(f"repository root does not exist: {base}")
    execute = runner or subprocess.run
    try:
        completed = execute(
            list(GIT_LIST_COMMAND),
            cwd=str(base),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WorktreeDigestError(f"git ls-files could not run: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or b"").decode("utf-8", "replace").strip()
        raise WorktreeDigestError(
            f"git ls-files failed with exit {completed.returncode}: {detail or 'no stderr'}"
        )
    raw = completed.stdout
    if not isinstance(raw, bytes):
        raise WorktreeDigestError("git ls-files did not return raw bytes")
    if raw and not raw.endswith(b"\x00"):
        raise WorktreeDigestError("git ls-files output is not NUL-terminated")

    entries: list[str] = []
    for raw_path in raw.split(b"\x00")[:-1] if raw else []:
        if not raw_path:
            raise WorktreeDigestError("git ls-files returned an empty path")
        try:
            value = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WorktreeDigestError(f"git path is not UTF-8: {exc}") from exc
        entries.append(normalise_path(value))
    if len(entries) != len(set(entries)):
        raise WorktreeDigestError("git ls-files returned duplicate paths")
    return entries


def digest_paths(root: str | Path, paths: Iterable[str]) -> dict[str, Any]:
    """Compute the algorithm-v1 digest for an explicit path list."""

    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        raise WorktreeDigestError(f"repository root does not exist: {base}")

    all_paths: list[str] = []
    for value in paths:
        all_paths.append(normalise_path(str(value)))
    if len(all_paths) != len(set(all_paths)):
        raise WorktreeDigestError("file list contains duplicate paths")

    selected = sorted(
        (value for value in all_paths if in_scope(value)),
        key=lambda value: value.encode("utf-8"),
    )
    if not selected:
        raise WorktreeDigestError(
            f"worktree scope {WORKTREE_SCOPE!r} contains no files"
        )

    digest = hashlib.sha256()
    files: list[dict[str, str]] = []
    for relative in selected:
        path = _assert_regular_file(base, relative)
        payload = _read_bytes(path, relative)
        file_sha256 = hashlib.sha256(payload).hexdigest()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(file_sha256.encode("ascii"))
        digest.update(b"\n")
        files.append({"path": relative, "sha256": file_sha256})

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "worktree_scope": WORKTREE_SCOPE,
        "worktree_algorithm": WORKTREE_ALGORITHM,
        "file_count": len(files),
        "files": files,
        "worktree_sha256": digest.hexdigest(),
    }


def build_report(
    root: str | Path = ROOT,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
) -> dict[str, Any]:
    """List Git files and compute the source snapshot digest."""

    return digest_paths(root, list_files(root, runner=runner))


def _write_json(report: dict[str, Any], destination: str | Path) -> Path:
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)
    return path


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument("--json-out", type=Path, help="write the report to this path")
    parser.add_argument(
        "--expect",
        help="fail unless the computed digest equals this lowercase SHA-256",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        report = build_report(args.root)
    except WorktreeDigestError as exc:
        print(f"worktree: failed: {exc}", file=sys.stderr)
        return 1

    digest = report["worktree_sha256"]
    if args.expect is not None:
        expected = args.expect.strip().lower()
        if not SHA256_RE.fullmatch(expected):
            print("worktree: failed: --expect must be a 64-character SHA-256", file=sys.stderr)
            return 1
        if digest != expected:
            print(
                f"worktree: failed: digest mismatch (expected {expected}, got {digest})",
                file=sys.stderr,
            )
            return 1

    if args.json_out is not None:
        try:
            destination = _write_json(report, args.json_out)
        except OSError as exc:
            print(f"worktree: failed: cannot write {args.json_out}: {exc}", file=sys.stderr)
            return 1
        print(
            f"worktree: ok (files={report['file_count']}, sha256={digest}, "
            f"json={destination})"
        )
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
