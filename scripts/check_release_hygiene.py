#!/usr/bin/env python3
"""Fail when the public tree or Git index still describes the retired layout."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PREFIXES = (
    "lib/",
    "Packer-Fuzzer/",
    "ehole/",
    "db/",
    "static/",
    "chromedriver",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "AGENTS.md",
    "docs/internal/",
    "docs/archive/",
)
FORBIDDEN_SUFFIXES = (
    ".pyc",
    ".exe",
    ".dll",
    ".pyd",
    ".so",
    ".dylib",
    ".docx",
    ".xlsx",
    ".pdf",
    ".zip",
    ".whl",
)
REQUIRED_PUBLIC_PATHS = (
    "README.md",
    "CHANGELOG.md",
    "NOTICE.md",
    "pyproject.toml",
    ".editorconfig",
    ".gitattributes",
    ".gitignore",
    "dirsearch.py",
    "single_403pass.py",
    "swagger.py",
    "src/surfacescope/__init__.py",
    ".github/SECURITY.md",
    ".github/CONTRIBUTING.md",
    ".github/CODE_OF_CONDUCT.md",
    ".github/workflows/ci.yml",
    ".github/dependabot.yml",
    ".github/pull_request_template.md",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    "docs/QUICKSTART.md",
    "docs/CLI_REFERENCE.md",
    "docs/COMPATIBILITY.md",
    "docs/DEVELOPMENT.md",
    "docs/PROJECT_STRUCTURE.md",
)

def _git_paths(*args: str) -> list[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [item.decode("utf-8", errors="replace") for item in result.stdout.split(b"\0") if item]


def _legacy_paths(paths: list[str]) -> list[str]:
    return sorted(
        {
            path
            for path in paths
            if any(path == prefix.rstrip("/") or path.startswith(prefix) for prefix in FORBIDDEN_PREFIXES)
            or path.lower().endswith(FORBIDDEN_SUFFIXES)
        }
    )


def main() -> int:
    errors: list[str] = []
    index_paths = _git_paths("ls-files", "-z")
    head_paths = _git_paths("ls-tree", "-r", "-z", "--name-only", "HEAD")
    for label, paths in (("index", index_paths), ("HEAD", head_paths)):
        legacy = _legacy_paths(paths)
        if legacy:
            errors.append(f"{label} still tracks {len(legacy)} retired paths; first: {legacy[:8]}")
    missing = [path for path in REQUIRED_PUBLIC_PATHS if not (ROOT / path).is_file()]
    if missing:
        errors.append(f"worktree is missing required public paths: {missing}")
    if errors:
        print("release hygiene: FAILED", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        print("Commit the reviewed working tree, then rerun this gate from a clean worktree.", file=sys.stderr)
        return 1
    print(f"release hygiene: ok (index={len(index_paths)}, HEAD={len(head_paths)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
