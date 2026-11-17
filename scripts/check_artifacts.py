#!/usr/bin/env python3
"""Validate built wheel/sdist contents without third-party dependencies."""

from __future__ import annotations

import argparse
import hashlib
import sys
import tarfile
import zipfile
from pathlib import Path

FORBIDDEN_PARTS = frozenset({"__pycache__", ".git", "lib", "Packer-Fuzzer", "ehole", "db", "static", "tests", "docs", ".venv"})
FORBIDDEN_NAMES = frozenset({"chromedriver", "chromedriver.exe", "ehole", "ehole.exe", "setup.py", "requirements.txt"})


def _normalized(name: str) -> str:
    return name.replace("\\", "/").strip("/")


def _forbidden(name: str) -> bool:
    normalized = _normalized(name)
    parts = set(normalized.split("/"))
    if parts & FORBIDDEN_PARTS:
        return True
    if Path(normalized).name in FORBIDDEN_NAMES:
        return True
    return normalized.endswith((".pyc", ".pyo"))


def _required_suffix(name: str, suffixes: tuple[str, ...]) -> bool:
    normalized = _normalized(name)
    return any(normalized.endswith(suffix) for suffix in suffixes)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_wheel(path: Path) -> list[str]:
    errors: list[str] = []
    with zipfile.ZipFile(path) as archive:
        names = [_normalized(name) for name in archive.namelist() if not name.endswith("/")]
    for name in names:
        if _forbidden(name):
            errors.append(f"wheel contains forbidden path: {name}")
    required = (
        ("surfacescope/assets/manifest.json",),
    )
    for suffixes in required:
        if not any(_required_suffix(name, suffixes) for name in names):
            errors.append(f"wheel missing required suffix: {suffixes[0]}")
    return errors


def check_sdist(path: Path) -> list[str]:
    errors: list[str] = []
    with tarfile.open(path, "r:gz") as archive:
        names = [_normalized(member.name) for member in archive.getmembers() if member.isfile()]
    for name in names:
        if _forbidden(name):
            errors.append(f"sdist contains forbidden path: {name}")
    required_suffixes = (
        "pyproject.toml",
        "src/surfacescope/assets/manifest.json",
    )
    for suffix in required_suffixes:
        if not any(name.endswith(suffix) for name in names):
            errors.append(f"sdist missing required suffix: {suffix}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", nargs="?", default="dist")
    args = parser.parse_args()
    dist = Path(args.dist).resolve()
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    errors: list[str] = []
    if len(wheels) != 1:
        errors.append(f"expected exactly one wheel in {dist}, found {len(wheels)}")
    if len(sdists) != 1:
        errors.append(f"expected exactly one sdist in {dist}, found {len(sdists)}")
    if wheels:
        errors.extend(check_wheel(wheels[0]))
    if sdists:
        errors.extend(check_sdist(sdists[0]))
    if errors:
        print("artifacts: FAILED", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    wheel = wheels[0]
    sdist = sdists[0]
    with zipfile.ZipFile(wheel) as archive:
        wheel_files = sum(1 for name in archive.namelist() if not name.endswith("/"))
    with tarfile.open(sdist, "r:gz") as archive:
        sdist_files = sum(1 for member in archive.getmembers() if member.isfile())
    print(f"wheel: {wheel.name} files={wheel_files} bytes={wheel.stat().st_size} sha256={_digest(wheel)}")
    print(f"sdist: {sdist.name} files={sdist_files} bytes={sdist.stat().st_size} sha256={_digest(sdist)}")
    print("artifacts: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
