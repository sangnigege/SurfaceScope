#!/usr/bin/env python3
"""Validate the public documentation tree.

The public repository deliberately contains user and developer documentation only.
Private plans, evidence logs and candidate records live outside the public tree.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
FENCE = "```"
TOP_LEVEL_DOCS = (
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "NOTICE.md",
)
REQUIRED_DOCS = (
    *TOP_LEVEL_DOCS,
    "docs/QUICKSTART.md",
    "docs/CLI_REFERENCE.md",
    "docs/CONFIGURATION.md",
    "docs/COMPONENTS.md",
    "docs/COMPATIBILITY.md",
    "docs/DIRSEARCH_PARITY.md",
    "docs/QUALITY.md",
    "docs/ASSETS.md",
    "docs/MIGRATION.md",
    "docs/NAMING.md",
    "docs/TROUBLESHOOTING.md",
    "docs/DEVELOPMENT.md",
    "docs/PROJECT_STRUCTURE.md",
    "docs/SECURITY.md",
)
PRIVATE_MARKERS = (
    "surface-scope-evidence",
    "candidate-",
    "E:\\",
    "/mnt/e/",
    "C:\\Users\\",
    "未提交工作树",
    "PLAN_INDEX",
    "TASK_LEDGER",
    "VERIFICATION.md",
    "RELEASE_EVIDENCE",
    "AUDIT_FINDINGS",
    "AGENTS.md",
    "docs/internal",
    "docs/archive",
)
README_VERSION_RE = re.compile(r"当前公开版本：`([^`]+)`")


def _paths(root: Path) -> list[Path]:
    paths = [root / name for name in TOP_LEVEL_DOCS if (root / name).exists()]
    docs = root / "docs"
    if docs.is_dir():
        paths.extend(sorted(docs.glob("*.md")))
    return paths


def _check_text(path: Path, root: Path) -> list[str]:
    errors: list[str] = []
    rel = path.relative_to(root)
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        errors.append(f"{rel}: UTF-8 BOM is not allowed")
    if b"\r" in raw:
        errors.append(f"{rel}: CRLF/CR line endings are not allowed")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [f"{rel}: invalid UTF-8: {exc}"]
    if not text.endswith("\n"):
        errors.append(f"{rel}: missing final newline")
    if text.count(FENCE) % 2:
        errors.append(f"{rel}: odd number of code fences")

    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        if line.rstrip() != line:
            errors.append(f"{rel}:{number}: trailing whitespace")

    headings: list[tuple[int, int, str]] = []
    in_fence = False
    for number, line in enumerate(lines, 1):
        if line.startswith(FENCE):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = re.match(r"^(#{1,6})\s+(.+)$", line)
        if match:
            headings.append((number, len(match.group(1)), match.group(2).strip()))

    seen: dict[tuple[int, str], int] = {}
    previous_level = 0
    for number, level, title in headings:
        key = (level, title)
        if key in seen and path.name != "CHANGELOG.md":
            errors.append(f"{rel}:{number}: duplicate heading {title!r} (first at line {seen[key]})")
        seen.setdefault(key, number)
        if previous_level and level > previous_level + 1:
            errors.append(f"{rel}:{number}: heading level jumps {previous_level}->{level}")
        previous_level = level

    for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
        target = target.strip().split(" ", 1)[0].strip("<>")
        if not target or target.startswith(("#", "http://", "https://", "mailto:")):
            continue
        clean = target.split("#", 1)[0]
        if not clean:
            continue
        candidates = (path.parent / clean, root / clean)
        if not any(candidate.exists() for candidate in candidates):
            errors.append(f"{rel}: missing local link target {target!r}")

    in_table = False
    expected_columns: int | None = None
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            columns = len(re.findall(r"(?<!\\)\|", stripped)) - 1
            if not in_table:
                in_table = True
                expected_columns = columns
            elif expected_columns != columns:
                errors.append(f"{rel}:{number}: table has {columns} columns, expected {expected_columns}")
        else:
            in_table = False
            expected_columns = None
    return errors


def check_markdown_tree(root: Path) -> list[str]:
    errors: list[str] = []
    for path in _paths(root):
        errors.extend(_check_text(path, root))
    return errors


def check_required_docs(root: Path) -> list[str]:
    return [f"missing public document: {relative}" for relative in REQUIRED_DOCS if not (root / relative).is_file()]


def check_private_markers(root: Path) -> list[str]:
    errors: list[str] = []
    for path in _paths(root):
        rel = path.relative_to(root)
        text = path.read_text(encoding="utf-8")
        for marker in PRIVATE_MARKERS:
            for number, line in enumerate(text.splitlines(), 1):
                if marker in line:
                    errors.append(f"{rel}:{number}: private marker {marker!r}")
    return errors


def check_version_identity(root: Path) -> list[str]:
    pyproject_path = root / "pyproject.toml"
    if not pyproject_path.is_file():
        return ["pyproject.toml: missing pyproject.toml"]
    try:
        pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return [f"pyproject.toml: invalid pyproject.toml: {exc}"]
    project = pyproject.get("project")
    version = project.get("version") if isinstance(project, dict) else None
    if not isinstance(version, str) or not version:
        return ["pyproject.toml: missing project version"]
    readme_path = root / "README.md"
    if not readme_path.is_file():
        return ["README.md: missing README.md"]
    readme = readme_path.read_text(encoding="utf-8")
    readme_match = README_VERSION_RE.search(readme)
    if not readme_match:
        return ["README.md: missing current public version marker"]
    if readme_match.group(1) != version:
        return [f"README.md version {readme_match.group(1)} != pyproject version {version}"]
    return []


def check(root: Path = ROOT) -> list[str]:
    errors = check_required_docs(root)
    errors.extend(check_markdown_tree(root))
    errors.extend(check_private_markers(root))
    errors.extend(check_version_identity(root))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    root = args.root.resolve()
    errors = check(root)
    if errors:
        print("documentation: FAILED", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"documentation: ok ({len(_paths(root))} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
