from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from surfacescope._compat import tomllib

ROOT = Path(__file__).resolve().parents[2]


def _git(*arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout


def test_only_root_git_directory_exists() -> None:
    if not (ROOT / ".git").exists():
        pytest.skip("source tree is not a Git checkout")
    git_dirs: list[Path] = []
    for current, directories, _ in os.walk(ROOT):
        directories[:] = [name for name in directories if name not in {".git", ".venv", "build", "__pycache__"}]
        if ".git" in os.listdir(current):
            git_dirs.append(Path(current) / ".git")
    assert git_dirs == [ROOT / ".git"]


def test_generated_and_runtime_artifacts_are_not_tracked() -> None:
    if not (ROOT / ".git").exists():
        pytest.skip("source tree is not a Git checkout")
    tracked = [line.replace("\\", "/") for line in _git("ls-files").splitlines() if line]
    forbidden_suffixes = (".pyc",)
    forbidden_segments = ("__pycache__", ".DS_Store")
    forbidden_names = {
        "chromedriver",
        "chromedriver.exe",
        "403list.txt",
        "bypass403_url.txt",
        "jsfind403list.txt",
        "dir_file_path.txt",
        "output.txt",
        "dada.sql",
    }
    forbidden_exact = {"ehole/ehole", "ehole/ehole.exe"}
    violations = [
        path
        for path in tracked
        if path.endswith(forbidden_suffixes)
        or any(segment in path.split("/") for segment in forbidden_segments)
        or path.rsplit("/", 1)[-1] in forbidden_names
        or path in forbidden_exact
    ]
    assert violations == []


def test_root_import_side_effect_is_removed() -> None:
    assert not (ROOT / "__init__.py").exists()


def test_retired_root_scripts_and_binaries_are_gone() -> None:
    retired = {
        "chromedriver",
        "chromedriver.exe",
        "ehole/ehole",
        "ehole/ehole.exe",
        "test.py",
        "testing.py",
        "test_env.py",
        "test_packer_import.py",
        "403list.txt",
        "bypass403_url.txt",
        "jsfind403list.txt",
        "dir_file_path.txt",
        "output.txt",
        "dada.sql",
    }
    assert sorted(path for path in retired if (ROOT / path).exists()) == []


def test_legacy_component_trees_are_not_reintroduced() -> None:
    retired_directories = ("lib", "Packer-Fuzzer", "ehole", "db", "static")

    assert sorted(path for path in retired_directories if (ROOT / path).exists()) == []


def test_root_entrypoint_shims_delegate_to_unified_cli() -> None:
    for name in ("dirsearch.py", "single_403pass.py", "swagger.py"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "legacy_entry" in text
        assert "Packer-Fuzzer" not in text
        assert "requests" not in text
        assert "venv" not in text


def test_ignore_rules_cover_agent_and_runtime_files() -> None:
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (
        ".agent/",
        ".agent_tmp/",
        "docs/plans/scratch/",
        "__pycache__/",
        ".venv/",
        ".wheel-smoke/",
        "build/",
        "pytest-of-*/",
        "docs/internal/",
        "*.exe",
        "*.docx",
    ):
        assert pattern in ignore


def test_hygiene_suite_is_part_of_default_testpaths() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    testpaths = project["tool"]["pytest"]["ini_options"]["testpaths"]
    assert any(path == "tests" or path.rstrip("/") == "tests/hygiene" for path in testpaths)


def test_project_identity_is_surfacescope() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = project["project"]["scripts"]

    assert project["project"]["name"] == "surfacescope"
    assert "license" not in project["project"]
    assert "license-files" not in project["project"]
    assert (ROOT / ".github" / "SECURITY.md").is_file()
    assert not (ROOT / "SECURITY.md").exists()
    assert "surfacescope*" in project["tool"]["setuptools"]["packages"]["find"]["include"]
    assert scripts["surfacescope"] == "surfacescope.cli:main"
    assert scripts["sscope"] == scripts["surfacescope"]
    assert scripts["dsbp"] == scripts["surfacescope"]
    assert not (ROOT / "src" / "dirsearch_bypass403").exists()
    assert (ROOT / "docs" / "NAMING.md").is_file()
