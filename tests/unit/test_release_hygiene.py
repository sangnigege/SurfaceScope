from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_release_hygiene.py"
_SPEC = importlib.util.spec_from_file_location("surfacescope_check_release_hygiene", SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
check_release_hygiene = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = check_release_hygiene
_SPEC.loader.exec_module(check_release_hygiene)


def test_release_hygiene_rejects_private_paths_and_binary_objects() -> None:
    paths = [
        "README.md",
        "src/surfacescope/cli.py",
        "AGENTS.md",
        "docs/internal/PLAN.md",
        "docs/archive/old.md",
        "tools/chromedriver.exe",
        "reports/result.docx",
        "dist/surfacescope-0.2.0-py3-none-any.whl",
        "src/surfacescope/__pycache__/cli.cpython-312.pyc",
    ]

    assert check_release_hygiene._legacy_paths(paths) == sorted(
        {
            "AGENTS.md",
            "docs/internal/PLAN.md",
            "docs/archive/old.md",
            "tools/chromedriver.exe",
            "reports/result.docx",
            "dist/surfacescope-0.2.0-py3-none-any.whl",
            "src/surfacescope/__pycache__/cli.cpython-312.pyc",
        }
    )


def test_release_hygiene_accepts_public_source_paths() -> None:
    assert check_release_hygiene._legacy_paths(
        [
            "README.md",
            "docs/PROJECT_STRUCTURE.md",
            "src/surfacescope/assets/fingerprints/finger.json",
            "tests/unit/test_release_hygiene.py",
        ]
    ) == []
