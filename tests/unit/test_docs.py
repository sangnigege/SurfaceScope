from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_docs.py"
_SPEC = importlib.util.spec_from_file_location("surfacescope_check_docs", SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
check_docs = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = check_docs
_SPEC.loader.exec_module(check_docs)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def test_current_public_documentation_passes() -> None:
    assert check_docs.check(ROOT) == []


def test_text_checks_reject_encoding_and_whitespace_defects(tmp_path: Path) -> None:
    sample = tmp_path / "sample.md"
    _write(sample, "# Heading\r\nbody  ")

    errors = check_docs._check_text(sample, tmp_path)

    assert any("CRLF/CR line endings" in error for error in errors)
    assert any("trailing whitespace" in error for error in errors)
    assert any("missing final newline" in error for error in errors)


def test_text_checks_reject_bom_duplicate_headings_and_broken_markdown(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "sample.md"
    _write(
        sample,
        "# Heading\n\n### Skipped level\n\n## Same\n\n## Same\n\n"
        "[missing](missing.md)\n\n| a | b |\n|---|---|\n| only one cell |\n",
    )
    errors = check_docs._check_text(sample, tmp_path)

    assert any("duplicate heading 'Same'" in error for error in errors)
    assert any("missing local link target" in error for error in errors)
    assert any("heading level jumps" in error for error in errors)
    assert any("table has 1 columns" in error for error in errors)

    sample.write_bytes(b"\xef\xbb\xbf" + sample.read_bytes())
    errors = check_docs._check_text(sample, tmp_path)

    assert any("UTF-8 BOM" in error for error in errors)


def test_text_checks_reject_invalid_utf8_and_odd_code_fences(tmp_path: Path) -> None:
    sample = tmp_path / "sample.md"
    sample.write_bytes(b"# Heading\n\n```text\n")

    errors = check_docs._check_text(sample, tmp_path)

    assert any("odd number of code fences" in error for error in errors)

    sample.write_bytes(b"\xff\xfe\x00")
    errors = check_docs._check_text(sample, tmp_path)

    assert any("invalid UTF-8" in error for error in errors)


def test_required_docs_reports_every_missing_public_file(tmp_path: Path) -> None:
    errors = check_docs.check_required_docs(tmp_path)

    assert len(errors) == len(check_docs.REQUIRED_DOCS)
    assert any("README.md" in error for error in errors)
    assert any("docs/QUICKSTART.md" in error for error in errors)

    for relative in check_docs.REQUIRED_DOCS:
        _write(tmp_path / relative, "# Document\n")

    assert check_docs.check_required_docs(tmp_path) == []


def test_private_markers_and_internal_docs_are_not_part_of_the_public_tree(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "README.md",
        "# SurfaceScope\n\nE:\\AI\\private candidate-123 is still uncommitted\n",
    )
    _write(tmp_path / "docs" / "internal" / "PLAN_INDEX.md", "private plan\n")

    errors = check_docs.check_private_markers(tmp_path)

    assert any("private marker 'E:\\\\'" in error for error in errors)
    assert any("private marker 'candidate-'" in error for error in errors)
    assert all("docs/internal" not in error for error in errors)
    assert tmp_path / "docs" / "internal" / "PLAN_INDEX.md" not in check_docs._paths(tmp_path)


def test_version_identity_requires_matching_project_and_readme_versions(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "surfacescope"\nversion = "1.2.3"\n',
    )
    _write(tmp_path / "README.md", "当前公开版本：`1.2.3`\n")

    assert check_docs.check_version_identity(tmp_path) == []

    _write(tmp_path / "README.md", "当前公开版本：`1.2.4`\n")
    errors = check_docs.check_version_identity(tmp_path)

    assert any("README.md version 1.2.4 != pyproject version 1.2.3" in error for error in errors)


def test_version_identity_rejects_missing_or_invalid_toml(tmp_path: Path) -> None:
    _write(tmp_path / "README.md", "当前公开版本：`0.2.0`\n")

    errors = check_docs.check_version_identity(tmp_path)

    assert any("missing pyproject.toml" in error for error in errors)

    _write(tmp_path / "pyproject.toml", "[project\nversion = '0.2.0'\n")
    errors = check_docs.check_version_identity(tmp_path)

    assert any("invalid pyproject.toml" in error for error in errors)


def test_check_aggregates_public_document_failures(tmp_path: Path) -> None:
    _write(tmp_path / "README.md", "# SurfaceScope\n\ncandidate-123\n")

    errors = check_docs.check(tmp_path)

    assert any("missing public document" in error for error in errors)
    assert any("private marker 'candidate-'" in error for error in errors)
    assert any("missing pyproject.toml" in error for error in errors)

def test_version_identity_allows_readme_without_marker(tmp_path: Path) -> None:
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "surfacescope"\nversion = "1.2.3"\n',
    )
    _write(tmp_path / "README.md", "# SurfaceScope\n")

    assert check_docs.check_version_identity(tmp_path) == []