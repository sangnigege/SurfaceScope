from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_worktree.py"
_SPEC = importlib.util.spec_from_file_location("surfacescope_check_worktree", SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
check_worktree = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = check_worktree
_SPEC.loader.exec_module(check_worktree)


def _write(root: Path, relative: str, payload: bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def _runner(*, returncode: int = 0, stdout: bytes = b"", stderr: bytes = b""):
    def execute(argv, **_kwargs):
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    return execute


def test_digest_is_stable_across_file_creation_order(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    _write(first, "src/b.py", b"b")
    _write(first, "src/a.py", b"a")
    _write(second, "src/a.py", b"a")
    _write(second, "src/b.py", b"b")

    left = check_worktree.digest_paths(first, ["src/a.py", "src/b.py"])
    right = check_worktree.digest_paths(second, ["src/b.py", "src/a.py"])

    assert left["worktree_sha256"] == right["worktree_sha256"]
    assert [item["path"] for item in left["files"]] == ["src/a.py", "src/b.py"]


def test_changed_file_bytes_change_the_digest(tmp_path: Path) -> None:
    _write(tmp_path, "src/a.py", b"one")
    before = check_worktree.digest_paths(tmp_path, ["src/a.py"])
    _write(tmp_path, "src/a.py", b"two")
    after = check_worktree.digest_paths(tmp_path, ["src/a.py"])

    assert before["worktree_sha256"] != after["worktree_sha256"]


def test_out_of_scope_docs_do_not_change_the_digest(tmp_path: Path) -> None:
    _write(tmp_path, "src/a.py", b"code")
    _write(tmp_path, "docs/notes.md", b"first")
    before = check_worktree.digest_paths(
        tmp_path, ["src/a.py", "docs/notes.md"]
    )
    _write(tmp_path, "docs/notes.md", b"second")
    after = check_worktree.digest_paths(
        tmp_path, ["src/a.py", "docs/notes.md"]
    )

    assert before["worktree_sha256"] == after["worktree_sha256"]
    assert [item["path"] for item in after["files"]] == ["src/a.py"]


def test_symlink_in_scope_is_rejected(tmp_path: Path, monkeypatch) -> None:
    link = _write(tmp_path, "src/link.py", b"simulated link")
    original_lstat = Path.lstat

    def fake_lstat(path: Path):
        if path == link:
            return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777)
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    with pytest.raises(check_worktree.WorktreeDigestError, match="symlink"):
        check_worktree.digest_paths(tmp_path, ["src/link.py"])


def test_empty_scope_is_rejected(tmp_path: Path) -> None:
    _write(tmp_path, "docs/README.md", b"docs only")

    with pytest.raises(check_worktree.WorktreeDigestError, match="contains no files"):
        check_worktree.digest_paths(tmp_path, ["docs/README.md"])


def test_missing_scoped_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(check_worktree.WorktreeDigestError, match="cannot stat"):
        check_worktree.digest_paths(tmp_path, ["src/missing.py"])


def test_unreadable_scoped_file_is_rejected(tmp_path: Path, monkeypatch) -> None:
    _write(tmp_path, "src/a.py", b"code")

    def fail_read(_path: Path, relative: str) -> bytes:
        raise check_worktree.WorktreeDigestError(f"cannot read {relative!r}")

    monkeypatch.setattr(check_worktree, "_read_bytes", fail_read)
    with pytest.raises(check_worktree.WorktreeDigestError, match="cannot read"):
        check_worktree.digest_paths(tmp_path, ["src/a.py"])


def test_git_failure_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(check_worktree.WorktreeDigestError, match="git ls-files failed"):
        check_worktree.list_files(
            tmp_path,
            runner=_runner(returncode=128, stderr=b"fatal: not a git repository"),
        )


def test_duplicate_git_paths_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(check_worktree.WorktreeDigestError, match="duplicate paths"):
        check_worktree.list_files(
            tmp_path,
            runner=_runner(stdout=b"src/a.py\x00src/a.py\x00"),
        )


def test_utf8_path_byte_order_controls_the_digest(tmp_path: Path) -> None:
    names = ["src/é.py", "src/z.py", "src/Ä.py"]
    for name in names:
        _write(tmp_path, name, name.encode("utf-8"))

    report = check_worktree.digest_paths(tmp_path, names)

    assert [item["path"] for item in report["files"]] == sorted(
        names, key=lambda value: value.encode("utf-8")
    )
    expected = hashlib.sha256()
    for name in sorted(names, key=lambda value: value.encode("utf-8")):
        file_sha256 = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        expected.update(name.encode("utf-8") + b"\x00" + file_sha256.encode("ascii") + b"\n")
    assert report["worktree_sha256"] == expected.hexdigest()


def test_json_output_shape_and_expected_digest_mismatch(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    _write(tmp_path, "src/a.py", b"code")
    report = check_worktree.digest_paths(tmp_path, ["src/a.py"])
    monkeypatch.setattr(check_worktree, "build_report", lambda _root: report)
    destination = tmp_path / "worktree.json"

    exit_code = check_worktree.main(
        [
            "--root",
            str(tmp_path),
            "--json-out",
            str(destination),
            "--expect",
            report["worktree_sha256"],
        ]
    )

    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert payload["schema_version"] == 1
    assert payload["worktree_scope"] == "source-test-build-v1"
    assert payload["worktree_algorithm"] == "worktree_sha256 algorithm v1"
    assert payload["file_count"] == 1
    assert payload["files"] == [
        {"path": "src/a.py", "sha256": hashlib.sha256(b"code").hexdigest()}
    ]
    assert "worktree: ok" in capsys.readouterr().out

    assert (
        check_worktree.main(
            [
                "--root",
                str(tmp_path),
                "--expect",
                "0" * 64,
            ]
        )
        == 1
    )
