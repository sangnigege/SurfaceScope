from __future__ import annotations

import pytest

from surfacescope.tempdirs import TemporaryDirectoryError, make_temp_dir, select_temp_parent


def test_select_temp_parent_skips_excluded_candidate(tmp_path) -> None:
    work = tmp_path / "work"
    fallback = tmp_path / "fallback"
    work.mkdir()
    fallback.mkdir()

    parent = select_temp_parent(exclude=[work], candidates=[work, fallback])

    assert parent == fallback.resolve()


def test_make_temp_dir_uses_a_safe_parent(tmp_path) -> None:
    work = tmp_path / "work"
    fallback = tmp_path / "fallback"
    work.mkdir()
    fallback.mkdir()

    created = make_temp_dir("probe-", exclude=[work], candidates=[work, fallback])
    try:
        assert created.parent == fallback.resolve()
        assert created.is_dir()
        assert work not in created.parents
    finally:
        created.rmdir()


def test_select_temp_parent_rejects_unusable_candidates(tmp_path) -> None:
    work = tmp_path / "work"
    not_a_directory = tmp_path / "file"
    work.mkdir()
    not_a_directory.write_text("occupied", encoding="utf-8")

    with pytest.raises(TemporaryDirectoryError, match="no writable temporary directory"):
        select_temp_parent(exclude=[work], candidates=[work, not_a_directory])
