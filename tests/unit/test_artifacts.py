from __future__ import annotations

from surfacescope.artifacts import ArtifactStore


def test_artifact_store_never_falls_back_to_the_working_directory(tmp_path, monkeypatch) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.setattr(
        "surfacescope.tempdirs._default_candidates",
        lambda: [work, tmp_path],
    )

    store = ArtifactStore()
    try:
        root = store.root.resolve()
        assert root != work.resolve()
        assert work.resolve() not in root.parents
        assert root.parent == tmp_path.resolve()
    finally:
        store.cleanup()
