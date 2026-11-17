from __future__ import annotations

import hashlib
import json
import re

import pytest

import surfacescope.assets as assets_module
from surfacescope.assets import AssetManifest, WordlistRegistry, logical_item_count
from surfacescope.errors import AssetError


def test_manifest_validates_all_assets() -> None:
    manifest = AssetManifest()

    assert manifest.validate() == []
    assert manifest.schema_version == 3
    assert len(tuple(manifest.all())) == 11


def test_manifest_metadata_matches_files() -> None:
    manifest = AssetManifest()

    for ref in manifest.all():
        data = ref.read_bytes()
        text = data.decode(ref.encoding)
        assert not data.startswith(b"\xef\xbb\xbf"), ref.id
        assert b"\r" not in data, ref.id
        assert data.endswith(b"\n"), ref.id
        assert ref.size_bytes == len(data), ref.id
        assert ref.sha256 == hashlib.sha256(data).hexdigest(), ref.id
        assert ref.raw_line_count == len(text.splitlines()), ref.id
        assert ref.item_count == logical_item_count(ref.kind, text), ref.id
        assert ref.canonical_id == ref.id, ref.id
        assert ref.copy_of is None, ref.id


def test_packer_credentials_are_explicitly_legacy_until_login_exists() -> None:
    manifest = AssetManifest()

    username = manifest.resolve("wordlist.credentials.username")
    password = manifest.resolve("wordlist.credentials.password")
    assert username.status == "legacy"
    assert password.status == "legacy"
    assert username.consumers == ()
    assert password.consumers == ()


def test_wordlist_registry_reads_and_deduplicates() -> None:
    values = WordlistRegistry().lines("wordlist.paths.dicc")

    assert values
    assert len(values) == len(set(values))


def test_default_path_wordlist_is_curated_and_excludes_injection_noise() -> None:
    words = WordlistRegistry().lines("wordlist.paths.dicc")

    assert "api/config.json" in words
    assert "v3/api-docs" in words
    assert "swagger/v3.0/swagger.json" in words
    assert "llms.txt" in words
    assert ".well-known/ai-plugin.json" in words
    assert "api/openapi.json" in words
    assert "swagger-ui/index.html" in words
    assert "readyz" in words
    assert "livez" in words
    assert "data.php" in words
    assert not any(re.match(r"^(19|20)\d{2}(?:\.|/|$)", word) for word in words)
    assert not any("etc/passwd" in word for word in words)


def test_status_suffix_filters_are_loaded_from_manifest() -> None:
    filters = WordlistRegistry().status_suffix_filters()

    assert set(filters) == {400, 403, 500}
    assert len(filters[400]) == 8
    assert len(filters[403]) == 21
    assert len(filters[500]) == 5
    assert ".htaccess" in filters[403]


def test_manifest_rejects_v1_schema(monkeypatch, tmp_path) -> None:
    asset_root = tmp_path / "assets"
    asset_root.mkdir()
    (asset_root / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "assets": []}),
        encoding="utf-8",
    )
    monkeypatch.setattr(assets_module, "_asset_root", lambda: tmp_path)

    with pytest.raises(AssetError, match="expected 3"):
        AssetManifest()


def test_dedupe_assets_are_physically_unique() -> None:
    manifest = AssetManifest()

    for ref in manifest.all():
        if not ref.kind.startswith("wordlist.") or "dedupe" not in ref.normalization:
            continue
        lines = [
            line
            for line in ref.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        assert len(lines) == len(set(lines)), ref.id
