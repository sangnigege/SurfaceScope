from __future__ import annotations

import json
from pathlib import Path

import pytest

from surfacescope.assets import AssetManifest
from surfacescope.config import load_config
from surfacescope.errors import ConfigurationError


def test_default_config_is_loadable_and_typed() -> None:
    config = load_config(include_env=False)

    assert config.sources == ("defaults",)
    assert config.section("run")["threads"] == 25
    assert config.section("bypass")["mode"] == "fast"
    assert config.section("bypass")["initial_variants_per_url"] == 0
    assert config.section("bypass")["max_variants_per_url"] == 0
    assert config.section("traffic")["verify_tls"] is True


def test_every_default_config_key_is_declared_in_the_schema() -> None:
    manifest = AssetManifest()
    defaults = load_config(include_env=False, manifest=manifest).to_dict()
    schema = json.loads(manifest.resolve("config.schema").read_text())

    def assert_keys(value: dict, node: dict, path: str = "$") -> None:
        properties = node.get("properties", {})
        for key, child in value.items():
            assert key in properties, f"{path}.{key} is missing from schema"
            if isinstance(child, dict):
                assert_keys(child, properties[key], f"{path}.{key}")

    assert_keys(defaults, schema)


def test_config_loads_defaults_and_schema_through_manifest() -> None:
    manifest = AssetManifest()
    requested: list[str] = []

    class RecordingManifest:
        def resolve(self, asset_id: str):
            requested.append(asset_id)
            return manifest.resolve(asset_id)

    config = load_config(include_env=False, manifest=RecordingManifest())  # type: ignore[arg-type]

    assert config.section("run")["threads"] == 25
    assert requested == ["config.defaults", "config.schema"]


def test_overrides_take_priority_over_defaults() -> None:
    config = load_config(include_env=False, overrides={"run": {"threads": 3}})

    assert config.section("run")["threads"] == 3
    assert config.sources == ("defaults", "cli")


def test_environment_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SURFACESCOPE_THREADS", "7")

    assert load_config(include_env=False).section("run")["threads"] == 25
    assert load_config(include_env=True).section("run")["threads"] == 7


def test_legacy_dsbp_environment_prefix_is_still_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SURFACESCOPE_THREADS", raising=False)
    monkeypatch.setenv("DSBP_THREADS", "9")

    assert load_config(include_env=True).section("run")["threads"] == 9


def test_legacy_user_path_keyword_is_supported(tmp_path: Path) -> None:
    user_config = tmp_path / "user.toml"
    user_config.write_text("[run]\nthreads = 2\n", encoding="utf-8")

    config = load_config(user_path=user_config, include_env=False)

    assert config.section("run")["threads"] == 2
    assert str(user_config) in config.sources


def test_user_config_and_user_path_cannot_be_combined(tmp_path: Path) -> None:
    user_config = tmp_path / "user.toml"
    user_config.write_text("[run]\nthreads = 2\n", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="only one"):
        load_config(user_config=user_config, user_path=user_config)
