"""Configuration loading, merging, and validation."""

from __future__ import annotations

import copy
import json
import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._compat import tomllib
from .assets import AssetManifest
from .errors import ConfigurationError


def _deep_merge(base: dict[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = _deep_merge(dict(result[key]), value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _asset_json(manifest: AssetManifest, asset_id: str) -> dict[str, Any]:
    try:
        return json.loads(manifest.resolve(asset_id).read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise ConfigurationError(f"cannot load {asset_id}: {exc}") from exc


def _asset_toml(manifest: AssetManifest, asset_id: str) -> dict[str, Any]:
    try:
        return tomllib.loads(manifest.resolve(asset_id).read_text())
    except (tomllib.TOMLDecodeError, OSError) as exc:
        raise ConfigurationError(f"cannot load {asset_id}: {exc}") from exc


def _coerce_env_value(raw: str, default: Any, path: str) -> Any:
    if isinstance(default, bool):
        value = raw.strip().lower()
        if value in ("1", "true", "yes", "on"):
            return True
        if value in ("0", "false", "no", "off"):
            return False
        raise ConfigurationError(f"{path}: expected boolean, got {raw!r}")
    if isinstance(default, int) and not isinstance(default, bool):
        try:
            return int(raw)
        except ValueError as exc:
            raise ConfigurationError(f"{path}: expected integer, got {raw!r}") from exc
    if isinstance(default, float):
        try:
            return float(raw)
        except ValueError as exc:
            raise ConfigurationError(f"{path}: expected number, got {raw!r}") from exc
    return raw


def _validate(value: Any, schema: Mapping[str, Any], path: str = "$") -> list[str]:
    errors: list[str] = []
    expected = schema.get("type")
    if expected == "object" and not isinstance(value, Mapping):
        return [f"{path}: expected object"]
    if expected == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
        return [f"{path}: expected integer"]
    if expected == "number" and (not isinstance(value, (int, float)) or isinstance(value, bool)):
        return [f"{path}: expected number"]
    if expected == "boolean" and not isinstance(value, bool):
        return [f"{path}: expected boolean"]
    if expected == "string" and not isinstance(value, str):
        return [f"{path}: expected string"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value {value!r} is not in {schema['enum']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: above maximum {schema['maximum']}")
    if isinstance(value, Mapping):
        for key, child in schema.get("properties", {}).items():
            if key in value:
                errors.extend(_validate(value[key], child, f"{path}.{key}"))
    return errors


@dataclass(frozen=True)
class ConfigSnapshot(Mapping[str, Any]):
    data: Mapping[str, Any]
    sources: tuple[str, ...] = ("defaults",)

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.data)

    def __len__(self) -> int:
        return len(self.data)

    def section(self, name: str) -> Mapping[str, Any]:
        value = self.data.get(name, {})
        return value if isinstance(value, Mapping) else {}

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(dict(self.data))


def load_config(
    user_config: str | Path | None = None,
    overrides: Mapping[str, Any] | None = None,
    include_env: bool = True,
    *,
    user_path: str | Path | None = None,
    manifest: AssetManifest | None = None,
) -> ConfigSnapshot:
    if user_config is not None and user_path is not None:
        raise ConfigurationError("pass only one of user_config or user_path")
    if user_config is None:
        user_config = user_path
    manifest = manifest or AssetManifest()
    defaults = _asset_toml(manifest, "config.defaults")
    merged = defaults
    sources = ["defaults"]
    if user_config:
        path = Path(user_config).expanduser()
        if not path.exists():
            raise ConfigurationError(f"user config does not exist: {path}")
        try:
            user = tomllib.loads(path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError) as exc:
            raise ConfigurationError(f"cannot parse user config {path}: {exc}") from exc
        merged = _deep_merge(merged, user)
        sources.append(str(path))
    if include_env:
        env: dict[str, dict[str, Any]] = {"run": {}, "traffic": {}, "reports": {}}
        env_spec = {
            ("run", "threads"): "SURFACESCOPE_THREADS",
            ("run", "timeout"): "SURFACESCOPE_TIMEOUT",
            ("run", "profile"): "SURFACESCOPE_PROFILE",
            ("traffic", "verify_tls"): "SURFACESCOPE_VERIFY_TLS",
            ("reports", "format"): "SURFACESCOPE_FORMAT",
        }
        for (section, key), variable in env_spec.items():
            raw = os.getenv(variable)
            if raw in (None, ""):
                raw = os.getenv("DSBP_" + variable.removeprefix("SURFACESCOPE_"))
            if raw in (None, ""):
                continue
            default = merged.get(section, {}).get(key)
            env[section][key] = _coerce_env_value(raw, default, f"${variable}")
        env = {section: values for section, values in env.items() if values}
        if env:
            merged = _deep_merge(merged, env)
            sources.append("environment")
    if overrides:
        merged = _deep_merge(merged, overrides)
        sources.append("cli")
    schema = _asset_json(manifest, "config.schema")
    errors = _validate(merged, schema)
    if errors:
        raise ConfigurationError("; ".join(errors))
    return ConfigSnapshot(data=merged, sources=tuple(sources))
