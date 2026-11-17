"""Manifest-backed access to runtime assets."""

from __future__ import annotations

import hashlib
import importlib
import inspect
import json
from collections.abc import Iterable
from dataclasses import dataclass
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any

from ._compat import tomllib
from .errors import AssetError


def _asset_root():
    return files("surfacescope")


@dataclass(frozen=True, slots=True)
class AssetRef:
    id: str
    kind: str
    path: str
    version: str
    source: str
    source_sha256: str
    license: str
    license_file: str
    sha256: str
    size_bytes: int
    encoding: str
    raw_line_count: int
    item_count: int
    normalization: str
    normalization_version: int
    canonical_id: str
    copy_of: str | None
    consumers: tuple[str, ...]
    package: str
    status: str
    review_after: str
    source_refs: tuple[dict[str, str], ...] = ()
    merge_policy: str = "single-source"

    def read_bytes(self) -> bytes:
        try:
            return (_asset_root() / self.path).read_bytes()
        except (FileNotFoundError, IsADirectoryError, OSError) as exc:
            raise AssetError(f"asset {self.id} is unreadable at {self.path}: {exc}") from exc

    def read_text(self, encoding: str | None = None) -> str:
        data = self.read_bytes()
        try:
            return data.decode(encoding or self.encoding)
        except UnicodeDecodeError as exc:
            raise AssetError(f"asset {self.id} cannot be decoded as {encoding or self.encoding}") from exc


_ALLOWED_STATUSES = frozenset({"active", "deprecated", "legacy", "blocked"})
_ALLOWED_PACKAGES = frozenset(
    {"core", "packer-report", "dev-fixture", "test-fixture", "docs-asset", "legacy"}
)
_TEXT_KINDS = frozenset(
    {
        "config.defaults",
        "config.schema",
        "profile.request",
        "wordlist.paths",
        "wordlist.targets",
        "wordlist.credentials",
        "filter.status_suffix",
        "fingerprint.rules",
        "bypass.payloads",
    }
)


def _is_hex_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value.lower())


def _leaf_count(value: Any) -> int:
    if isinstance(value, dict):
        return sum(_leaf_count(child) for child in value.values())
    if isinstance(value, list):
        return len(value)
    return 1


def _schema_property_count(value: Any) -> int:
    if not isinstance(value, dict):
        return 0
    properties = value.get("properties", {})
    if not isinstance(properties, dict):
        return 0
    return len(properties) + sum(_schema_property_count(child) for child in properties.values())


def logical_item_count(kind: str, text: str) -> int | None:
    if kind.startswith("wordlist."):
        return len({line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")})
    if kind == "filter.status_suffix":
        payload = json.loads(text)
        groups = payload.get("groups", {})
        if not isinstance(groups, dict):
            raise ValueError("filter.status_suffix groups must be an object")
        return sum(
            len({str(item).strip() for item in values if str(item).strip()})
            for values in groups.values()
            if isinstance(values, list)
        )
    if kind == "fingerprint.rules":
        payload = json.loads(text)
        rules = payload.get("fingerprint", [])
        if not isinstance(rules, list):
            raise ValueError("fingerprint.rules must contain a fingerprint list")
        return len(rules)
    if kind == "profile.request":
        payload = json.loads(text)
        profiles = payload.get("profiles", [])
        if not isinstance(profiles, list):
            raise ValueError("profile.request must contain a profiles list")
        return len(profiles)
    if kind == "config.defaults":
        payload = tomllib.loads(text)
        return _leaf_count(payload)
    if kind == "config.schema":
        payload = json.loads(text)
        return _schema_property_count(payload)
    if kind == "bypass.payloads":
        payload = json.loads(text)
        if not isinstance(payload, dict):
            raise ValueError("bypass.payloads must be an object")
        count = 0
        for key, value in payload.items():
            if key == "source_files":
                continue
            if isinstance(value, (list, dict)):
                count += len(value)
        return count
    return None


class AssetManifest:
    def __init__(self, path: str = "assets/manifest.json") -> None:
        try:
            raw = json.loads((_asset_root() / path).read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
            raise AssetError(f"cannot load asset manifest: {exc}") from exc
        if raw.get("schema_version") != 3:
            raise AssetError("unsupported asset manifest schema_version; expected 3")
        self.schema_version = 3
        self._assets: dict[str, AssetRef] = {}
        for item in raw.get("assets", []):
            try:
                ref = AssetRef(
                    id=item["id"],
                    kind=item["kind"],
                    path=item["path"],
                    version=item["version"],
                    source=item["source"],
                    source_sha256=item["source_sha256"],
                    license=item["license"],
                    license_file=item["license_file"],
                    sha256=item["sha256"],
                    size_bytes=item["size_bytes"],
                    encoding=item.get("encoding", "utf-8"),
                    raw_line_count=item["raw_line_count"],
                    item_count=item["item_count"],
                    normalization=item["normalization"],
                    normalization_version=item["normalization_version"],
                    canonical_id=item["canonical_id"],
                    copy_of=item.get("copy_of"),
                    consumers=tuple(item.get("consumers", [])),
                    package=item.get("package", "core"),
                    status=item.get("status", "active"),
                    review_after=item.get("review_after", ""),
                    source_refs=tuple(
                        {str(key): str(value) for key, value in ref.items()}
                        for ref in item.get("source_refs", [])
                        if isinstance(ref, dict)
                    ),
                    merge_policy=str(item.get("merge_policy", "single-source")),
                )
            except KeyError as exc:
                raise AssetError(f"asset manifest entry missing {exc}") from exc
            if ref.id in self._assets:
                raise AssetError(f"duplicate asset id: {ref.id}")
            self._assets[ref.id] = ref

    def _consumer_errors(self, ref: AssetRef) -> list[str]:
        errors: list[str] = []
        for module_name in ref.consumers:
            try:
                module = importlib.import_module(module_name)
            except Exception as exc:
                errors.append(f"consumer import failed: {ref.id}: {module_name}: {exc}")
                continue
            try:
                source = inspect.getsource(module)
            except (OSError, TypeError) as exc:
                errors.append(f"consumer source unavailable: {ref.id}: {module_name}: {exc}")
                continue
            if ref.id not in source:
                errors.append(f"declared consumer does not reference asset id: {ref.id}: {module_name}")
        return errors

    def resolve(self, asset_id: str) -> AssetRef:
        try:
            return self._assets[asset_id]
        except KeyError as exc:
            raise AssetError(f"unknown asset id: {asset_id}") from exc

    def all(self) -> Iterable[AssetRef]:
        return tuple(self._assets.values())

    def validate(self, verify_hash: bool = True, verify_consumers: bool = True) -> list[str]:
        errors: list[str] = []
        seen_paths: dict[str, str] = {}
        for ref in self._assets.values():
            asset_path = PurePosixPath(ref.path)
            if asset_path.is_absolute() or ".." in asset_path.parts or "\\" in ref.path:
                errors.append(f"unsafe asset path: {ref.id}: {ref.path}")
                continue
            if ref.path in seen_paths:
                errors.append(f"duplicate asset path: {ref.id} and {seen_paths[ref.path]}: {ref.path}")
            else:
                seen_paths[ref.path] = ref.id
            if ref.status not in _ALLOWED_STATUSES:
                errors.append(f"invalid asset status: {ref.id}: {ref.status}")
            if ref.package not in _ALLOWED_PACKAGES:
                errors.append(f"invalid asset package: {ref.id}: {ref.package}")
            if not _is_hex_digest(ref.sha256):
                errors.append(f"invalid sha256: {ref.id}")
            if not _is_hex_digest(ref.source_sha256):
                errors.append(f"invalid source_sha256: {ref.id}")
            if not ref.merge_policy:
                errors.append(f"merge_policy missing: {ref.id}")
            if ref.source.startswith("project-maintained"):
                if ref.source_refs:
                    errors.append(f"project-maintained asset has upstream refs: {ref.id}")
            elif not ref.source_refs:
                errors.append(f"source_refs missing for upstream/merged asset: {ref.id}")
            for index, source_ref in enumerate(ref.source_refs, start=1):
                source_path = source_ref.get("path", "")
                source_hash = source_ref.get("sha256", "")
                if not source_path:
                    errors.append(f"source_refs[{index}] path missing: {ref.id}")
                if not _is_hex_digest(source_hash):
                    errors.append(f"source_refs[{index}] sha256 invalid: {ref.id}")
            if not ref.license_file:
                errors.append(f"license_file missing: {ref.id}")
            if not ref.normalization or not isinstance(ref.normalization_version, int) or ref.normalization_version < 1:
                errors.append(f"invalid normalization metadata: {ref.id}")
            if not ref.canonical_id:
                errors.append(f"canonical_id missing: {ref.id}")
            elif ref.canonical_id not in self._assets:
                errors.append(f"canonical_id does not exist: {ref.id}: {ref.canonical_id}")
            elif ref.copy_of is None and ref.canonical_id != ref.id:
                errors.append(f"canonical asset points elsewhere: {ref.id}: {ref.canonical_id}")
            elif ref.copy_of is not None:
                if ref.copy_of != ref.canonical_id:
                    errors.append(f"copy_of and canonical_id disagree: {ref.id}")
                if ref.status == "active":
                    errors.append(f"copy asset cannot be active: {ref.id}")
                if ref.consumers:
                    errors.append(f"copy asset cannot have independent consumers: {ref.id}")
            if ref.status == "active" and not ref.consumers:
                errors.append(f"active asset has no consumer: {ref.id}")
            if verify_consumers:
                errors.extend(self._consumer_errors(ref))
            try:
                data = ref.read_bytes()
            except AssetError as exc:
                errors.append(str(exc))
                continue
            if not isinstance(ref.size_bytes, int) or ref.size_bytes < 0:
                errors.append(f"size_bytes missing or invalid: {ref.id}")
            elif len(data) != ref.size_bytes:
                errors.append(f"size mismatch: {ref.id} ({len(data)} != {ref.size_bytes})")
            if verify_hash:
                digest = hashlib.sha256(data).hexdigest()
                if digest != ref.sha256:
                    errors.append(f"hash mismatch: {ref.id}")
            try:
                count = len(data.decode(ref.encoding).splitlines())
            except (UnicodeDecodeError, LookupError) as exc:
                errors.append(f"decode failed: {ref.id}: {exc}")
            else:
                if ref.kind in _TEXT_KINDS:
                    if data.startswith(b"\xef\xbb\xbf"):
                        errors.append(f"BOM present: {ref.id}")
                    if b"\r" in data:
                        errors.append(f"non-canonical line ending (CR present): {ref.id}")
                    if not data.endswith(b"\n"):
                        errors.append(f"canonical text must end with LF: {ref.id}")
                if count != ref.raw_line_count:
                    errors.append(f"raw line count mismatch: {ref.id} ({count} != {ref.raw_line_count})")
                try:
                    expected_items = logical_item_count(ref.kind, data.decode(ref.encoding))
                except (ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
                    errors.append(f"item count validation failed: {ref.id}: {exc}")
                else:
                    if expected_items is not None and expected_items != ref.item_count:
                        errors.append(f"item count mismatch: {ref.id} ({expected_items} != {ref.item_count})")
        return errors


class WordlistRegistry:
    def __init__(self, manifest: AssetManifest | None = None) -> None:
        self.manifest = manifest or AssetManifest()

    def lines(self, asset_id: str, *, strip: bool = True, dedupe: bool = True) -> list[str]:
        ref = self.manifest.resolve(asset_id)
        text = ref.read_text()
        values: list[str] = []
        seen: set[str] = set()
        for line in text.splitlines():
            value = line.strip() if strip else line.rstrip("\r\n")
            if not value or value.startswith("#"):
                continue
            if dedupe and value in seen:
                continue
            seen.add(value)
            values.append(value)
        return values

    def status_suffix_filters(self, asset_id: str = "blacklist.status.codes") -> dict[int, tuple[str, ...]]:
        ref = self.manifest.resolve(asset_id)
        try:
            payload = json.loads(ref.read_text())
        except json.JSONDecodeError as exc:
            raise AssetError(f"invalid status suffix filter JSON: {asset_id}: {exc}") from exc
        groups = payload.get("groups")
        if not isinstance(groups, dict):
            raise AssetError(f"status suffix filter asset has no groups object: {asset_id}")
        filters: dict[int, tuple[str, ...]] = {}
        for raw_status, raw_values in groups.items():
            try:
                status = int(raw_status)
            except (TypeError, ValueError) as exc:
                raise AssetError(f"invalid status key in {asset_id}: {raw_status!r}") from exc
            if not isinstance(raw_values, list):
                raise AssetError(f"status suffix filter must be a list: {asset_id}: {raw_status}")
            values = tuple(
                str(value).strip()
                for value in raw_values
                if str(value).strip() and not str(value).strip().startswith("#")
            )
            if values:
                filters[status] = values
        return filters
