#!/usr/bin/env python3
"""Normalize manifest-declared text assets to canonical LF bytes and refresh metadata."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from surfacescope.assets import logical_item_count  # noqa: E402

ASSET_ROOT = SRC / "surfacescope"
MANIFEST_PATH = ASSET_ROOT / "assets" / "manifest.json"


def _canonical_text(raw: bytes, encoding: str, normalization: str, kind: str) -> bytes:
    text = raw.decode(encoding)
    if text.startswith("\ufeff"):
        text = text[1:]
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    operations = {item.strip() for item in normalization.split(",") if item.strip()}
    line_oriented = kind.startswith("wordlist.")
    if line_oriented and ("strip-empty" in operations or any(item.startswith("dedupe") for item in operations)):
        lines = text.splitlines()
        if "strip-empty" in operations:
            lines = [line for line in lines if line.strip()]
        if any(item.startswith("dedupe") for item in operations):
            seen: set[str] = set()
            lines = [line for line in lines if not (line in seen or seen.add(line))]
        text = "\n".join(lines)
    if not text.endswith("\n"):
        text += "\n"
    return text.encode(encoding)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.replace(temporary, path)
    finally:
        temporary_path = Path(temporary)
        if temporary_path.exists():
            temporary_path.unlink()


def _asset_path(relative_path: str) -> Path:
    root = ASSET_ROOT.resolve()
    path = (ASSET_ROOT / relative_path).resolve()
    if not path.is_relative_to(root):
        raise SystemExit(f"asset path escapes package root: {relative_path}")
    return path


def main() -> int:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 3:
        raise SystemExit("normalize_assets requires schema_version 3")
    changed: list[str] = []
    for item in manifest.get("assets", []):
        encoding = str(item.get("encoding", "utf-8"))
        if not encoding:
            continue
        path = _asset_path(str(item["path"]))
        raw = path.read_bytes()
        try:
            normalized = _canonical_text(
                raw,
                encoding,
                str(item.get("normalization", "")),
                str(item.get("kind", "")),
            )
        except UnicodeDecodeError as exc:
            raise SystemExit(f"cannot normalize {item['id']}: {exc}") from exc
        if normalized != raw:
            _atomic_write(path, normalized)
            changed.append(str(item["id"]))
        text = normalized.decode(encoding)
        item["source_sha256"] = item.get("source_sha256") or hashlib.sha256(raw).hexdigest()
        item["sha256"] = hashlib.sha256(normalized).hexdigest()
        item["size_bytes"] = len(normalized)
        item["raw_line_count"] = len(text.splitlines())
        item_count = logical_item_count(str(item["kind"]), text)
        if item_count is None:
            raise SystemExit(f"cannot compute item_count for {item['id']}")
        item["item_count"] = item_count
    _atomic_write(
        MANIFEST_PATH,
        (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    if changed:
        print("normalized:", ", ".join(changed))
    else:
        print("normalized: no byte changes")
    print(f"manifest updated: {MANIFEST_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
