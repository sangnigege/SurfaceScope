"""Per-run artifact storage with no CWD side effects."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from .tempdirs import make_temp_dir

_SAFE_RUN_ID = re.compile(r"[^A-Za-z0-9_.-]+")


class ArtifactStore:
    def __init__(self, root: str | Path | None = None, run_id: str | None = None) -> None:
        self._temporary = root is None
        self.root = Path(root) if root else make_temp_dir(exclude=(Path.cwd(),))
        self.run_id = _SAFE_RUN_ID.sub("-", run_id or "run")
        self.run_dir = self.root / self.run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._paths: list[str] = []

    def path(self, *parts: str) -> Path:
        target = self.run_dir.joinpath(*parts).resolve()
        run_root = self.run_dir.resolve()
        if target != run_root and run_root not in target.parents:
            raise ValueError(f"artifact path escapes run directory: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        self._paths.append(str(target))
        return target

    def write_text(self, name: str, text: str, encoding: str = "utf-8") -> Path:
        target = self.path(name)
        target.write_text(text, encoding=encoding, newline="\n")
        return target

    def write_bytes(self, name: str, data: bytes) -> Path:
        target = self.path(name)
        target.write_bytes(data)
        return target

    def write_json(self, name: str, payload: Any) -> Path:
        return self.write_text(name, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

    @property
    def artifacts(self) -> list[str]:
        return list(self._paths)

    def cleanup(self) -> None:
        if not self._temporary:
            return
        shutil.rmtree(self.root, ignore_errors=True)
