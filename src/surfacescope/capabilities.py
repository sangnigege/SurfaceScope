"""Optional capability detection that never installs anything implicitly."""

from __future__ import annotations

import shutil
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Capability:
    name: str
    available: bool
    detail: str


class CapabilityRegistry:
    def __init__(self) -> None:
        self._items: dict[str, Capability] = {}

    def detect(self) -> CapabilityRegistry:
        for name in ("deno", "node", "libreoffice", "soffice"):
            path = shutil.which(name)
            self._items[name] = Capability(name, bool(path), path or "not found")
        self._items["word_pdf"] = Capability(
            "word_pdf",
            any(self._items[name].available for name in ("libreoffice", "soffice")),
            "requires LibreOffice/Word conversion; HTML/JSON reports remain available",
        )
        return self

    def get(self, name: str) -> Capability:
        return self._items.get(name, Capability(name, False, "not detected"))

    def to_dict(self) -> dict[str, dict[str, object]]:
        return {name: {"available": item.available, "detail": item.detail} for name, item in self._items.items()}
