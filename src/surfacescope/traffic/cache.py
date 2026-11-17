"""Bounded, thread-safe response cache."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from ..models import ResponseSnapshot


@dataclass
class _CacheEntry:
    snapshot: ResponseSnapshot
    expires_at: float


class ResponseCache:
    def __init__(self, max_entries: int = 2048, ttl: float = 300.0) -> None:
        self.max_entries = max(1, int(max_entries))
        self.ttl = max(0.0, float(ttl))
        self._lock = threading.RLock()
        self._items: OrderedDict[str, _CacheEntry] = OrderedDict()

    def get(self, key: str) -> ResponseSnapshot | None:
        now = time.monotonic()
        with self._lock:
            entry = self._items.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                self._items.pop(key, None)
                return None
            self._items.move_to_end(key)
            return entry.snapshot

    def put(self, key: str, snapshot: ResponseSnapshot) -> None:
        if self.ttl <= 0:
            return
        with self._lock:
            self._items[key] = _CacheEntry(snapshot, time.monotonic() + self.ttl)
            self._items.move_to_end(key)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)
