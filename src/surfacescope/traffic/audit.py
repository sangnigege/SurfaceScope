"""Request audit counters used by budgets and reports."""

from __future__ import annotations

import threading
from collections import Counter
from datetime import datetime, timezone
from typing import Any


class RequestAudit:
    def __init__(self, max_events: int = 10000) -> None:
        self._lock = threading.RLock()
        self._counts: Counter[str] = Counter()
        self._events: list[dict[str, Any]] = []
        self._max_events = max(100, int(max_events))

    def increment(self, key: str, amount: int = 1) -> None:
        with self._lock:
            self._counts[key] += amount

    def record(self, **event: Any) -> None:
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        with self._lock:
            self._events.append(event)
            if len(self._events) > self._max_events:
                del self._events[: len(self._events) - self._max_events]

    def counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)

    def summary(self) -> dict[str, Any]:
        return {"counts": self.counts(), "last_events": self.events()[-20:]}
