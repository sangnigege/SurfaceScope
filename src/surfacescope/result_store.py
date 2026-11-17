"""Thread-safe result collection."""

from __future__ import annotations

import threading
from collections.abc import Iterable
from urllib.parse import urlsplit, urlunsplit

from .models import Finding, ResponseSnapshot


class ResultStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._findings: list[Finding] = []
        self._finding_keys: set[str] = set()
        self._snapshots: dict[tuple[str, str, str, str], ResponseSnapshot] = {}
        self._snapshot_urls: dict[str, set[tuple[str, str, str, str]]] = {}

    def add_findings(self, findings: Iterable[Finding]) -> None:
        with self._lock:
            for finding in findings:
                key = finding.semantic_key
                if key in self._finding_keys:
                    continue
                self._finding_keys.add(key)
                self._findings.append(finding)

    def add_snapshot(self, snapshot: ResponseSnapshot) -> None:
        with self._lock:
            method = (snapshot.method or "GET").upper()
            for url in (snapshot.url, snapshot.final_url):
                for alias in {url, _canonical_url(url)}:
                    key = (snapshot.target_id, snapshot.auth_scope, method, alias)
                    self._snapshots[key] = snapshot
                    self._snapshot_urls.setdefault(alias, set()).add(key)

    def get_snapshot(
        self,
        url: str,
        *,
        target_id: str | None = None,
        auth_scope: str | None = None,
        method: str | None = None,
    ) -> ResponseSnapshot | None:
        """Return a snapshot only when its target/auth/method scope is unambiguous."""

        with self._lock:
            keys: set[tuple[str, str, str, str]] = set()
            for alias in {url, _canonical_url(url)}:
                keys.update(self._snapshot_urls.get(alias, ()))
            method_filter = method.upper() if method else None
            matches = [
                self._snapshots[key]
                for key in keys
                if (target_id is None or key[0] == target_id)
                and (auth_scope is None or key[1] == auth_scope)
                and (method_filter is None or key[2] == method_filter)
            ]
            unique = {id(snapshot): snapshot for snapshot in matches}
            if len(unique) == 1:
                return next(iter(unique.values()))
            return None

    def findings(self) -> list[Finding]:
        with self._lock:
            return list(self._findings)

    def snapshots(self) -> dict[str, ResponseSnapshot]:
        with self._lock:
            return {
                f"{target_id}|{auth_scope}|{method}|{url}": snapshot
                for (target_id, auth_scope, method, url), snapshot in self._snapshots.items()
            }

    def summary(self) -> dict[str, int]:
        with self._lock:
            return {
                "findings": len(self._findings),
                "snapshots": len({id(snapshot) for snapshot in self._snapshots.values()}),
            }


def _canonical_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))
