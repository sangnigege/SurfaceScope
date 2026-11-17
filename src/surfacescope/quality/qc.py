"""Deterministic QC without rereading report files."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from difflib import SequenceMatcher
from urllib.parse import urlsplit

from ..models import ResponseSnapshot


@dataclass(frozen=True, slots=True)
class QCDecision:
    accepted: bool
    reason: str
    confidence: float = 0.0


def _fingerprint(snapshot: ResponseSnapshot) -> str:
    normalized = " ".join(snapshot.text.split()).lower()
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()


def _similarity(left: ResponseSnapshot, right: ResponseSnapshot) -> float:
    if not left.text or not right.text:
        return 1.0 if left.status == right.status and left.length == right.length else 0.0
    return SequenceMatcher(None, left.text[:20000], right.text[:20000], autojunk=False).ratio()


class QualityController:
    def __init__(
        self,
        default_include_statuses: set[int] | None = None,
        status_suffix_filters: Mapping[int, Iterable[str]] | None = None,
    ) -> None:
        self.default_include_statuses = default_include_statuses or {200, 204, 301, 302, 307, 308, 401, 403}
        self.status_suffix_filters = {
            int(status): tuple(str(suffix) for suffix in suffixes if str(suffix).strip())
            for status, suffixes in (status_suffix_filters or {}).items()
        }

    def _status_suffix_excluded(self, candidate: ResponseSnapshot) -> bool:
        suffixes = self.status_suffix_filters.get(candidate.status, ())
        if not suffixes:
            return False
        path = urlsplit(candidate.final_url).path
        for suffix in suffixes:
            normalized = suffix[1:] if suffix.startswith("/") else suffix
            if normalized and path.endswith(normalized):
                return True
        return False

    def is_soft_404(self, candidate: ResponseSnapshot, baseline: ResponseSnapshot | None) -> bool:
        if baseline is None:
            return False
        if candidate.status == 404 and baseline.status == 404:
            return True
        if candidate.status == baseline.status and candidate.length == baseline.length:
            return True
        return candidate.status == baseline.status and _similarity(candidate, baseline) >= 0.98

    def discovery(self, candidate: ResponseSnapshot, baseline: ResponseSnapshot | None, include_statuses: set[int] | None = None) -> QCDecision:
        allowed = include_statuses or self.default_include_statuses
        if candidate.status not in allowed:
            return QCDecision(False, f"status {candidate.status} excluded")
        if self._status_suffix_excluded(candidate):
            return QCDecision(False, f"status {candidate.status} suffix filter excluded")
        if self.is_soft_404(candidate, baseline):
            return QCDecision(False, "soft-404 or equivalent response")
        confidence = 0.9 if candidate.status in (200, 204) else 0.65
        return QCDecision(True, "status accepted", confidence)

    def bypass(self, baseline: ResponseSnapshot, candidate: ResponseSnapshot) -> QCDecision:
        if candidate.error:
            return QCDecision(False, f"request error: {candidate.error}")
        if candidate.status in (404, 429):
            return QCDecision(False, f"non-bypass status {candidate.status}")
        if candidate.status == 403:
            return QCDecision(False, "still forbidden")
        if candidate.status == baseline.status and _fingerprint(candidate) == _fingerprint(baseline):
            return QCDecision(False, "identical response")
        if self.is_soft_404(candidate, baseline):
            return QCDecision(False, "soft-404 after mutation")
        if 200 <= candidate.status < 300:
            return QCDecision(True, "successful status after mutation", 0.85)
        if 300 <= candidate.status < 400:
            return QCDecision(
                False,
                "redirect is not direct access evidence; it commonly targets a login page",
            )
        return QCDecision(False, f"non-success status {candidate.status}")
