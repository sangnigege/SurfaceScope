"""Passive attack-surface classification for Packer-discovered endpoints."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .analyzer import Endpoint

_UPLOAD_PATH = re.compile(
    r"(?i)(?:^|/)(?:upload|uploads|file|files|attachment|attachments|import|media)(?:/|$)|"
    r"(?:upload|attach|multipart)"
)
_UPLOAD_METHOD = re.compile(r"(?i)multipart/form-data|filename=|FormData")
_AUTH_PATH = re.compile(
    r"(?i)(?:^|/)(?:login|signin|sign-in|auth|oauth|token|session|password|register|sso)(?:/|$)"
)
_SENSITIVE_PATH = re.compile(
    r"(?i)(?:^|/)(?:admin|internal|manage|management|debug|export|download|backup|config|"
    r"actuator|swagger|api-docs|users?|tenants?)(?:/|$)"
)


@dataclass(frozen=True, slots=True)
class SurfaceCandidate:
    endpoint: Endpoint
    category: str
    confidence: float
    reason: str


def classify_surface(endpoints: list[Endpoint], *, limit: int = 200) -> list[SurfaceCandidate]:
    """Classify likely upload, authentication and sensitive endpoints without traffic."""

    result: list[SurfaceCandidate] = []
    seen: set[tuple[str, str, str]] = set()
    for endpoint in endpoints[: max(0, limit)]:
        path = urlsplit(endpoint.url).path or "/"
        candidate: SurfaceCandidate | None = None
        if _UPLOAD_PATH.search(path):
            confidence = 0.72 if endpoint.method.upper() in {"POST", "PUT", "PATCH"} else 0.58
            candidate = SurfaceCandidate(endpoint, "upload", confidence, "upload-like path")
        elif _AUTH_PATH.search(path):
            candidate = SurfaceCandidate(endpoint, "authentication", 0.67, "authentication-like path")
        elif _SENSITIVE_PATH.search(path):
            candidate = SurfaceCandidate(endpoint, "sensitive", 0.55, "sensitive-looking path")
        if candidate is None:
            continue
        key = (candidate.category, endpoint.method.upper(), endpoint.url)
        if key not in seen:
            seen.add(key)
            result.append(candidate)
    return result


def upload_markers(text: str) -> bool:
    """Return whether a source or response exposes multipart upload semantics."""

    return bool(_UPLOAD_METHOD.search(text or ""))


__all__ = ["SurfaceCandidate", "classify_surface", "upload_markers"]
