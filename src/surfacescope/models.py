"""Shared data models used by every component and report."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .urls import canonical_url, origin

_UNSUPPORTED_FRAMING_HEADERS = frozenset({"content-length", "transfer-encoding"})


def validate_request_headers(headers: Mapping[str, str]) -> None:
    """Reject header shapes the unified HTTP transport cannot represent safely."""

    seen: set[str] = set()
    for raw_name, raw_value in headers.items():
        name = str(raw_name)
        value = str(raw_value)
        normalized = name.strip().lower()
        if not normalized:
            raise ValueError("request header name must not be empty")
        if any(character in name + value for character in ("\r", "\n")):
            raise ValueError("request headers must not contain CR/LF")
        if normalized in seen:
            raise ValueError(f"duplicate request header (case-insensitive): {name}")
        if normalized in _UNSUPPORTED_FRAMING_HEADERS:
            raise ValueError(f"request framing header is not supported: {name}")
        seen.add(normalized)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Target:
    url: str
    target_id: str = ""
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None
    scope: str | None = None

    @property
    def origin(self) -> str:
        return origin(self.url)

    @property
    def auth_scope(self) -> str:
        return self.scope or self.origin

    @property
    def identity(self) -> str:
        if self.target_id:
            return self.target_id
        material = json.dumps(
            {
                "url": self.url,
                "scope": self.scope,
                "headers": self.headers,
                "cookies": self.cookies,
                "proxy": self.proxy,
            },
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )
        return "target-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


@dataclass(slots=True)
class RequestSpec:
    url: str
    target_id: str = ""
    profile_id: str = ""
    attack: bool = False
    dedupe_key: str | None = None
    budget_scope: str = "default"
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, Any] | None = None
    data: Any = None
    json: Any = None
    cookies: dict[str, str] = field(default_factory=dict)
    auth_scope: str = ""
    auth_origin: str = ""
    purpose: str = "navigation"
    cache_policy: str = "default"
    side_effect_free: bool = True
    timeout: float | None = None
    allow_redirects: bool | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass(slots=True)
class ResponseSnapshot:
    request_id: str
    url: str
    final_url: str
    method: str
    status: int
    headers: dict[str, str]
    body: bytes
    text: str
    elapsed: float
    history: list[str] = field(default_factory=list)
    truncated: bool = False
    from_cache: bool = False
    request_headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    target_id: str = ""
    auth_scope: str = ""

    @property
    def content_type(self) -> str:
        return self.header("content-type").split(";", 1)[0].strip().lower()

    def header(self, name: str, default: str = "") -> str:
        wanted = str(name).lower()
        for key, value in self.headers.items():
            if str(key).lower() == wanted:
                return str(value)
        return default

    @property
    def length(self) -> int:
        return len(self.body)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("body", None)
        payload["body_sha256"] = hashlib.sha256(self.body).hexdigest()
        payload["request_headers"] = _redact_headers(self.request_headers)
        payload["headers"] = _redact_headers(self.headers)
        return payload


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    sensitive = {"authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key", "api-key"}
    return {
        str(key): "<redacted>" if str(key).lower() in sensitive else str(value)
        for key, value in headers.items()
    }


@dataclass(slots=True)
class Finding:
    module: str
    kind: str
    target: str
    method: str = "GET"
    severity: str = "info"
    confidence: float = 0.5
    technique: str = ""
    evidence: str = ""
    request_summary: dict[str, Any] = field(default_factory=dict)
    response_summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now)
    source_target: str = ""
    dedupe_key: str = ""
    request_id: str = ""
    target_id: str = ""
    auth_scope: str = ""

    def __post_init__(self) -> None:
        # Keep identity fields populated for callers that still construct
        # findings with the historical metadata-only convention.
        if not self.target_id:
            self.target_id = str(
                self.metadata.get("target_id")
                or self.request_summary.get("target_id")
                or ""
            )
        if not self.auth_scope:
            self.auth_scope = str(
                self.metadata.get("auth_scope")
                or self.metadata.get("scope")
                or self.request_summary.get("scope")
                or ""
            )

    @property
    def semantic_key(self) -> str:
        """Stable identity used by the in-memory store and reports."""

        if self.dedupe_key:
            return self.dedupe_key
        request = self.request_summary or {}
        method = str(request.get("method") or self.method or "GET").upper()
        scope = self.auth_scope
        evidence = hashlib.sha256(str(self.evidence).encode("utf-8")).hexdigest()
        return "|".join(
            (
                str(self.module),
                str(self.kind),
                canonical_url(str(self.target)),
                method,
                self.target_id,
                scope,
                evidence,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ComponentResult:
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)

    def merge(self, other: ComponentResult) -> ComponentResult:
        self.findings.extend(other.findings)
        self.errors.extend(other.errors)
        self.artifacts.extend(other.artifacts)
        for key, value in other.stats.items():
            if isinstance(value, (int, float)) and isinstance(self.stats.get(key), (int, float)):
                self.stats[key] += value
            else:
                self.stats[key] = value
        return self

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "stats": self.stats,
            "errors": self.errors,
            "artifacts": self.artifacts,
            "ok": self.ok,
        }


@dataclass(frozen=True, slots=True)
class EndpointCandidate:
    """Source-bound endpoint discovered by one component."""

    url: str
    source_component: str
    source_target: str
    kind: str = "endpoint"
    method: str = "GET"
    confidence: float = 0.5
    auth_scope: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def canonical_url(self) -> str:
        return canonical_url(self.url)

    @property
    def dedupe_key(self) -> str:
        return "|".join((self.source_component, self.method.upper(), self.canonical_url, self.auth_scope))
