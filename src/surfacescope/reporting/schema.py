"""Versioned, deterministic report schema."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..models import ComponentResult, Finding

SCHEMA_VERSION = 1

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


def _canonical_url(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if not parts.scheme and not parts.netloc:
        return value
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)


def _severity_rank(value: str) -> int:
    return _SEVERITY_ORDER.get(str(value).strip().lower(), _SEVERITY_ORDER["unknown"])


def _finding_identity(finding: Finding) -> tuple[str, ...]:
    request = finding.request_summary or {}
    method = str(request.get("method") or finding.method or "GET").upper()
    scope = str(
        finding.auth_scope
        or request.get("scope")
        or finding.metadata.get("scope")
        or ""
    )
    evidence_digest = hashlib.sha256(str(finding.evidence).encode("utf-8")).hexdigest()
    return (
        str(finding.module),
        str(finding.kind),
        _canonical_url(str(finding.target)),
        method,
        str(finding.target_id),
        scope,
        evidence_digest,
    )


def _preferred(finding: Finding) -> tuple[int, float, str, str]:
    return (
        _severity_rank(finding.severity),
        -float(finding.confidence),
        str(finding.timestamp),
        _stable_json(finding.metadata),
    )


def _sort_key(finding: Finding) -> tuple[int, float, str, str, str, str, str]:
    return (
        _severity_rank(finding.severity),
        -float(finding.confidence),
        str(finding.module),
        str(finding.kind),
        _canonical_url(str(finding.target)),
        str(finding.timestamp),
        _stable_json(finding.metadata),
    )


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Keep one strongest record per semantic identity, never per text length."""

    groups: dict[tuple[str, ...], list[Finding]] = {}
    for finding in findings:
        groups.setdefault(_finding_identity(finding), []).append(finding)

    result: list[Finding] = []
    for identity in sorted(groups):
        candidates = sorted(groups[identity], key=_preferred)
        selected = candidates[0]
        if len(candidates) > 1:
            count = sum(int(item.metadata.get("duplicate_count", 1)) for item in candidates)
            metadata = dict(selected.metadata)
            metadata["duplicate_count"] = count
            selected = replace(selected, metadata=metadata)
        result.append(selected)
    return sorted(result, key=_sort_key)


def build_report(run_id: str, results: ComponentResult, run_meta: dict[str, Any]) -> dict[str, Any]:
    findings = deduplicate_findings(results.findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": run_meta.get("generated_at"),
        "meta": run_meta,
        "summary": {
            "findings": len(findings),
            "errors": len(results.errors),
            "components": dict(results.stats),
        },
        "findings": [finding.to_dict() for finding in findings],
        "errors": sorted(str(error) for error in results.errors),
        "artifacts": sorted(str(artifact) for artifact in results.artifacts),
    }
