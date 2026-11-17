"""Adapter protocol."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from ..context import ScanContext
from ..models import ComponentResult, Finding, Target


class ComponentAdapter(ABC):
    name = "component"

    @abstractmethod
    def scan(self, context: ScanContext, targets: list[Target], options: dict) -> ComponentResult:
        raise NotImplementedError


def merge_finding_provenance(existing: Finding, incoming: Finding) -> None:
    """Merge duplicate observations without discarding where they came from.

    Endpoint-like findings deliberately use a ``dedupe_key`` that excludes the
    source target identity. The same URL observed from two seeds is one result,
    but every source remains visible under ``metadata.provenance``.
    """

    provenance = existing.metadata.get("provenance")
    if not isinstance(provenance, list):
        provenance = []
        existing.metadata["provenance"] = provenance
    for finding in (existing, incoming):
        entry = {
            key: value
            for key, value in {
                "source": finding.metadata.get("source") or finding.source_target,
                "source_target": finding.metadata.get("source_target") or finding.source_target,
                "source_asset": finding.metadata.get("source_asset"),
            }.items()
            if value
        }
        if entry and entry not in provenance:
            provenance.append(entry)
    existing.metadata["occurrences"] = max(
        int(existing.metadata.get("occurrences") or 1),
        len(provenance),
    )
    if incoming.confidence > existing.confidence:
        existing.confidence = incoming.confidence
        existing.technique = incoming.technique or existing.technique
        existing.evidence = incoming.evidence or existing.evidence
        existing.request_summary = incoming.request_summary or existing.request_summary
        existing.response_summary = incoming.response_summary or existing.response_summary
        existing.request_id = incoming.request_id or existing.request_id
        existing.method = incoming.method or existing.method


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse duplicates that opted into an explicit semantic ``dedupe_key``."""

    merged: list[Finding] = []
    indexes: dict[str, int] = {}
    for finding in findings:
        if not finding.dedupe_key:
            merged.append(finding)
            continue
        key = finding.semantic_key
        index = indexes.get(key)
        if index is None:
            indexes[key] = len(merged)
            merged.append(finding)
            continue
        merge_finding_provenance(merged[index], finding)
    return merged


__all__ = ["ComponentAdapter", "dedupe_findings", "merge_finding_provenance"]
