"""Pure-Python Finger fingerprinting without EHole binaries or subprocesses."""

from __future__ import annotations

import json
from urllib.parse import urljoin

from ..components.finger import FingerMatcher, favicon_hashes, favicon_href
from ..context import ScanContext
from ..models import ComponentResult, Finding, Target
from ..urls import canonical_url, host_allowed
from .base import ComponentAdapter


class FingerAdapter(ComponentAdapter):
    name = "finger"

    def __init__(self) -> None:
        self._rules: list[dict] | None = None

    def _load_rules(self, context: ScanContext) -> list[dict]:
        if self._rules is None:
            ref = context.manifest.resolve("fingerprint.finger.rules")
            payload = json.loads(ref.read_text())
            rules = payload.get("fingerprint", [])
            if not isinstance(rules, list):
                raise ValueError("fingerprint rules must contain a fingerprint list")
            self._rules = rules
        return self._rules

    def scan(self, context: ScanContext, targets: list[Target], options: dict) -> ComponentResult:
        result = ComponentResult()
        settings = context.config.section("finger")
        max_endpoints = max(1, int(options.get("max_endpoints") or settings.get("max_endpoints", 100)))
        scan_discovered = bool(options.get("scan_discovered", settings.get("scan_discovered", True)))
        rules = self._load_rules(context)
        matcher = FingerMatcher(rules)
        result.stats.update({"rules": matcher.rule_count, "targets": len(targets)})

        jobs: list[tuple[Target, str, str]] = []
        seen_pages: set[tuple[str, str]] = set()
        for target in targets:
            jobs.append((target, target.url, target.url))
            seen_pages.add((target.identity, canonical_url(target.url)))
        if scan_discovered:
            for finding in context.results.findings():
                if finding.module == self.name:
                    continue
                if finding.kind not in {"path", "endpoint", "packer_endpoint", "swagger_endpoint"}:
                    continue
                candidates = [
                    target
                    for target in targets
                    if host_allowed(target.url, finding.target)
                ]
                finding_scope = str(finding.auth_scope or finding.metadata.get("auth_scope") or "")
                scoped = [target for target in candidates if target.auth_scope == finding_scope]
                if len(scoped) == 1:
                    base = scoped[0]
                elif len({target.auth_scope for target in candidates}) == 1 and candidates:
                    base = candidates[0]
                else:
                    base = None
                if base is None or not host_allowed(base.url, finding.target):
                    continue
                key = (base.identity, canonical_url(finding.target))
                if key in seen_pages:
                    continue
                seen_pages.add(key)
                jobs.append((base, finding.target, finding.metadata.get("source_target", base.url)))
                if len(jobs) >= max_endpoints + len(targets):
                    break

        pages_probed = skipped_unusable_pages = favicon_requests = matches = 0
        favicon_cache: dict[tuple[str, str], set[str]] = {}
        fingerprints: dict[tuple[str, str], Finding] = {}
        for target, page_url, _source in jobs:
            page = context.results.get_snapshot(
                page_url,
                target_id=target.identity,
                auth_scope=target.auth_scope,
                method="GET",
            )
            if page is None:
                try:
                    page = context.executor.get(
                        page_url,
                        target_id=target.identity,
                        profile_id=context.profile.id,
                        purpose="navigation",
                        headers=target.headers,
                        cookies=target.cookies,
                        auth_scope=target.auth_scope,
                        auth_origin=target.origin,
                        metadata={"direct_navigation": True},
                    )
                except Exception as exc:
                    result.errors.append(f"fingerprint page failed {page_url}: {exc}")
                    continue
                context.results.add_snapshot(page)
            pages_probed += 1
            if page.error or page.status <= 0 or page.status == 404 or page.status >= 500:
                skipped_unusable_pages += 1
                continue

            favicon_key = (target.identity, page.final_url)
            hash_values = favicon_cache.get(favicon_key)
            if hash_values is None:
                hash_values = set()
                icon_url = favicon_href(page.text)
                icon_url = urljoin(page.final_url, icon_url or "/favicon.ico")
                if host_allowed(target.url, icon_url):
                    try:
                        favicon = context.executor.get(
                            icon_url,
                            target_id=target.identity,
                            profile_id=context.profile.id,
                            purpose="asset",
                            headers=target.headers,
                            cookies=target.cookies,
                            auth_scope=target.auth_scope,
                            auth_origin=target.origin,
                            metadata={"resource_type": "image", "referer": page.final_url},
                        )
                        context.results.add_snapshot(favicon)
                        favicon_requests += 1
                        if favicon.status < 400 and favicon.body:
                            hash_values = set(favicon_hashes(favicon.body).values())
                    except Exception as exc:
                        result.errors.append(f"favicon failed for {page.final_url}: {exc}")
                favicon_cache[favicon_key] = hash_values

            page_matches = matcher.match(
                url=page.final_url,
                text=page.text,
                headers=page.headers,
                favicon_hash_values=hash_values,
            )
            matches += len(page_matches)
            best_by_cms: dict[str, object] = {}
            for match in page_matches:
                current = best_by_cms.get(match.cms)
                if current is None or match.confidence > current.confidence:
                    best_by_cms[match.cms] = match
            for cms, match in sorted(best_by_cms.items()):
                evidence_parts = [f"location={match.location}", f"method={match.method}"]
                if match.evidence:
                    evidence_parts.append("keywords=" + ",".join(match.evidence))
                if match.version:
                    evidence_parts.append(f"version={match.version}")
                if match.model:
                    evidence_parts.append(f"model={match.model}")
                finding = Finding(
                    module=self.name,
                    kind="fingerprint",
                    target=target.url,
                    target_id=target.identity,
                    auth_scope=target.auth_scope,
                    severity="info",
                    confidence=round(match.confidence, 3),
                    technique=f"finger-{match.method}",
                    evidence="; ".join(evidence_parts),
                    response_summary={"status": page.status, "length": page.length},
                    metadata={
                        "cms": cms,
                        "version": match.version,
                        "model": match.model,
                        "location": match.location,
                        "method": match.method,
                        "evidence": list(match.evidence),
                        "source": page.final_url,
                        "sources": [page.final_url],
                        "auth_scope": target.auth_scope,
                    },
                    source_target=target.url,
                )
                key = (target.auth_scope, cms)
                existing = fingerprints.get(key)
                if existing is None:
                    fingerprints[key] = finding
                    continue
                sources = existing.metadata.setdefault("sources", [])
                if page.final_url not in sources:
                    sources.append(page.final_url)
                if finding.confidence > existing.confidence:
                    finding.metadata["sources"] = sources
                    fingerprints[key] = finding
                else:
                    existing.metadata["sources"] = sources

        for key in sorted(fingerprints):
            finding = fingerprints[key]
            sources = finding.metadata.get("sources")
            if isinstance(sources, list):
                finding.metadata["occurrences"] = len(sources)
            result.findings.append(finding)

        result.stats.update(
            {
                "pages_probed": pages_probed,
                "skipped_unusable_pages": skipped_unusable_pages,
                "favicon_requests": favicon_requests,
                "matches": matches,
                "findings": len(result.findings),
            }
        )
        return result
