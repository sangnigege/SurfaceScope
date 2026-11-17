"""Adapter for browserless JavaScript and endpoint discovery."""

from __future__ import annotations

from urllib.parse import urlsplit

from ..components.jsfinder import base_href, extract_script_urls, extract_urls
from ..context import ScanContext
from ..models import ComponentResult, Finding, Target
from ..urls import canonical_url
from .base import ComponentAdapter, dedupe_findings

# Kept as a compatibility import for the existing public test surface.
_extract_urls = extract_urls


class JSFinderAdapter(ComponentAdapter):
    name = "jsfinder"

    def scan(self, context: ScanContext, targets: list[Target], options: dict) -> ComponentResult:
        result = ComponentResult()
        max_assets = int(options.get("max_assets", 80))
        for target in targets:
            base = target.url
            page = context.results.get_snapshot(
                base,
                target_id=target.identity,
                auth_scope=target.auth_scope,
                method="GET",
            )
            if page is None:
                page = context.executor.get(
                    base,
                    target_id=target.identity,
                    profile_id=context.profile.id,
                    purpose="navigation",
                    headers=target.headers,
                    cookies=target.cookies,
                    auth_scope=target.auth_scope,
                    auth_origin=target.origin,
                    metadata={"direct_navigation": True},
                )
                context.results.add_snapshot(page)
            if page.error:
                result.errors.append(f"page failed: {base}: {page.error}")
                continue
            scripts = [(page.final_url, page.text)]
            script_urls = extract_script_urls(page.text, page.final_url, base)
            script_assets = {canonical_url(url) for url in script_urls}
            page_base = base_href(page.text, page.final_url)
            discovered: set[str] = set()
            discovered.update(extract_urls(page.text, page.final_url, base, page_base))
            seen_script_findings: set[str] = set()
            for script_url in list(dict.fromkeys(script_urls))[:max_assets]:
                try:
                    asset = context.executor.get(
                        script_url,
                        target_id=target.identity,
                        profile_id=context.profile.id,
                        purpose="asset",
                        headers=target.headers,
                        cookies=target.cookies,
                        auth_scope=target.auth_scope,
                        auth_origin=target.origin,
                        metadata={"resource_type": "script", "referer": page.final_url},
                    )
                except Exception as exc:
                    result.errors.append(f"asset failed: {script_url}: {exc}")
                    continue
                context.results.add_snapshot(asset)
                if script_url not in seen_script_findings:
                    seen_script_findings.add(script_url)
                    result.findings.append(Finding(
                        module=self.name,
                        kind="js_asset",
                        target=script_url,
                        dedupe_key=(
                            f"{self.name}|asset|{target.auth_scope}|"
                            f"{canonical_url(script_url)}|GET"
                        ),
                        target_id=target.identity,
                        auth_scope=target.auth_scope,
                        method="GET",
                        confidence=0.9,
                        technique="script-src",
                        evidence=f"status={asset.status}; length={asset.length}",
                        response_summary={"status": asset.status, "length": asset.length},
                        metadata={
                            "source": page.final_url,
                            "resource_type": "script",
                            "status": asset.status,
                            "source_target": target.url,
                            "auth_scope": target.auth_scope,
                        },
                        source_target=target.url,
                        request_id=asset.request_id,
                    ))
                scripts.append((asset.final_url, asset.text))
            for source_url, script in scripts:
                discovered.update(extract_urls(script, source_url, base, page_base))
            for url in sorted(discovered):
                if canonical_url(url) == canonical_url(base):
                    continue
                if canonical_url(url) in script_assets:
                    continue
                result.findings.append(Finding(
                    module=self.name,
                    kind="endpoint",
                    target=url,
                    dedupe_key=(
                        f"{self.name}|endpoint|{target.auth_scope}|"
                        f"{canonical_url(url)}|GET"
                    ),
                    target_id=target.identity,
                    auth_scope=target.auth_scope,
                    method="GET",
                    confidence=0.55,
                    technique="static-extraction",
                    evidence="URL found in HTML/JavaScript",
                    metadata={
                        "source": page.final_url,
                        "scope": urlsplit(url).hostname,
                        "source_target": target.url,
                        "auth_scope": target.auth_scope,
                        "status": 0,
                    },
                    source_target=target.url,
                ))
        result.findings = dedupe_findings(result.findings)
        result.stats.update(
            {
                "targets": len(targets),
                "findings": len(result.findings),
                "assets": sum(1 for finding in result.findings if finding.kind == "js_asset"),
                "endpoints": sum(1 for finding in result.findings if finding.kind == "endpoint"),
            }
        )
        return result
