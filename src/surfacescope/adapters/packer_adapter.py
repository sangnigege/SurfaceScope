"""Packer adapter: passive webpack analysis first, safe probing opt-in."""

from __future__ import annotations

import json
from collections import deque

from ..components.packer import (
    CORS_PROBE_ORIGIN,
    Endpoint,
    analyse_document,
    classify_surface,
    evaluate_cors,
    evaluate_unauthorized,
    extract_endpoints,
    extract_scripts,
    find_secrets,
    looks_like_sql_error,
    source_map_urls,
    sql_probe_urls,
    upload_markers,
)
from ..context import ScanContext
from ..errors import BudgetExceeded, CancelledError
from ..models import ComponentResult, Finding, RequestSpec, ResponseSnapshot, Target
from ..urls import canonical_url, host_allowed
from .base import ComponentAdapter, dedupe_findings, merge_finding_provenance


class PackerAdapter(ComponentAdapter):
    name = "packer"

    def scan(self, context: ScanContext, targets: list[Target], options: dict) -> ComponentResult:
        result = ComponentResult()
        settings = context.config.section("packer")
        max_assets = max(1, int(options.get("max_assets") or settings.get("max_assets", 120)))
        max_endpoints = max(1, int(options.get("max_endpoints") or settings.get("max_endpoints", 2000)))
        probe_endpoints = bool(options.get("probe_endpoints", settings.get("probe_endpoints", False)))
        probe_context_methods = bool(
            options.get("probe_context_methods", settings.get("probe_context_methods", False))
        )
        fetch_sourcemaps = bool(options.get("fetch_sourcemaps", settings.get("fetch_sourcemaps", False)))
        active = bool(options.get("active", settings.get("active", False)))
        active_sqli = bool(options.get("active_sqli", settings.get("active_sqli", False)))
        max_active_checks = max(1, int(settings.get("max_active_checks", 60)))
        max_secrets = max(1, int(settings.get("max_secrets", 50)))
        seen_findings: dict[str, Finding] = {}
        seen_active: set[tuple[str, str, str]] = set()
        seen_assets: set[tuple[str, str, str]] = set()
        reported_endpoints: set[tuple[str, str, str, str]] = set()
        assets_count = 0
        probes = 0
        active_requests = 0
        secrets_found = 0

        budget_stopped = False
        for target in targets:
            try:
                page = self._page(context, target, result)
            except BudgetExceeded:
                result.stats["budget_stopped"] = True
                budget_stopped = True
                break
            except CancelledError:
                raise
            if page is None:
                continue
            document = analyse_document(page.text, page.final_url, target.url)
            if document.markers or document.scripts:
                self._append_once(
                    result,
                    seen_findings,
                    Finding(
                        module=self.name,
                        kind="packer_detected",
                        target=target.url,
                        target_id=target.identity,
                        auth_scope=target.auth_scope,
                        method="GET",
                        severity="info",
                        confidence=0.7 if document.markers else 0.55,
                        technique="marker-detection",
                        evidence=("markers=" + ",".join(document.markers)) if document.markers else "webpack-style assets found",
                        metadata={
                            "markers": document.markers,
                            "assets": len(document.scripts),
                            "target_id": target.identity,
                            "source_target": target.url,
                            "auth_scope": target.auth_scope,
                        },
                        source_target=target.url,
                    ),
                )

            endpoints: list[Endpoint] = list(document.endpoints)
            all_text: list[tuple[str, str]] = [(page.final_url, page.text)]
            queue = deque(document.scripts)
            fetched_assets = 0
            source_maps_seen = 0
            progress = getattr(context, "progress", None)
            asset_budget = max_assets * max(1, len(targets))
            while queue and fetched_assets < max_assets and assets_count < max_assets * max(1, len(targets)):
                asset_url = queue.popleft()
                asset_key = (target.identity, target.auth_scope, canonical_url(asset_url))
                if asset_key in seen_assets or not host_allowed(target.url, asset_url):
                    continue
                seen_assets.add(asset_key)
                try:
                    asset = context.executor.get(
                        asset_url,
                        target_id=target.identity,
                        profile_id=context.profile.id,
                        purpose="asset",
                        headers=target.headers,
                        cookies=target.cookies,
                        auth_scope=target.auth_scope,
                        auth_origin=target.origin,
                        metadata={"resource_type": "script", "referer": page.final_url},
                    )
                except BudgetExceeded:
                    result.stats["budget_stopped"] = True
                    budget_stopped = True
                    break
                except CancelledError:
                    raise
                except Exception as exc:
                    result.errors.append(f"asset failed {asset_url}: {exc}")
                    continue
                context.results.add_snapshot(asset)
                fetched_assets += 1
                assets_count += 1
                if progress is not None:
                    progress("packer", assets_count, asset_budget)
                self._append_once(
                    result,
                    seen_findings,
                    Finding(
                        module=self.name,
                        kind="packer_asset",
                        target=asset_url,
                        target_id=target.identity,
                        auth_scope=target.auth_scope,
                        method="GET",
                        severity="info",
                        confidence=0.8,
                        technique="static-webpack",
                        evidence=f"status={asset.status}; length={asset.length}",
                        response_summary={"status": asset.status, "length": asset.length},
                        metadata={
                            "source": page.final_url,
                            "asset_id": _sha256(asset.body),
                            "target_id": target.identity,
                            "source_target": target.url,
                            "auth_scope": target.auth_scope,
                        },
                        source_target=target.url,
                        request_id=asset.request_id,
                    ),
                )
                all_text.append((asset.final_url, asset.text))
                queue.extend(extract_scripts(asset.text, asset.final_url, target.url))
                endpoints.extend(extract_endpoints(asset.text, asset.final_url, target.url))
                if fetch_sourcemaps:
                    for map_url in source_map_urls(asset.text, asset.final_url, target.url):
                        if source_maps_seen >= 8:
                            break
                        source_maps_seen += 1
                        try:
                            endpoints.extend(self._source_map_endpoints(context, target, map_url, result))
                        except BudgetExceeded:
                            result.stats["budget_stopped"] = True
                            budget_stopped = True
                            break
                        except CancelledError:
                            raise
                    if budget_stopped:
                        break

            if budget_stopped:
                break

            upload_marker_seen = False
            for source_url, text in all_text:
                endpoints.extend(extract_endpoints(text, source_url, target.url))
                if not upload_marker_seen and upload_markers(text):
                    upload_marker_seen = True
                    self._append_once(
                        result,
                        seen_findings,
                        Finding(
                            module=self.name,
                            kind="packer_upload_surface",
                            target=source_url,
                            target_id=target.identity,
                            auth_scope=target.auth_scope,
                            method="GET",
                            severity="medium",
                            confidence=0.7,
                            technique="upload-marker-detection",
                            evidence="multipart or FormData upload semantics detected",
                            metadata={
                                "surface": "upload",
                                "target_id": target.identity,
                                "source_target": target.url,
                                "auth_scope": target.auth_scope,
                                "source_asset": source_url,
                            },
                            source_target=target.url,
                        ),
                    )
                if secrets_found < max_secrets:
                    for secret in find_secrets(text, source_url, limit=max_secrets):
                        appended = self._append_once(
                            result,
                            seen_findings,
                            Finding(
                                module=self.name,
                                kind="packer_secret",
                                target=source_url,
                                target_id=target.identity,
                                auth_scope=target.auth_scope,
                                method="GET",
                                severity="medium" if secret.kind.startswith("generic-") else "high",
                                confidence=0.65 if secret.kind.startswith("generic-") else 0.9,
                                technique="static-secret-extraction",
                                evidence=f"{secret.kind} detected; value={secret.preview}",
                                metadata={
                                    "secret_kind": secret.kind,
                                    "target_id": target.identity,
                                    "source_target": target.url,
                                    "auth_scope": target.auth_scope,
                                    "source_asset": source_url,
                                },
                                dedupe_key=(
                                    f"{target.identity}|{target.auth_scope}|secret|"
                                    f"{secret.kind}|{_sha256(secret.value.encode('utf-8'))}"
                                ),
                                source_target=target.url,
                            ),
                        )
                        if appended:
                            secrets_found += 1
                            if secrets_found >= max_secrets:
                                break
            endpoints = _dedupe_endpoints(endpoints)
            endpoints = endpoints[:max_endpoints]
            surfaces = classify_surface(endpoints, limit=200)
            for surface in surfaces:
                category = surface.category
                self._append_once(
                    result,
                    seen_findings,
                    Finding(
                        module=self.name,
                        kind=f"packer_{category}_surface",
                        target=surface.endpoint.url,
                        dedupe_key=(
                            f"{self.name}|{category}_surface|{target.auth_scope}|"
                            f"{surface.endpoint.method}|{canonical_url(surface.endpoint.url)}"
                        ),
                        target_id=target.identity,
                        auth_scope=target.auth_scope,
                        method=surface.endpoint.method,
                        severity="medium" if category == "upload" else "low",
                        confidence=surface.confidence,
                        technique="passive-surface-classification",
                        evidence=surface.reason,
                        request_summary={"method": surface.endpoint.method, "url": surface.endpoint.url},
                        metadata={
                            "surface": category,
                            "target_id": target.identity,
                            "source_target": target.url,
                            "auth_scope": target.auth_scope,
                            "source_asset": surface.endpoint.source_asset,
                        },
                        source_target=target.url,
                    ),
                )
            for endpoint in endpoints:
                endpoint_key = (target.identity, target.auth_scope, endpoint.method, canonical_url(endpoint.url))
                if endpoint_key in reported_endpoints:
                    continue
                reported_endpoints.add(endpoint_key)
                status = 0
                verified = False
                request_id = ""
                probe_response: ResponseSnapshot | None = None
                response_summary: dict[str, object] = {}
                probe_methods = {"explicit", "context"} if probe_context_methods else {"explicit"}
                can_probe_get = endpoint.method == "GET" and endpoint.method_source in probe_methods
                if probe_endpoints and can_probe_get:
                    if probes >= max_endpoints:
                        result.stats["probe_limit_reached"] = True
                    else:
                        try:
                            response = context.executor.get(
                                endpoint.url,
                                target_id=target.identity,
                                profile_id=context.profile.id,
                                purpose="api",
                                headers=target.headers,
                                cookies=target.cookies,
                                auth_scope=target.auth_scope,
                                auth_origin=target.origin,
                                cache_policy="default",
                                metadata={"source": "packer-probe", "referer": target.url},
                            )
                        except BudgetExceeded:
                            result.stats["budget_stopped"] = True
                            budget_stopped = True
                            break
                        except CancelledError:
                            raise
                        except Exception as exc:
                            result.errors.append(f"probe failed {endpoint.url}: {exc}")
                        else:
                            context.results.add_snapshot(response)
                            probe_response = response
                            probes += 1
                            status = response.status
                            verified = True
                            request_id = response.request_id
                            response_summary = {"status": response.status, "length": response.length}
                self._append_once(
                    result,
                    seen_findings,
                    Finding(
                        module=self.name,
                        kind="packer_endpoint",
                        target=endpoint.url,
                        dedupe_key=(
                            f"{self.name}|endpoint|{target.auth_scope}|"
                            f"{endpoint.method}|{canonical_url(endpoint.url)}"
                        ),
                        target_id=target.identity,
                        auth_scope=target.auth_scope,
                        method=endpoint.method,
                        severity="info",
                        confidence=0.72 if verified else 0.55,
                        technique=endpoint.technique,
                        evidence=(
                            f"path extracted from packaged JavaScript; status={status}"
                            if verified
                            else "API-like path extracted from packaged JavaScript"
                        ),
                        request_summary={"method": endpoint.method, "url": endpoint.url},
                        response_summary=response_summary,
                        metadata={
                            "target_id": target.identity,
                            "source_target": target.url,
                            "auth_scope": target.auth_scope,
                            "source_asset": endpoint.source_asset,
                            "status": status,
                            "verified": verified,
                        },
                        source_target=target.url,
                        request_id=request_id,
                    ),
                )
                if active and can_probe_get and active_requests < max_active_checks:
                    active_requests += self._active_endpoint_checks(
                        context,
                        target,
                        endpoint,
                        probe_response,
                        result,
                        seen_findings,
                        seen_active,
                        active_sqli=active_sqli,
                        remaining=max_active_checks - active_requests,
                    )
                if result.stats.get("budget_stopped"):
                    budget_stopped = True
                    break

            if budget_stopped:
                break

        result.findings = dedupe_findings(result.findings)
        unique_endpoints = {
            (finding.auth_scope, finding.method, canonical_url(finding.target))
            for finding in result.findings
            if finding.kind == "packer_endpoint"
        }
        unique_surfaces = {
            (finding.auth_scope, finding.kind, finding.method, canonical_url(finding.target))
            for finding in result.findings
            if finding.kind.startswith("packer_") and finding.kind.endswith("_surface")
        }
        result.stats.update(
            {
                "targets": len(targets),
                "assets": assets_count,
                "endpoints": len(unique_endpoints),
                "surface_candidates": len(unique_surfaces),
                "probed_endpoints": probes,
                "active": active,
                "active_requests": active_requests,
                "secrets_found": secrets_found,
                "active_checks": sorted(seen_active),
                "runtime_available": bool(
                    context.capabilities.get("deno").available or context.capabilities.get("node").available
                ),
                "dynamic_analysis": False,
                "static_fallback": True,
            }
        )
        return result

    def _active_endpoint_checks(
        self,
        context: ScanContext,
        target: Target,
        endpoint: Endpoint,
        authenticated_probe: ResponseSnapshot | None,
        result: ComponentResult,
        seen_findings: dict[str, Finding],
        seen_active: set[tuple[str, str, str]],
        *,
        active_sqli: bool,
        remaining: int,
    ) -> int:
        """Run conservative checks without creating a second HTTP stack."""

        used = 0
        key = (target.identity, target.auth_scope, canonical_url(endpoint.url))
        if remaining > 0 and key not in seen_active:
            seen_active.add(key)
            try:
                response = context.executor.request(
                    RequestSpec(
                        url=endpoint.url,
                        target_id=target.identity,
                        profile_id=context.profile.id,
                        headers={**target.headers, "Origin": CORS_PROBE_ORIGIN},
                        cookies=target.cookies,
                        auth_scope=target.auth_scope,
                        auth_origin=target.origin,
                        purpose="api",
                        attack=True,
                        cache_policy="no-store",
                        side_effect_free=False,
                        metadata={
                            "technique": "cors",
                            "source": "packer-active",
                            "referer": target.url,
                            "site": "cross-site",
                            "origin": CORS_PROBE_ORIGIN,
                        },
                    )
                )
                used += 1
                context.results.add_snapshot(response)
                decision = evaluate_cors(response)
                if decision.accepted:
                    self._append_once(
                        result,
                        seen_findings,
                        Finding(
                            module=self.name,
                            kind="packer_cors",
                            target=endpoint.url,
                            target_id=target.identity,
                            auth_scope=target.auth_scope,
                            method="GET",
                            severity="medium",
                            confidence=decision.confidence,
                            technique=decision.technique,
                            evidence=decision.evidence,
                            response_summary={"status": response.status, "length": response.length},
                            metadata={
                                "target_id": target.identity,
                                "source_target": target.url,
                                "auth_scope": target.auth_scope,
                            },
                            source_target=target.url,
                            request_id=response.request_id,
                        ),
                    )
            except BudgetExceeded:
                result.stats["budget_stopped"] = True
                return used
            except Exception as exc:
                result.errors.append(f"cors check failed {endpoint.url}: {exc}")

        if active_sqli and remaining > used:
            used += self._active_sqli_checks(
                context,
                target,
                endpoint,
                result,
                seen_findings,
                remaining=remaining - used,
            )

        if not (target.headers or target.cookies) or remaining <= used:
            return used

        authenticated = authenticated_probe
        if authenticated is None:
            try:
                authenticated = context.executor.request(
                    RequestSpec(
                        url=endpoint.url,
                        target_id=target.identity,
                        profile_id=context.profile.id,
                        headers=target.headers,
                        cookies=target.cookies,
                        auth_scope=target.auth_scope,
                        auth_origin=target.origin,
                        purpose="api",
                        attack=True,
                        cache_policy="no-store",
                        side_effect_free=False,
                        metadata={"technique": "authenticated-baseline", "referer": target.url},
                    )
                )
                used += 1
                context.results.add_snapshot(authenticated)
            except BudgetExceeded:
                result.stats["budget_stopped"] = True
                return used
            except Exception as exc:
                result.errors.append(f"authenticated baseline failed {endpoint.url}: {exc}")
                return used

        if authenticated.status not in (401, 403) or remaining <= used:
            return used
        anonymous_scope = f"{target.auth_scope}#anonymous"
        try:
            response = context.executor.get(
                endpoint.url,
                target_id=target.identity,
                auth_scope=anonymous_scope,
                auth_origin=target.origin,
                profile_id=context.profile.id,
                headers={},
                cookies={},
                purpose="api",
                attack=True,
                side_effect_free=False,
                cache_policy="no-store",
                metadata={"technique": "anonymous-baseline", "referer": target.url},
            )
            used += 1
            context.results.add_snapshot(response)
            decision = evaluate_unauthorized(authenticated, response)
            if decision.accepted:
                self._append_once(
                    result,
                    seen_findings,
                    Finding(
                        module=self.name,
                        kind="packer_unauthorized",
                        target=endpoint.url,
                        target_id=target.identity,
                        auth_scope=target.auth_scope,
                        method="GET",
                        severity="high",
                        confidence=decision.confidence,
                        technique=decision.technique,
                        evidence=decision.evidence,
                        response_summary={"status": response.status, "length": response.length},
                        metadata={
                            "target_id": target.identity,
                            "source_target": target.url,
                            "auth_scope": target.auth_scope,
                        },
                        source_target=target.url,
                        request_id=response.request_id,
                    ),
                )
        except BudgetExceeded:
            result.stats["budget_stopped"] = True
            return used
        except Exception as exc:
            result.errors.append(f"anonymous check failed {endpoint.url}: {exc}")

        return used

    def _active_sqli_checks(
        self,
        context: ScanContext,
        target: Target,
        endpoint: Endpoint,
        result: ComponentResult,
        seen_findings: dict[str, Finding],
        *,
        remaining: int,
    ) -> int:
        used = 0
        for probe_url, parameter in sql_probe_urls(endpoint.url):
            if used >= remaining:
                break
            try:
                response = context.executor.request(
                    RequestSpec(
                        url=probe_url,
                        target_id=target.identity,
                        profile_id=context.profile.id,
                        headers=target.headers,
                        cookies=target.cookies,
                        auth_scope=target.auth_scope,
                        auth_origin=target.origin,
                        purpose="api",
                        attack=True,
                        cache_policy="no-store",
                        side_effect_free=False,
                        metadata={"technique": "sql-quote", "parameter": parameter, "referer": target.url},
                    )
                )
                used += 1
                context.results.add_snapshot(response)
            except BudgetExceeded:
                result.stats["budget_stopped"] = True
                break
            except Exception as exc:
                result.errors.append(f"SQL probe failed {probe_url}: {exc}")
                continue
            if looks_like_sql_error(response.text):
                self._append_once(
                    result,
                    seen_findings,
                    Finding(
                        module=self.name,
                        kind="packer_sqli",
                        target=endpoint.url,
                        target_id=target.identity,
                        auth_scope=target.auth_scope,
                        method="GET",
                        severity="high",
                        confidence=0.8,
                        technique="sql-error-signature",
                        evidence=f"parameter={parameter}; server returned a database error signature",
                        response_summary={"status": response.status, "length": response.length},
                        metadata={
                            "parameter": parameter,
                            "target_id": target.identity,
                            "source_target": target.url,
                            "auth_scope": target.auth_scope,
                        },
                        source_target=target.url,
                        request_id=response.request_id,
                    ),
                )
                break
        return used

    def _page(self, context: ScanContext, target: Target, result: ComponentResult):
        page = context.results.get_snapshot(
            target.url,
            target_id=target.identity,
            auth_scope=target.auth_scope,
            method="GET",
        )
        if page is not None:
            return page
        try:
            page = context.executor.get(
                target.url,
                target_id=target.identity,
                profile_id=context.profile.id,
                purpose="navigation",
                headers=target.headers,
                cookies=target.cookies,
                auth_scope=target.auth_scope,
                auth_origin=target.origin,
                metadata={"direct_navigation": True},
            )
        except BudgetExceeded:
            result.stats["budget_stopped"] = True
            raise
        except CancelledError:
            raise
        except Exception as exc:
            result.errors.append(f"page failed for {target.url}: {exc}")
            return None
        context.results.add_snapshot(page)
        return page

    def _source_map_endpoints(
        self,
        context: ScanContext,
        target: Target,
        map_url: str,
        result: ComponentResult,
    ) -> list[Endpoint]:
        try:
            response = context.executor.get(
                map_url,
                target_id=target.identity,
                profile_id=context.profile.id,
                purpose="asset",
                headers=target.headers,
                cookies=target.cookies,
                auth_scope=target.auth_scope,
                auth_origin=target.origin,
                metadata={"resource_type": "script", "referer": target.url},
            )
            context.results.add_snapshot(response)
            payload = json.loads(response.text)
        except BudgetExceeded:
            result.stats["budget_stopped"] = True
            raise
        except CancelledError:
            raise
        except Exception:
            return []
        if not isinstance(payload, dict):
            return []
        result: list[Endpoint] = []
        source_contents = payload.get("sourcesContent")
        if isinstance(source_contents, list):
            for content in source_contents[:32]:
                if isinstance(content, str):
                    result.extend(extract_endpoints(content, map_url, target.url))
        return _dedupe_endpoints(result)

    @staticmethod
    def _append_once(
        result: ComponentResult,
        seen: dict[str, Finding],
        finding: Finding,
    ) -> bool:
        key = finding.semantic_key
        existing = seen.get(key)
        if existing is not None:
            merge_finding_provenance(existing, finding)
            return False
        seen[key] = finding
        result.findings.append(finding)
        return True


def _dedupe_endpoints(values: list[Endpoint]) -> list[Endpoint]:
    seen: set[tuple[str, str]] = set()
    indexes: dict[tuple[str, str], int] = {}
    result: list[Endpoint] = []
    rank = {"explicit": 3, "context": 2, "inferred": 1}
    for value in values:
        if value.key not in seen:
            seen.add(value.key)
            indexes[value.key] = len(result)
            result.append(value)
            continue
        index = indexes[value.key]
        if rank.get(value.method_source, 0) > rank.get(result[index].method_source, 0):
            result[index] = value
    return result


def _sha256(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()


__all__ = ["PackerAdapter"]
