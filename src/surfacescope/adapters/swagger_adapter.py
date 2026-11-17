"""Adapter for browserless Swagger/OpenAPI discovery and safe probing."""

from __future__ import annotations

import hashlib
import json
from urllib.parse import urljoin

from ..components.swagger import DOCUMENT_PATHS, document_links, iter_operations, parse_document
from ..context import ScanContext
from ..errors import BudgetExceeded
from ..models import ComponentResult, Finding, RequestSpec, Target
from ..urls import canonical_url, host_allowed, origin
from .base import ComponentAdapter


class SwaggerAdapter(ComponentAdapter):
    name = "swagger"

    def scan(self, context: ScanContext, targets: list[Target], options: dict) -> ComponentResult:
        result = ComponentResult()
        settings = context.config.section("swagger")
        max_documents = max(1, int(options.get("max_documents") or settings.get("max_documents", 12)))
        max_requests = max(1, int(options.get("max_requests") or settings.get("max_requests", 200)))
        include_unsafe = bool(options.get("include_unsafe", settings.get("include_unsafe", False)))
        allow_external = bool(options.get("allow_external", settings.get("allow_external", False)))
        seen_documents: set[tuple[str, str]] = set()
        seen_operations: set[tuple[str, str, str, str]] = set()
        stats = {
            "documents_fetched": 0,
            "documents_parsed": 0,
            "endpoints": 0,
            "requests": 0,
            "skipped_unsafe": 0,
            "methods": {},
        }

        for target in targets:
            page = self._page(context, target, result)
            candidates = [urljoin(origin(target.url) + "/", path.lstrip("/")) for path in DOCUMENT_PATHS]
            if page is not None:
                candidates.extend(document_links(page.text, page.final_url))
            for doc_url in _dedupe(candidates):
                if stats["documents_fetched"] >= max_documents or stats["requests"] >= max_requests:
                    break
                if not host_allowed(target.url, doc_url):
                    continue
                doc_key = (target.identity, canonical_url(doc_url))
                if doc_key in seen_documents:
                    continue
                seen_documents.add(doc_key)
                snapshot = self._fetch_document(context, target, doc_url, result)
                if snapshot is None:
                    continue
                stats["documents_fetched"] += 1
                stats["requests"] += 1
                document = parse_document(snapshot.text) if snapshot.status < 400 else None
                if document is None:
                    continue
                if not isinstance(document.get("paths"), dict):
                    continue
                stats["documents_parsed"] += 1
                spec_version = str(document.get("openapi") or document.get("swagger") or "unknown")
                path_count = len(document["paths"])
                result.findings.append(
                    Finding(
                        module=self.name,
                        kind="swagger_document",
                        target=doc_url,
                        target_id=target.identity,
                        auth_scope=target.auth_scope,
                        method="GET",
                        severity="info",
                        confidence=0.95,
                        technique="openapi-discovery",
                        evidence=f"spec={spec_version}; paths={path_count}",
                        response_summary={"status": snapshot.status, "length": snapshot.length},
                        metadata={
                            "spec_version": spec_version,
                            "path_count": path_count,
                            "source_target": target.url,
                            "auth_scope": target.auth_scope,
                        },
                        source_target=target.url,
                        request_id=snapshot.request_id,
                    )
                )
                for operation in iter_operations(
                    document,
                    target.url,
                    include_unsafe=include_unsafe,
                    max_operations=max_requests,
                    allow_external=allow_external,
                ):
                    operation_key = _operation_key(operation)
                    if operation_key in seen_operations:
                        continue
                    seen_operations.add(operation_key)
                    stats["endpoints"] += 1
                    if not operation.safe and not include_unsafe:
                        stats["skipped_unsafe"] += 1
                        result.findings.append(
                            self._finding(
                                target,
                                doc_url,
                                spec_version,
                                operation,
                                status=0,
                                verified=False,
                                evidence="declared operation; unsafe method not requested",
                            )
                        )
                        continue
                    if stats["requests"] >= max_requests:
                        result.stats["request_limit_reached"] = True
                        result.findings.append(
                            self._finding(
                                target,
                                doc_url,
                                spec_version,
                                operation,
                                status=0,
                                verified=False,
                                evidence="declared operation; request limit reached",
                            )
                        )
                        continue
                    finding = self._probe_operation(
                        context,
                        target,
                        doc_url,
                        spec_version,
                        operation,
                        result,
                    )
                    if finding is not None:
                        stats["requests"] += 1
                        method = operation.method
                        stats["methods"][method] = stats["methods"].get(method, 0) + 1

        result.stats.update(stats)
        return result

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
        except Exception as exc:
            result.errors.append(f"page discovery failed for {target.url}: {exc}")
            return None
        context.results.add_snapshot(page)
        return page

    def _fetch_document(
        self,
        context: ScanContext,
        target: Target,
        doc_url: str,
        result: ComponentResult,
    ):
        try:
            snapshot = context.executor.request(
                RequestSpec(
                    url=doc_url,
                    target_id=target.identity,
                    profile_id=context.profile.id,
                    method="GET",
                    purpose="api",
                    headers=target.headers,
                    cookies=target.cookies,
                    auth_scope=target.auth_scope,
                    auth_origin=target.origin,
                    cache_policy="default",
                    metadata={"source": "swagger-document", "referer": target.url},
                )
            )
        except Exception as exc:
            result.errors.append(f"document fetch failed {doc_url}: {exc}")
            return None
        context.results.add_snapshot(snapshot)
        return snapshot

    def _probe_operation(
        self,
        context: ScanContext,
        target: Target,
        doc_url: str,
        spec_version: str,
        operation,
        result: ComponentResult,
    ) -> Finding | None:
        body = operation.request_body
        kwargs = {
            "json": body if operation.method not in ("GET", "HEAD") and isinstance(body, dict) else None,
        }
        try:
            response = context.executor.request(
                RequestSpec(
                    url=operation.url,
                    target_id=target.identity,
                    profile_id=context.profile.id,
                    method=operation.method,
                    purpose="api",
                    headers={**target.headers, **operation.headers},
                    params=operation.query or None,
                    cookies={**target.cookies, **operation.cookies},
                    auth_scope=target.auth_scope,
                    auth_origin=target.origin,
                    cache_policy="default" if operation.safe else "no-store",
                    side_effect_free=operation.safe,
                    attack=not operation.safe,
                    metadata={
                        "source": "swagger-operation",
                        "swagger_method": operation.method,
                        "referer": target.url,
                    },
                    **kwargs,
                )
            )
        except BudgetExceeded:
            result.stats["budget_stopped"] = True
            return None
        except Exception as exc:
            result.errors.append(f"endpoint failed {operation.method} {operation.url}: {exc}")
            return None
        context.results.add_snapshot(response)
        finding = self._finding(
            target,
            doc_url,
            spec_version,
            operation,
            status=response.status,
            verified=True,
            evidence=f"status={response.status}; length={response.length}",
            response=response,
        )
        result.findings.append(finding)
        return finding

    def _finding(
        self,
        target: Target,
        doc_url: str,
        spec_version: str,
        operation,
        *,
        status: int,
        verified: bool,
        evidence: str,
        response=None,
    ) -> Finding:
        return Finding(
            module=self.name,
            kind="swagger_endpoint",
            target=operation.url,
            target_id=target.identity,
            auth_scope=target.auth_scope,
            method=operation.method,
            severity="info",
            confidence=0.85 if verified else 0.6,
            technique=f"openapi-{operation.method.lower()}",
            evidence=evidence,
            request_summary={
                "method": operation.method,
                "url": operation.url,
                "query": operation.query,
                "header_names": sorted(operation.headers),
            },
            response_summary={
                "status": status,
                "length": getattr(response, "length", 0),
                "verified": verified,
            },
            metadata={
                "document": doc_url,
                "spec_version": spec_version,
                "operation_id": operation.operation_id,
                "summary": operation.summary,
                "status": status,
                "verified": verified,
                "source_target": target.url,
                "auth_scope": target.auth_scope,
            },
            source_target=target.url,
            request_id=getattr(response, "request_id", ""),
        )


def _operation_key(operation) -> tuple[str, str, str, str]:
    material = json.dumps(
        {"query": operation.query, "headers": operation.headers, "cookies": operation.cookies},
        sort_keys=True,
        ensure_ascii=False,
    )
    return (
        operation.method,
        canonical_url(operation.url),
        hashlib.sha256(material.encode("utf-8")).hexdigest(),
        str(operation.request_body) if operation.request_body is not None else "",
    )


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


__all__ = ["SwaggerAdapter"]
