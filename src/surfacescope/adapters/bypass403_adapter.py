"""One 403/401 review engine with a small, evidence-oriented default set.

There is no reliable way to infer that an untested header cannot bypass an
authorization layer. The fast mode therefore sends a fixed, curated set of
high-value variants and stops on the first accepted response. It does not
pretend a silent first round proves that all other techniques are ineffective.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from urllib.parse import unquote, urlsplit, urlunsplit

from ..components.bypass403.catalog import MODE_POLICIES, MODES, BypassCatalog
from ..components.bypass403.catalog import Variant as _Variant
from ..context import ScanContext
from ..errors import BudgetExceeded
from ..models import ComponentResult, Finding, RequestSpec, ResponseSnapshot, Target
from ..quality.qc import QualityController
from ..urls import canonical_url, origin
from .base import ComponentAdapter

_VALID_MODES = MODES


def _signature(snapshot: ResponseSnapshot) -> tuple[int, str, int, str]:
    text = " ".join(snapshot.text.lower().split())[:20000].encode("utf-8", errors="ignore")
    return (snapshot.status, snapshot.content_type, len(snapshot.body), hashlib.sha256(text).hexdigest())


def _same_response(left: ResponseSnapshot | None, right: ResponseSnapshot | None) -> bool:
    return left is not None and right is not None and _signature(left) == _signature(right)


def _matches_baseline(variant: _Variant, target_url: str) -> bool:
    """Return whether a mutation is byte-for-byte the original request."""

    return (
        variant.method == "GET"
        and not variant.headers
        and variant.data is None
        and variant.allow_redirects is None
        and canonical_url(variant.url) == canonical_url(target_url)
    )


def _merge_headers(base: dict[str, str], overrides: dict[str, str]) -> dict[str, str]:
    """Merge headers case-insensitively so Host/Content-Type overrides win cleanly."""

    merged = {str(key): str(value) for key, value in base.items()}
    for key, value in overrides.items():
        wanted = str(key).lower()
        for existing in [name for name in merged if name.lower() == wanted]:
            merged.pop(existing, None)
        merged[str(key)] = str(value)
    return merged


def _normalized_site_path(value: str) -> str:
    """Collapse dot segments and duplicate slashes for root-equivalence checks."""

    parts: list[str] = []
    for segment in unquote(value or "/").split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts:
                parts.pop()
            continue
        parts.append(segment)
    return "/" + "/".join(parts)


class Bypass403Adapter(ComponentAdapter):
    name = "bypass403"

    def scan(self, context: ScanContext, targets: list[Target], options: dict) -> ComponentResult:
        result = ComponentResult()
        settings = context.config.section("bypass")
        mode = str(options.get("mode") or settings.get("mode", "fast")).lower()
        if mode not in _VALID_MODES:
            result.errors.append(f"unsupported bypass mode: {mode}")
            return result

        policy = MODE_POLICIES[mode]
        configured_max = options.get("max_variants_per_url")
        if configured_max is None:
            configured_max = settings.get("max_variants_per_url", 0)
        max_variants = int(configured_max) if int(configured_max or 0) > 0 else policy.max_variants
        configured_initial = int(settings.get("initial_variants_per_url", 0) or 0)
        initial_variants = (
            policy.initial_variants
            if configured_initial <= 0
            else max(1, min(max_variants, configured_initial))
        )
        catalog = BypassCatalog(context.manifest)
        qc = QualityController()
        soft404_by_key: dict[tuple[str, str, str, str], ResponseSnapshot | None] = {}
        root_by_key: dict[tuple[str, str, str, str], ResponseSnapshot | None] = {}
        targets_seen: set[tuple[str, str]] = set()
        skipped = tested = accepted = 0
        planned_variants = 0
        generated_variants = 0
        escalated_targets = 0
        network_before = context.executor.audit.counts().get("network_sent", 0)

        for target in targets:
            target_key = (target.url, target.identity)
            if target_key in targets_seen:
                continue
            targets_seen.add(target_key)
            parsed = urlsplit(target.url)
            if not parsed.netloc:
                result.errors.append(f"invalid bypass target: {target.url}")
                continue
            target_path = _normalized_site_path(parsed.path)

            baseline = context.results.get_snapshot(
                target.url,
                target_id=target.identity,
                auth_scope=target.auth_scope,
                method="GET",
            )
            if baseline is None:
                try:
                    baseline = context.executor.get(
                        target.url,
                        target_id=target.identity,
                        budget_scope="bypass403",
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
                    break
                except Exception as exc:
                    result.errors.append(f"baseline failed for {target.url}: {exc}")
                    continue
                context.results.add_snapshot(baseline)
            if baseline.status not in (401, 403):
                skipped += 1
                continue

            soft_key = (
                target.identity,
                target.auth_scope,
                str(target.proxy or ""),
                hashlib.sha256(
                    json.dumps(
                        {"headers": target.headers, "cookies": target.cookies},
                        sort_keys=True,
                        ensure_ascii=False,
                    ).encode("utf-8")
                ).hexdigest(),
            )
            soft404 = soft404_by_key.get(soft_key)
            if soft404 is None and soft_key not in soft404_by_key:
                soft_path = "/.surfacescope-qc-" + secrets.token_hex(8)
                try:
                    soft404 = context.executor.get(
                        urlunsplit((parsed.scheme, parsed.netloc, soft_path, "", "")),
                        target_id=target.identity,
                        budget_scope="bypass403",
                        profile_id=context.profile.id,
                        purpose="navigation",
                        headers=target.headers,
                        cookies=target.cookies,
                        auth_scope=target.auth_scope,
                        auth_origin=target.origin,
                        metadata={"direct_navigation": True},
                    )
                    soft404_by_key[soft_key] = soft404
                    context.results.add_snapshot(soft404)
                except BudgetExceeded:
                    result.stats["budget_stopped"] = True
                    break
                except Exception:
                    soft404_by_key[soft_key] = None

            variants = catalog.variants(target.url, mode)
            variants = [variant for variant in variants if not _matches_baseline(variant, target.url)]
            if mode == "quick":
                if len(variants) < 2:
                    variants = [
                        variant
                        for variant in catalog.variants(target.url, "fast")
                        if not _matches_baseline(variant, target.url)
                    ]
                variants = variants[:2]
            elif mode == "fast":
                variants = variants[:max_variants]
            else:
                variants = variants[:max_variants]
            generated_variants += len(variants)
            initial_count = min(len(variants), initial_variants) if mode == "fast" else len(variants)
            planned_variants += initial_count

            root_url = origin(target.url) + "/"
            if target.url.rstrip("/") == root_url.rstrip("/"):
                root_by_key[soft_key] = baseline
            elif soft_key not in root_by_key:
                cached_root = context.results.get_snapshot(
                    root_url,
                    target_id=target.identity,
                    auth_scope=target.auth_scope,
                    method="GET",
                )
                if cached_root is not None:
                    root_by_key[soft_key] = cached_root

            signal_seen = False
            target_escalated = False
            for index, variant in enumerate(variants):
                if mode == "fast" and index >= initial_count and not signal_seen:
                    break
                if mode == "fast" and index >= initial_count and not target_escalated:
                    target_escalated = True
                    escalated_targets += 1
                    planned_variants += len(variants) - initial_count
                request_headers = _merge_headers(target.headers, variant.headers)
                try:
                    candidate = context.executor.request(
                        RequestSpec(
                            url=variant.url,
                            target_id=target.identity,
                            budget_scope="bypass403",
                            profile_id=context.profile.id,
                            attack=True,
                            method=variant.method,
                            headers=request_headers,
                            data=variant.data,
                            cookies=target.cookies,
                            auth_scope=target.auth_scope,
                            auth_origin=target.origin,
                            purpose="navigation",
                            cache_policy="no-store",
                            side_effect_free=False,
                            allow_redirects=variant.allow_redirects,
                            metadata={
                                "technique": variant.technique,
                                "direct_navigation": True,
                                "keep_content_type": variant.keep_content_type,
                                "preserve_path_encoding": "%" in urlsplit(variant.url).path,
                            },
                        )
                    )
                except BudgetExceeded:
                    result.stats["budget_stopped"] = True
                    break
                except Exception as exc:
                    result.errors.append(f"{variant.technique} failed for {target.url}: {exc}")
                    continue

                tested += 1
                context.results.add_snapshot(candidate)
                matches_soft404 = soft404 is not None and qc.is_soft_404(candidate, soft404)
                if (
                    variant.compare_to_root
                    and soft_key not in root_by_key
                    and not candidate.error
                    and 200 <= candidate.status < 300
                    and not matches_soft404
                ):
                    try:
                        root_by_key[soft_key] = context.executor.get(
                            root_url,
                            target_id=target.identity,
                            budget_scope="bypass403",
                            profile_id=context.profile.id,
                            purpose="navigation",
                            headers=target.headers,
                            cookies=target.cookies,
                            auth_scope=target.auth_scope,
                            auth_origin=target.origin,
                            cache_policy="no-store",
                            metadata={"direct_navigation": True},
                        )
                        context.results.add_snapshot(root_by_key[soft_key])
                    except BudgetExceeded:
                        result.stats["budget_stopped"] = True
                        break
                    except Exception:
                        root_by_key[soft_key] = None
                decision = qc.bypass(baseline, candidate)
                if matches_soft404:
                    decision = type(decision)(False, "matches random-path soft-404", 0.0)
                if variant.compare_to_root and _same_response(candidate, root_by_key.get(soft_key)):
                    decision = type(decision)(False, "matches ordinary root response", 0.0)
                candidate_path = _normalized_site_path(
                    urlsplit(candidate.final_url or candidate.url).path
                )
                if (
                    not variant.compare_to_root
                    and target_path not in ("", "/")
                    and candidate_path in ("", "/")
                ):
                    decision = type(decision)(
                        False,
                        "candidate normalized to the site root instead of the target path",
                        0.0,
                    )
                if not decision.accepted:
                    root_equivalent = variant.compare_to_root and _same_response(
                        candidate, root_by_key.get(soft_key)
                    )
                    if (
                        index < initial_count
                        and not root_equivalent
                        and _response_signal(baseline, candidate, soft404)
                    ):
                        signal_seen = True
                    continue

                accepted += 1
                result.findings.append(
                    self._finding(target, variant, candidate, decision, mode)
                )
                break

        network_after = context.executor.audit.counts().get("network_sent", 0)
        result.stats.update(
            {
                "mode": mode,
                "targets": len(targets_seen),
                "generated_variants": generated_variants,
                "candidate_variants": planned_variants,
                "initial_variants": initial_variants if mode == "fast" else None,
                "catalog": "sangnigege/bypass403@d465f2d3",
                "adaptively_escalated": bool(escalated_targets),
                "escalated_targets": escalated_targets,
                "skipped_not_blocked": skipped,
                "variants_tested": tested,
                "accepted": accepted,
                "network_requests": max(0, network_after - network_before),
                "request_budget_scope": "bypass403",
                "request_budget": context.executor.budget_usage("bypass403"),
            }
        )
        return result

    @staticmethod
    def _finding(
        target: Target,
        variant: _Variant,
        candidate: ResponseSnapshot,
        decision: object,
        mode: str,
    ) -> Finding:
        reason = getattr(decision, "reason", "")
        confidence = float(getattr(decision, "confidence", 0.0))
        safe_headers = {
            key: value
            for key, value in variant.headers.items()
            if key.lower() not in {"cookie", "authorization", "proxy-authorization"}
        }
        return Finding(
            module="bypass403",
            kind="403_bypass",
            target=target.url,
            target_id=target.identity,
            auth_scope=target.auth_scope,
            severity="medium",
            confidence=confidence,
            technique=variant.technique,
            evidence=(
                f"baseline={target.url}; candidate={candidate.status}/{candidate.length}; {reason}"
            ),
            request_summary={"method": variant.method, "url": variant.url, "headers": safe_headers},
            response_summary={
                "status": candidate.status,
                "length": candidate.length,
                "content_type": candidate.content_type,
            },
            metadata={
                "mode": mode,
                "decision": reason,
                "source": target.url,
                "auth_scope": target.auth_scope,
                "category": variant.category,
            },
            source_target=target.url,
            method=variant.method,
        )

def _response_signal(
    baseline: ResponseSnapshot,
    candidate: ResponseSnapshot,
    soft404: ResponseSnapshot | None,
) -> bool:
    """Escalate only when the initial probe produced a real response delta."""

    if candidate.error or not 200 <= candidate.status < 400:
        return False
    if soft404 is not None and candidate.status == soft404.status and candidate.length == soft404.length:
        return False
    if candidate.status != baseline.status:
        return True
    return abs(candidate.length - baseline.length) > max(64, int(baseline.length * 0.10))
