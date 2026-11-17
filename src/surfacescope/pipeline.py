"""Composition root for a single scan run.

The pipeline is the only place that constructs sessions, adapters and report
writers. Adapters receive an explicit ``ScanContext`` and never parse argv or
write user-facing reports.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .adapters.base import ComponentAdapter
from .adapters.bypass403_adapter import Bypass403Adapter
from .adapters.dirsearch_adapter import DirsearchAdapter
from .adapters.finger_adapter import FingerAdapter
from .adapters.jsfinder_adapter import JSFinderAdapter
from .adapters.packer_adapter import PackerAdapter
from .adapters.swagger_adapter import SwaggerAdapter
from .artifacts import ArtifactStore
from .assets import AssetManifest, WordlistRegistry
from .capabilities import CapabilityRegistry
from .components.bypass403.catalog import MODE_POLICIES
from .config import ConfigSnapshot, load_config
from .context import ScanContext
from .errors import CancelledError, ConfigurationError
from .logging import get_logger
from .models import ComponentResult, Target
from .reporting.writer import ReportWriter
from .result_store import ResultStore
from .traffic.audit import RequestAudit
from .traffic.cache import ResponseCache
from .traffic.executor import RequestExecutor
from .traffic.profiles import RequestProfile, RequestProfileRegistry
from .urls import canonical_url, host_allowed, origin

ADAPTERS: dict[str, type[ComponentAdapter]] = {
    "dirsearch": DirsearchAdapter,
    "jsfinder": JSFinderAdapter,
    "finger": FingerAdapter,
    "bypass": Bypass403Adapter,
    "bypass403": Bypass403Adapter,
    "swagger": SwaggerAdapter,
    "packer": PackerAdapter,
}

# Dependency order is part of the public pipeline contract. Discovery runs
# before consumers, and fingerprinting runs last so it can use discovered URLs.
COMPONENT_ORDER = ("dirsearch", "jsfinder", "packer", "swagger", "bypass403", "finger")
_DISCOVERY_COMPONENTS = frozenset({"dirsearch", "jsfinder", "packer", "swagger"})


@dataclass
class PipelineResult:
    run_id: str
    output_dir: Path
    component_result: ComponentResult
    report_paths: list[Path] = field(default_factory=list)
    run_meta: dict[str, Any] = field(default_factory=dict)
    component_results: dict[str, ComponentResult] = field(default_factory=dict)


def create_context(
    *,
    user_config: str | Path | None = None,
    overrides: dict[str, Any] | None = None,
    include_env: bool = True,
    profile_id: str | None = None,
    proxy: str | None = None,
    verbose: bool = False,
    artifact_root: str | Path | None = None,
) -> tuple[ScanContext, RequestExecutor, ArtifactStore, RequestAudit]:
    config, manifest, profile = validate_runtime(
        user_config=user_config,
        overrides=overrides,
        include_env=include_env,
        profile_id=profile_id,
    )
    run = config.section("run")
    traffic = config.section("traffic")
    logger = get_logger(verbose=verbose)
    artifacts = ArtifactStore(root=artifact_root)
    results = ResultStore()
    audit = RequestAudit()
    cache = ResponseCache(
        max_entries=int(traffic.get("cache_max_entries", 2048)),
        ttl=float(traffic.get("cache_ttl", 300.0)),
    )
    proxies = {"http": proxy, "https": proxy} if proxy else None
    profiles = RequestProfileRegistry(manifest)
    global_total = int(traffic.get("max_total_requests", 0) or 0)
    global_per_host = int(traffic.get("max_requests_per_host", 0) or 0)
    executor = RequestExecutor(
        profile,
        profiles=profiles,
        timeout=float(run.get("timeout", 10.0)),
        verify_tls=bool(traffic.get("verify_tls", True)),
        follow_redirects=bool(traffic.get("follow_redirects", False)),
        max_redirects=int(traffic.get("max_redirects", 10)),
        max_response_bytes=int(run.get("max_response_bytes", 8 * 1024 * 1024)),
        cache=cache,
        audit=audit,
        proxies=proxies,
        rate_limit_per_second=float(traffic.get("rate_limit_per_second", 0.0) or 0.0),
        max_workers=int(run.get("threads", 25)),
    )
    context = ScanContext(
        config=config,
        profile=profile,
        executor=executor,
        artifacts=artifacts,
        results=results,
        capabilities=CapabilityRegistry().detect(),
        logger=logger,
        manifest=manifest,
        wordlists=WordlistRegistry(manifest),
        output_dir=Path.home() / ".surfacescope" / "reports",
        options={},
    )
    # The executor owns one profile registry and one budget for the whole run.
    # Component-scoped policies prevent a 403 stage from silently consuming an
    # unrelated component's allowance.
    if global_total or global_per_host:
        executor.configure_budget("default", max_total=global_total, max_per_host=global_per_host)
    bypass = config.section("bypass")
    bypass_mode = str(bypass.get("mode", "fast"))
    bypass_policy = MODE_POLICIES.get(bypass_mode, MODE_POLICIES["fast"])
    bypass_total = int(bypass.get("max_total_requests", 0) or 0) or bypass_policy.max_total_requests
    bypass_per_host = (
        int(bypass.get("max_requests_per_host", 0) or 0) or bypass_policy.max_requests_per_host
    )
    executor.configure_budget(
        "bypass403",
        max_total=bypass_total,
        max_per_host=bypass_per_host,
    )
    return context, executor, artifacts, audit


def validate_runtime(
    *,
    user_config: str | Path | None = None,
    overrides: dict[str, Any] | None = None,
    include_env: bool = True,
    profile_id: str | None = None,
) -> tuple[ConfigSnapshot, AssetManifest, RequestProfile]:
    """Validate configuration, assets and the selected profile without scanning."""

    manifest = AssetManifest()
    config = load_config(
        user_config=user_config,
        overrides=overrides,
        include_env=include_env,
        manifest=manifest,
    )
    errors = manifest.validate()
    if errors:
        raise ConfigurationError("asset manifest validation failed: " + "; ".join(errors))
    profiles = RequestProfileRegistry(manifest)
    profile = profiles.get(profile_id or str(config.section("run").get("profile", "chromium-desktop-stable")))
    return config, manifest, profile


def run_scan(
    targets: list[Target],
    *,
    components: list[str],
    adapter_options: dict[str, Any] | None = None,
    output_dir: str | Path | None = None,
    report_format: str | list[str] | None = None,
    user_config: str | Path | None = None,
    overrides: dict[str, Any] | None = None,
    include_env: bool = True,
    profile_id: str | None = None,
    proxy: str | None = None,
    verbose: bool = False,
    artifact_root: str | Path | None = None,
) -> PipelineResult:
    if not targets:
        raise ConfigurationError("at least one target URL is required")
    _validate_target_identities(targets)
    unknown = [name for name in components if name not in ADAPTERS]
    if unknown:
        raise ConfigurationError("unknown component(s): " + ", ".join(sorted(set(unknown))))
    context, executor, artifacts, audit = create_context(
        user_config=user_config,
        overrides=overrides,
        include_env=include_env,
        profile_id=profile_id,
        proxy=proxy,
        verbose=verbose,
        artifact_root=artifact_root,
    )
    for target in targets:
        executor.register_target(target.identity, url=target.url, proxy=target.proxy)
    context.output_dir = Path(output_dir).expanduser() if output_dir else Path.home() / ".surfacescope" / "reports"
    if report_format is None:
        report_format = str(context.config.section("reports").get("format", "json"))
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
    aggregate = ComponentResult()
    options = dict(adapter_options or {})
    ordered_components = _ordered_components(components)
    context.options["components"] = list(ordered_components)
    component_results: dict[str, ComponentResult] = {}
    try:
        for name in ordered_components:
            adapter = ADAPTERS[name]()
            context.logger.info("running component %s", name)
            try:
                result = adapter.scan(context, _targets_for_component(name, targets, context), options)
            except CancelledError:
                raise
            except Exception as exc:
                result = ComponentResult(errors=[f"{name}: {type(exc).__name__}: {exc}"])
            component_results[name] = result
            aggregate.findings.extend(result.findings)
            aggregate.errors.extend(result.errors)
            aggregate.artifacts.extend(result.artifacts)
            context.results.add_findings(result.findings)
        aggregate.stats["components"] = ordered_components
        aggregate.stats["component_stats"] = {name: result.stats for name, result in component_results.items()}
        aggregate.stats["audit"] = audit.summary()
        aggregate.stats["results"] = context.results.summary()
        run_meta = _build_run_meta(context, run_id, targets, ordered_components, audit, component_results)
        writer = ReportWriter(context.output_dir)
        report_paths = writer.write(run_id, aggregate, run_meta, fmt=report_format)
        aggregate.artifacts.extend(str(path) for path in report_paths)
        return PipelineResult(
            run_id=run_id,
            output_dir=context.output_dir,
            component_result=aggregate,
            report_paths=report_paths,
            run_meta=run_meta,
            component_results=component_results,
        )
    finally:
        executor.close()
        if artifact_root is None:
            artifacts.cleanup()


def _normalise_components(components: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in components:
        for part in str(item).split(","):
            name = part.strip().lower()
            if not name:
                continue
            canonical = "bypass403" if name == "bypass" else name
            if canonical not in ADAPTERS:
                raise ConfigurationError(f"unknown component: {name}")
            if canonical not in seen:
                seen.add(canonical)
                result.append(canonical)
    return result


def _validate_target_identities(targets: list[Target]) -> None:
    """Reject explicit target IDs that silently merge different auth contexts."""

    seen: dict[str, tuple[object, ...]] = {}
    for target in targets:
        signature = (
            canonical_url(target.url),
            target.auth_scope,
            tuple(sorted((str(key).lower(), str(value)) for key, value in target.headers.items())),
            tuple(sorted((str(key), str(value)) for key, value in target.cookies.items())),
            str(target.proxy or ""),
        )
        previous = seen.get(target.identity)
        if previous is not None and previous != signature:
            raise ConfigurationError(
                "duplicate target_id with different URL/auth context: "
                f"{target.target_id!r}; use a unique target_id per authenticated identity"
            )
        seen[target.identity] = signature


def _ordered_components(components: list[str]) -> list[str]:
    """Sort components by dependency while preserving the public set."""

    normalized = _normalise_components(components)
    rank = {name: index for index, name in enumerate(COMPONENT_ORDER)}
    return sorted(normalized, key=lambda name: (rank.get(name, len(rank)), name))


def _targets_for_component(name: str, targets: list[Target], context: Any) -> list[Target]:
    """Bind discovered blocked endpoints to the 403 stage exactly once."""

    if name != "bypass403":
        return targets

    by_identity = {target.identity: target for target in targets}
    by_source: dict[tuple[str, str], list[Target]] = {}
    by_origin: dict[str, list[Target]] = {}
    for target in targets:
        by_source.setdefault((canonical_url(target.url), target.auth_scope), []).append(target)
        by_origin.setdefault(origin(target.url), []).append(target)

    def unique_target(matches: list[Target]) -> Target | None:
        identities = {target.identity for target in matches}
        return matches[0] if len(identities) == 1 and matches else None

    blocked: list[Target] = []
    unverified: list[Target] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in context.results.findings():
        if finding.module == "bypass403" or finding.kind not in {
            "path",
            "endpoint",
            "js_asset",
            "packer_endpoint",
            "swagger_endpoint",
        }:
            continue
        candidate_url = str(finding.target or "")
        parts = urlsplit(candidate_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            continue
        source_target = str(finding.source_target or "")
        finding_scope = str(finding.auth_scope or finding.metadata.get("auth_scope") or "")
        finding_target_id = str(
            finding.target_id or finding.metadata.get("target_id") or ""
        )
        base = by_identity.get(finding_target_id) if finding_target_id else None
        if base is None and source_target and finding_scope:
            base = unique_target(
                by_source.get((canonical_url(source_target), finding_scope), [])
            )
        if base is None and source_target:
            source_matches = [
                target
                for (source_url, _scope), matches in by_source.items()
                if source_url == canonical_url(source_target)
                for target in matches
            ]
            base = unique_target(source_matches)
        if base is None:
            matching = [
                target
                for base_url, targets_for_origin in by_origin.items()
                if host_allowed(base_url, candidate_url)
                for target in targets_for_origin
            ]
            scoped = [target for target in matching if finding_scope and target.auth_scope == finding_scope]
            if len(scoped) == 1:
                matching = scoped
            identities = {target.identity for target in matching}
            # Never guess between two authenticated contexts for the same host.
            base = matching[0] if len(identities) == 1 and matching else None
        if base is None:
            continue
        try:
            status = int(
                finding.metadata.get("status")
                or finding.response_summary.get("status")
                or 0
            )
        except (TypeError, ValueError):
            status = 0
        candidate = replace(
            base,
            url=canonical_url(candidate_url),
            target_id=base.identity,
            scope=finding.metadata.get("auth_scope") or base.auth_scope,
        )
        key = (candidate.target_id, candidate.url, candidate.auth_scope)
        if key not in seen:
            seen.add(key)
            if status in (401, 403):
                blocked.append(candidate)
            elif finding.kind in {"endpoint", "packer_endpoint", "swagger_endpoint"}:
                unverified.append(candidate)

    has_discovery = bool(_DISCOVERY_COMPONENTS.intersection(context.options.get("components", ())))
    if not has_discovery:
        return blocked or unverified or targets
    limit = max(1, int(context.config.section("bypass").get("max_targets", 400)))
    return (blocked + unverified)[:limit]


def _build_run_meta(
    context: Any,
    run_id: str,
    targets: list[Target],
    components: list[str],
    audit: RequestAudit,
    component_results: dict[str, ComponentResult],
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": [target.url for target in targets],
        "components": _normalise_components(components),
        "profile": context.profile.id,
        "config_sources": list(getattr(context.config, "sources", ())),
        "capabilities": context.capabilities.to_dict(),
        "audit": audit.summary(),
        "results": context.results.summary(),
        "component_stats": {name: result.stats for name, result in component_results.items()},
    }
