"""Dirsearch 0.4.3-compatible path discovery on the shared request executor.

The adapter preserves the useful 0.4.3 behaviors: wordlist expansion, status
filtering, soft-404 calibration and optional recursion. It deliberately does
not retain the legacy private session, scheduler, report writer or CWD queues.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..components.dirsearch import expand_words
from ..context import ScanContext
from ..errors import BudgetExceeded
from ..models import ComponentResult, Finding, ResponseSnapshot, Target
from ..quality.qc import QualityController
from .base import ComponentAdapter

_TARGET_PROFILES = {
    "grafana": "wordlist.targets.grafana",
    "spring-boot": "wordlist.targets.spring_boot_actuator",
    "spring_boot": "wordlist.targets.spring_boot_actuator",
    "springboot": "wordlist.targets.spring_boot_actuator",
    "actuator": "wordlist.targets.spring_boot_actuator",
}


def _random_path() -> str:
    return "/.surfacescope-" + secrets.token_hex(8)


def _candidate_url(base: str, path: str) -> str:
    if not path:
        return base
    return base.rstrip("/") + "/" + path.lstrip("/")


@dataclass(frozen=True, slots=True)
class _Baseline:
    first: ResponseSnapshot | None
    second: ResponseSnapshot | None = None


class DirsearchAdapter(ComponentAdapter):
    name = "dirsearch"

    def scan(self, context: ScanContext, targets: list[Target], options: dict) -> ComponentResult:
        result = ComponentResult()
        settings = context.config.section("dirsearch")
        wordlist_id = options.get("wordlist") or settings.get("wordlist", "wordlist.paths.dicc")
        words = context.wordlists.lines(wordlist_id)
        target_profiles = [
            str(value).strip().lower()
            for value in (options.get("target_profiles") or settings.get("target_profiles", []))
            if str(value).strip()
        ]
        target_words: list[str] = []
        resolved_target_profiles: list[str] = []
        for profile in target_profiles:
            asset_id = _TARGET_PROFILES.get(profile)
            if asset_id is None:
                raise ValueError(f"unknown target profile: {profile}")
            target_words.extend(context.wordlists.lines(asset_id))
            resolved_target_profiles.append(profile)
        if target_words:
            words = list(dict.fromkeys([*target_words, *words]))
        extensions = list(options.get("extensions") or settings.get("extensions", []))
        prefixes = list(options.get("prefixes") or settings.get("prefixes", []))
        suffixes = list(options.get("suffixes") or settings.get("suffixes", []))
        force_extensions = list(options.get("force_extensions") or settings.get("force_extensions", []))
        exclude_extensions = list(options.get("exclude_extensions") or settings.get("exclude_extensions", []))
        candidates = expand_words(
            words,
            extensions,
            prefixes,
            suffixes,
            force_extensions,
            exclude_extensions,
        )
        max_candidates = max(0, int(options.get("max_candidates") or settings.get("max_candidates", 0)))
        if max_candidates:
            candidates = candidates[:max_candidates]
        max_jobs = max(0, int(options.get("max_jobs") or settings.get("max_jobs", 200000)))
        include_statuses = {
            int(value)
            for value in (options.get("include_statuses") or settings.get("include_statuses", []))
        }
        exclude_statuses = {
            int(value)
            for value in (options.get("exclude_statuses") or settings.get("exclude_statuses", []))
        }
        redirect_exclusions = [
            re.compile(str(value), re.IGNORECASE)
            for value in (options.get("exclude_redirects") or settings.get("exclude_redirects", []))
            if str(value)
        ]
        threads = max(1, int(options.get("threads") or context.config.section("run").get("threads", 25)))
        recursive = bool(options.get("recursive", settings.get("recursive", False)))
        max_depth = max(1, int(options.get("max_depth", settings.get("max_depth", 1))))
        max_recursive_dirs = max(0, int(settings.get("max_recursive_dirs", 100)))
        max_time = max(0.0, float(options.get("max_time") or settings.get("max_time", 0.0)))
        deadline = time.monotonic() + max_time if max_time else None
        min_response_size = max(0, int(options.get("min_response_size") or settings.get("min_response_size", 0)))
        max_response_size = max(0, int(options.get("max_response_size") or settings.get("max_response_size", 0)))
        qc = QualityController(
            include_statuses or None,
            status_suffix_filters=context.wordlists.status_suffix_filters("blacklist.status.codes"),
        )
        baselines: dict[tuple[str, str], _Baseline] = {}
        roots: list[tuple[Target, str]] = []
        seen_roots: set[tuple[str, str]] = set()
        for target in targets:
            base = target.url.rstrip("/") + "/"
            key = (target.identity, base)
            if key not in seen_roots:
                seen_roots.add(key)
                roots.append((target, base))
        network_before = context.executor.audit.counts().get("network_sent", 0)
        cache_hit_before = context.executor.audit.counts().get("cache_hit", 0)
        for target, base in roots:
            baselines[(target.identity, base)] = self._collect_baseline(context, target, base, result)
            if result.stats.get("budget_stopped"):
                break

        jobs: list[tuple[Target, str, str, int]] = [
            (target, base, candidate, 0)
            for target, base in roots
            for candidate in candidates
        ]
        if max_jobs and len(jobs) > max_jobs:
            jobs = jobs[:max_jobs]
            result.stats["job_limit_reached"] = True
        scheduled_jobs = len(jobs)
        seen_jobs: set[tuple[str, str, str, int]] = set()
        recursive_dirs = 0
        blocked = 0
        tested = 0
        timed_out = False
        budget_stopped = bool(result.stats.get("budget_stopped"))

        def probe_job(job):
            target, base, path, depth = job
            try:
                finding, snapshot = self._probe(
                    context,
                    target,
                    base,
                    path,
                    baselines.get((target.identity, base)),
                    qc,
                    include_statuses,
                    exclude_statuses,
                    redirect_exclusions,
                    min_response_size,
                    max_response_size,
                )
                return job, finding, snapshot, None
            except Exception as exc:
                return job, None, None, exc

        pending = [] if budget_stopped else jobs
        while pending and not timed_out and not budget_stopped:
            next_pending: list[tuple[Target, str, str, int]] = []
            for job, finding, snapshot, exc in context.executor.run_many(probe_job, pending, max_workers=threads):
                if deadline is not None and time.monotonic() >= deadline:
                    timed_out = True
                    break
                target, base, path, depth = job
                marker = (target.identity, base, path, depth)
                if marker in seen_jobs:
                    continue
                seen_jobs.add(marker)
                if isinstance(exc, BudgetExceeded):
                    result.stats["budget_stopped"] = True
                    budget_stopped = True
                    break
                if exc is not None:
                    result.errors.append(f"{base}{path}: {exc}")
                    continue
                tested += 1
                if snapshot is not None:
                    context.results.add_snapshot(snapshot)
                if finding is None:
                    continue
                result.findings.append(finding)
                if finding.metadata.get("status") in (401, 403):
                    blocked += 1
                if (
                    recursive
                    and depth < max_depth
                    and finding.metadata.get("directory")
                    and (not max_recursive_dirs or recursive_dirs < max_recursive_dirs)
                ):
                    recursive_dirs += 1
                    child_base = finding.target.rstrip("/") + "/"
                    if (target.identity, child_base) not in baselines:
                        baselines[(target.identity, child_base)] = self._collect_baseline(
                            context,
                            target,
                            child_base,
                            result,
                        )
                        if result.stats.get("budget_stopped"):
                            budget_stopped = True
                            break
                    for candidate in candidates:
                        if max_jobs and scheduled_jobs >= max_jobs:
                            result.stats["job_limit_reached"] = True
                            break
                        child = (target, child_base, candidate, depth + 1)
                        if (child[0].identity, child[1], child[2], child[3]) not in seen_jobs:
                            next_pending.append(child)
                            scheduled_jobs += 1
            pending = next_pending

        if timed_out and not budget_stopped:
            result.stats["time_limit_reached"] = True
        audit_counts = context.executor.audit.counts()
        network_after = audit_counts.get("network_sent", 0)
        result.stats.update(
            {
                "wordlist": wordlist_id,
                "target_profiles": resolved_target_profiles,
                "candidates": len(candidates),
                "targets": len(targets),
                "tested": tested,
                "findings": len(result.findings),
                "blocked": blocked,
                "recursive_directories": recursive_dirs,
                "network_requests": max(0, network_after - network_before),
                "cache_hit": max(0, audit_counts.get("cache_hit", 0) - cache_hit_before),
            }
        )
        return result

    def _collect_baseline(
        self,
        context: ScanContext,
        target: Target,
        base: str,
        result: ComponentResult,
    ) -> _Baseline:
        snapshots: list[ResponseSnapshot | None] = [None, None]
        for index in range(2):
            try:
                snapshot = context.executor.get(
                    _candidate_url(base, _random_path()),
                    target_id=target.identity,
                    budget_scope="dirsearch",
                    profile_id=context.profile.id,
                    purpose="navigation",
                    headers=target.headers,
                    cookies=target.cookies,
                    auth_scope=target.auth_scope,
                    auth_origin=target.origin,
                    cache_policy="no-store",
                )
            except BudgetExceeded:
                result.stats["budget_stopped"] = True
                break
            except Exception as exc:
                result.errors.append(f"baseline failed for {base}: {exc}")
                continue
            context.results.add_snapshot(snapshot)
            snapshots[index] = snapshot
        return _Baseline(snapshots[0], snapshots[1])

    def _probe(
        self,
        context: ScanContext,
        target: Target,
        base: str,
        path: str,
        baseline: _Baseline | None,
        qc: QualityController,
        include_statuses: set[int],
        exclude_statuses: set[int],
        redirect_exclusions: list[re.Pattern[str]],
        min_response_size: int,
        max_response_size: int,
    ) -> tuple[Finding | None, ResponseSnapshot]:
        url = _candidate_url(base, path)
        snapshot = context.executor.get(
            url,
            target_id=target.identity,
            budget_scope="dirsearch",
            profile_id=context.profile.id,
            purpose="navigation",
            headers=target.headers,
            cookies=target.cookies,
            auth_scope=target.auth_scope,
            auth_origin=target.origin,
        )
        decision = qc.discovery(
            snapshot,
            baseline.first if baseline is not None else None,
            include_statuses or None,
        )
        if decision.accepted and exclude_statuses and snapshot.status in exclude_statuses:
            decision = type(decision)(False, "status excluded", 0.0)
        if (
            decision.accepted
            and baseline is not None
            and baseline.second is not None
            and qc.is_soft_404(snapshot, baseline.second)
        ):
            decision = type(decision)(False, "matches second wildcard baseline", 0.0)
        if decision.accepted and redirect_exclusions and 300 <= snapshot.status < 400:
            location = snapshot.header("location")
            if any(pattern.search(location) for pattern in redirect_exclusions):
                decision = type(decision)(False, "redirect excluded", 0.0)
        if decision.accepted and min_response_size and snapshot.length < min_response_size:
            decision = type(decision)(False, "response below minimum size", 0.0)
        if decision.accepted and max_response_size and snapshot.length > max_response_size:
            decision = type(decision)(False, "response above maximum size", 0.0)
        if not decision.accepted:
            return None, snapshot
        path_part = urlsplit(snapshot.final_url).path
        directory = path.endswith("/") or path_part.endswith("/")
        finding = Finding(
            module=self.name,
            kind="path",
            target=url,
            target_id=target.identity,
            auth_scope=target.auth_scope,
            method="GET",
            severity="info",
            confidence=decision.confidence,
            technique="wordlist",
            evidence=f"status={snapshot.status}; length={snapshot.length}; reason={decision.reason}",
            request_summary={"method": "GET", "url": url},
            response_summary={
                "status": snapshot.status,
                "length": snapshot.length,
                "content_type": snapshot.content_type,
            },
            metadata={
                "status": snapshot.status,
                "directory": directory,
                "sample": snapshot.text[:240],
                "source_target": target.url,
                "auth_scope": target.auth_scope,
            },
            source_target=target.url,
        )
        return finding, snapshot
