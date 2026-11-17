"""Deterministic human-readable terminal rendering for one scan result.

The renderer is intentionally dependency-free and never reads request bodies,
cookies or authorization values. It is a presentation layer only: findings,
stats and errors remain owned by ``PipelineResult``.
"""

from __future__ import annotations

import ctypes
import os
import sys
from typing import TYPE_CHECKING, Any, TextIO

from . import __version__

if TYPE_CHECKING:
    from .models import ComponentResult, Finding
    from .pipeline import PipelineResult


_COMPONENT_TITLES = {
    "dirsearch": "DIRSEARCH / PATH DISCOVERY",
    "jsfinder": "JSFINDER / JS & ENDPOINTS",
    "packer": "PACKER / WEBPACK ANALYSIS",
    "swagger": "SWAGGER / OPENAPI",
    "bypass403": "BYPASS403 / ACCESS CONTROL",
    "finger": "FINGER / TECHNOLOGY",
}

_LIMIT_FLAGS = (
    ("budget_stopped", "request budget stopped the stage"),
    ("time_limit_reached", "stage time limit reached"),
    ("job_limit_reached", "job limit reached"),
    ("request_limit_reached", "stage request limit reached"),
    ("probe_limit_reached", "endpoint probe limit reached"),
)


class _Palette:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap(text, "1")

    def dim(self, text: str) -> str:
        return self._wrap(text, "2")

    def green(self, text: str) -> str:
        return self._wrap(text, "32")

    def yellow(self, text: str) -> str:
        return self._wrap(text, "33")

    def red(self, text: str) -> str:
        return self._wrap(text, "31")

    def cyan(self, text: str) -> str:
        return self._wrap(text, "36")

    def magenta(self, text: str) -> str:
        return self._wrap(text, "35")

    def status(self, status: int, text: str) -> str:
        if 200 <= status < 300:
            return self.green(text)
        if 300 <= status < 400:
            return self.cyan(text)
        if status in (401, 403):
            return self.yellow(text)
        if status >= 400:
            return self.red(text)
        return self.dim(text)


def _clean(value: Any, limit: int | None = None) -> str:
    """Strip control characters so untrusted target data cannot drive a terminal."""

    text = "".join(
        character if character >= " " and character != "\x7f" else " "
        for character in ("" if value is None else str(value))
    )
    text = " ".join(text.split())
    if limit is not None and len(text) > limit:
        return text[: max(0, limit - 3)] + "..."
    return text


def _format_size(value: Any) -> str:
    try:
        size = max(0, int(value))
    except (TypeError, ValueError):
        return "-"
    if size < 1024:
        return f"{size}B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f}KB"
    return f"{size / (1024 * 1024):.1f}MB"


def _finding_status(finding: Finding) -> int:
    for source in (finding.metadata, finding.response_summary):
        if not isinstance(source, dict):
            continue
        value = source.get("status")
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return 0


def _finding_length(finding: Finding) -> Any:
    for source in (finding.response_summary, finding.metadata):
        if isinstance(source, dict) and source.get("length") is not None:
            return source["length"]
    return None


def _badge(finding: Finding, palette: _Palette) -> str:
    status = _finding_status(finding)
    if status:
        return palette.status(status, f"[{status}]")
    return palette.dim("[----]")


def _clean_target(finding: Finding) -> str:
    return _clean(finding.target, 500)


def _evidence(finding: Finding, limit: int = 220) -> str:
    return _clean(finding.evidence, limit)


def _finding_line(finding: Finding, palette: _Palette) -> str:
    module = finding.module
    kind = finding.kind
    target = _clean_target(finding)
    status_badge = _badge(finding, palette)
    size = _format_size(_finding_length(finding))
    confidence = f"{float(finding.confidence):.2f}"
    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}

    if module == "dirsearch" and kind == "path":
        return f"{status_badge} {size:>8}  {target}  conf={confidence}"

    if module == "jsfinder":
        if kind == "js_asset":
            return f"{status_badge} {size:>8}  [JS] {target}"
        if kind == "endpoint":
            return f"{palette.cyan('[URL]')} {target}  conf={confidence}"

    if module == "finger" and kind == "fingerprint":
        cms = _clean(metadata.get("cms") or "unknown", 80)
        version = _clean(metadata.get("version") or "", 50)
        suffix = f" {version}" if version else ""
        evidence = _evidence(finding, 100)
        tail = f"  {evidence}" if evidence else ""
        return f"{status_badge} [{cms}{suffix}]  {target}  conf={confidence}{tail}"

    if module == "bypass403" and kind == "403_bypass":
        technique = _clean(finding.technique or metadata.get("category") or "variant", 80)
        method = _clean(finding.method or "GET", 12).upper()
        decision = _clean(metadata.get("decision") or "", 100)
        tail = f"  ({decision})" if decision else ""
        return f"{status_badge} [{technique}] {method} {target}  conf={confidence}{tail}"

    if module == "swagger":
        if kind == "swagger_document":
            return (
                f"{status_badge} [OPENAPI] {target}  "
                f"spec={_clean(metadata.get('spec_version') or 'unknown', 30)} "
                f"paths={_clean(metadata.get('path_count', 0), 12)}"
            )
        if kind == "swagger_endpoint":
            verified = bool(metadata.get("verified"))
            state = "verified" if verified else "declared"
            method = _clean(finding.method or "GET", 12).upper()
            return f"{status_badge} [{method}] {target}  {state}  conf={confidence}"

    if module == "packer":
        if kind == "packer_secret":
            secret_kind = _clean(metadata.get("secret_kind") or "secret", 80)
            return f"{palette.magenta('[SECRET]')} [{secret_kind}] {target}  {_evidence(finding)}"
        if kind == "packer_endpoint":
            verified = bool(metadata.get("verified"))
            state = "verified" if verified else "extracted"
            method = _clean(finding.method or "GET", 12).upper()
            return f"{status_badge} [{method}] {target}  {state}  conf={confidence}"
        if kind == "packer_cors":
            return f"{status_badge} [CORS] {target}  {_evidence(finding)}"
        if kind == "packer_unauthorized":
            return f"{status_badge} [UNAUTH] {target}  {_evidence(finding)}"
        if kind == "packer_sqli":
            return f"{status_badge} [SQLI] {target}  {_evidence(finding)}"
        if kind == "packer_asset":
            return f"{status_badge} {size:>8}  [ASSET] {target}"
        if kind == "packer_detected":
            markers = _clean(metadata.get("markers") or evidence_marker(finding), 100)
            return f"{palette.cyan('[PACKER]')} {target}  markers={markers or '-'}"
        if kind.endswith("_surface"):
            surface = _clean(metadata.get("surface") or kind.removesuffix("_surface"), 60)
            return f"{palette.yellow('[SURFACE]')} [{surface}] {target}  {_evidence(finding)}"

    label = _clean(kind.replace("_", " ").upper(), 40)
    method = _clean(finding.method or "GET", 12).upper()
    extra = _evidence(finding)
    tail = f"  {extra}" if extra else ""
    return f"{status_badge} [{label}] {method} {target}  conf={confidence}{tail}"


def evidence_marker(finding: Finding) -> str:
    """Return a short marker summary for a detection finding."""

    return _clean(finding.evidence, 100)


def _source_count(finding: Finding) -> int:
    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    for key in ("occurrences", "sources", "provenance"):
        value = metadata.get(key)
        if isinstance(value, list):
            return len(value)
        try:
            count = int(value)
        except (TypeError, ValueError):
            continue
        return max(1, count)
    return 1


def _budget_text(budget: object) -> str:
    """Render total and worst-case per-host usage for one budget scope."""

    if not isinstance(budget, dict) or not budget.get("configured"):
        return ""
    parts: list[str] = []
    max_per_host = budget.get("max_per_host")
    if max_per_host:
        by_host = budget.get("by_host")
        values = [int(value) for value in by_host.values()] if isinstance(by_host, dict) else []
        host_used = max(values, default=0)
        parts.append(f"host={_clean(host_used, 20)}/{_clean(max_per_host, 20)}")
    parts.append(
        f"total={_clean(budget.get('total', 0), 20)}/{_clean(budget.get('max_total', '-'), 20)}"
    )
    return "  ".join(parts)


def _stat_text(name: str, stats: dict[str, Any]) -> str:
    parts: list[str] = []

    def add(label: str, key: str) -> None:
        value = stats.get(key)
        if value is not None and value != "":
            parts.append(f"{label}={_clean(value, 80)}")

    if name == "dirsearch":
        add("wordlist", "wordlist")
        add("candidates", "candidates")
        add("tested", "tested")
        add("found", "findings")
        add("blocked", "blocked")
        add("requests", "network_requests")
        add("cache", "cache_hit")
        if stats.get("recursive_directories"):
            add("recursive_dirs", "recursive_directories")
    elif name == "jsfinder":
        add("targets", "targets")
        add("assets", "assets")
        add("endpoints", "endpoints")
        add("findings", "findings")
    elif name == "finger":
        add("rules", "rules")
        add("pages", "pages_probed")
        add("skipped", "skipped_unusable_pages")
        add("favicons", "favicon_requests")
        add("matches", "matches")
        add("findings", "findings")
    elif name == "bypass403":
        add("mode", "mode")
        add("targets", "targets")
        add("generated", "generated_variants")
        add("initial", "candidate_variants")
        add("tested", "variants_tested")
        add("accepted", "accepted")
        add("skipped", "skipped_not_blocked")
        add("requests", "network_requests")
        budget = stats.get("request_budget")
        budget_text = _budget_text(budget)
        if budget_text:
            parts.append("budget " + budget_text)
    elif name == "swagger":
        add("documents", "documents_fetched")
        add("parsed", "documents_parsed")
        add("endpoints", "endpoints")
        add("requests", "requests")
        add("skipped_unsafe", "skipped_unsafe")
    elif name == "packer":
        add("assets", "assets")
        add("endpoints", "endpoints")
        add("probed", "probed_endpoints")
        add("secrets", "secrets_found")
        add("active_requests", "active_requests")
        add("surfaces", "surface_candidates")

    return "  ".join(parts)


def _render_component(index: int, name: str, result: ComponentResult, palette: _Palette) -> list[str]:
    title = _COMPONENT_TITLES.get(name, name.upper())
    state = palette.green("OK") if result.ok else palette.red(f"ERRORS ({len(result.errors)})")
    lines = ["", f"{palette.bold(f'[{index}] {title}')}  {state}"]
    stats = result.stats if isinstance(result.stats, dict) else {}
    stat_text = _stat_text(name, stats)
    if stat_text:
        lines.append("    " + palette.dim(stat_text))
    for finding in result.findings:
        line = _finding_line(finding, palette)
        source_count = _source_count(finding)
        if source_count > 1:
            line += "  " + palette.dim(f"sources={source_count}")
        lines.append("    " + line)
    if not result.findings:
        lines.append("    " + palette.dim("(no findings)"))
    for key, label in _LIMIT_FLAGS:
        if stats.get(key):
            lines.append("    " + palette.yellow(f"[!] {label}"))
    for error in result.errors:
        lines.append("    " + palette.red(f"[!] {_clean(error, 280)}"))
    return lines


def _render_summary(result: PipelineResult, palette: _Palette) -> list[str]:
    lines = ["", palette.bold("SUMMARY")]
    findings = len(result.component_result.findings)
    errors = len(result.component_result.errors)
    audit = (result.run_meta or {}).get("audit") or {}
    counts = audit.get("counts") if isinstance(audit, dict) else {}
    counts = counts if isinstance(counts, dict) else {}
    network = counts.get("network_sent", 0)
    cache_hits = counts.get("cache_hit", 0)
    lines.append(
        "    "
        + f"findings={findings}  errors={errors}  "
        + f"network={_clean(network, 20)}  cache_hits={_clean(cache_hits, 20)}"
    )
    bypass = (result.component_results or {}).get("bypass403")
    if bypass is not None:
        stats = bypass.stats if isinstance(bypass.stats, dict) else {}
        budget = stats.get("request_budget")
        budget_text = _budget_text(budget)
        if budget_text:
            lines.append(
                "    "
                + palette.dim(
                    f"bypass403 budget {budget_text}  "
                    f"mode={_clean(stats.get('mode', 'fast'), 20)}"
                )
            )
    if result.report_paths:
        lines.append("    " + palette.bold("reports"))
        for path in result.report_paths:
            lines.append("      " + _clean(path, 1000))
    if errors:
        lines.append("    " + palette.yellow("some stages returned errors; inspect the component sections above"))
    lines.append(
        "    "
        + palette.dim(
            "safe defaults: active write probes, SQLi, source-map fetches and verbose CORS checks remain opt-in"
        )
    )
    return lines


def _ansi_enabled(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR", "") not in ("", "0"):
        return True
    if not bool(getattr(stream, "isatty", lambda: False)()):
        return False
    if os.name != "nt":
        return True
    if stream not in (sys.stdout, sys.stderr):
        return True
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11 if stream is sys.stdout else -12)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError):
        pass
    return False


def render_scan_result(result: PipelineResult, *, color: bool = False) -> str:
    """Return the complete terminal report as a deterministic string."""

    palette = _Palette(color)
    meta = result.run_meta or {}
    lines = [palette.bold(f"SurfaceScope {__version__}")]
    targets = meta.get("targets") or []
    if targets:
        lines.append("  " + palette.dim("targets: " + ", ".join(_clean(item, 500) for item in targets)))
    run_id = _clean(meta.get("run_id") or result.run_id, 100)
    profile = _clean(meta.get("profile") or "-", 100)
    components = meta.get("components") or list((result.component_results or {}).keys())
    lines.append(f"  {palette.dim('run:')} {run_id}  {palette.dim('profile:')} {profile}")
    lines.append(f"  {palette.dim('components:')} {', '.join(_clean(item, 80) for item in components)}")

    component_results = result.component_results or {}
    ordered = [name for name in components if name in component_results]
    if not ordered:
        ordered = list(component_results)
    for index, name in enumerate(ordered, 1):
        lines.extend(_render_component(index, name, component_results[name], palette))
    lines.extend(_render_summary(result, palette))
    return "\n".join(lines) + "\n"


def write_scan_result(
    result: PipelineResult,
    *,
    stream: TextIO | None = None,
    color: bool | None = None,
) -> None:
    """Write a scan result to ``stream`` with TTY-aware color selection."""

    target_stream = stream or sys.stdout
    enabled = _ansi_enabled(target_stream) if color is None else bool(color)
    target_stream.write(render_scan_result(result, color=enabled))
    target_stream.flush()


__all__ = ["render_scan_result", "write_scan_result"]
