#!/usr/bin/env python3
"""Measure and compare SurfaceScope quality baselines.

The tool deliberately keeps measurement and policy separate:

* coverage comes from ``coverage.py`` JSON output;
* request budgets come from the real executor audit counters while a local
  loopback scan is running;
* latency is measured with repeated local-only runs and stored as a median;
* a baseline is environment-scoped, so a Linux timing is not treated as a
  Windows performance result.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import platform
import statistics
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from surfacescope import pipeline  # noqa: E402
from surfacescope.adapters.bypass403_adapter import Bypass403Adapter  # noqa: E402
from surfacescope.models import Target  # noqa: E402

DEFAULT_BASELINE = ROOT / "docs" / "QUALITY_BASELINE.json"
DEFAULT_COVERAGE = ROOT / "artifacts" / "coverage.json"
DEFAULT_MODULE_STATEMENTS = 40
COVERAGE_TOLERANCE = 0.5
PERFORMANCE_TOLERANCE = 2.5

Responder = Callable[[str, object, str], tuple[int, str, dict[str, str]]]


def _reply(status: int, body: str, **headers: str) -> tuple[int, str, dict[str, str]]:
    return status, body, headers


def _is_qc(path: str) -> bool:
    return path.startswith("/.surfacescope-qc-")


def _uniform_denial(_path: str, _headers: object, _method: str) -> tuple[int, str, dict[str, str]]:
    return _reply(403, "denied")


def _trailing_slash(path: str, _headers: object, _method: str) -> tuple[int, str, dict[str, str]]:
    if _is_qc(path):
        return _reply(403, "denied")
    if path == "/admin/":
        return _reply(200, "admin console")
    if path == "/":
        return _reply(404, "root not found")
    return _reply(403, "denied")


def _xff(path: str, headers: object, _method: str) -> tuple[int, str, dict[str, str]]:
    if _is_qc(path):
        return _reply(403, "denied")
    if headers.get("X-Forwarded-For") == "127.0.0.1":
        return _reply(200, "admin console")
    if path == "/":
        return _reply(404, "root not found")
    return _reply(403, "denied")


@dataclass(frozen=True)
class ProbeScenario:
    name: str
    responder: Responder
    expected_requests: int


SCENARIOS = (
    ProbeScenario("uniform_403", _uniform_denial, 29),
    ProbeScenario("trailing_slash", _trailing_slash, 4),
    ProbeScenario("xff", _xff, 3),
)


@contextlib.contextmanager
def _serve(responder: Responder) -> Iterator[tuple[str, list[tuple[str, str]]]]:
    hits: list[tuple[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def _dispatch(self) -> None:
            hits.append((self.command, self.path))
            status, body, headers = responder(self.path, self.headers, self.command)
            payload = body.encode("utf-8")
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        do_GET = _dispatch
        do_POST = _dispatch
        do_PUT = _dispatch
        do_PATCH = _dispatch
        do_DELETE = _dispatch
        do_OPTIONS = _dispatch
        do_HEAD = _dispatch
        do_TRACE = _dispatch

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", hits
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def environment_snapshot() -> dict[str, str]:
    return {
        "os": platform.system().lower(),
        "python": platform.python_version(),
        "branch_coverage": "true",
    }


def environment_key(snapshot: dict[str, Any]) -> tuple[str, str, str]:
    """Return the environment identity relevant to the latency policy."""

    python_version = str(snapshot.get("python", ""))
    python_minor = ".".join(python_version.split(".")[:2])
    return (
        str(snapshot.get("os", "")).strip().lower(),
        python_minor,
        str(snapshot.get("branch_coverage", "")).strip().lower(),
    )


def environment_matches(baseline: dict[str, Any], current: dict[str, Any]) -> bool:
    if not baseline:
        return True
    return environment_key(baseline) == environment_key(current)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"file does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def coverage_snapshot(data: dict[str, Any], *, min_statements: int = DEFAULT_MODULE_STATEMENTS) -> dict[str, Any]:
    totals = data.get("totals") or {}
    try:
        overall = round(float(totals["percent_covered"]), 2)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("coverage JSON is missing totals.percent_covered") from exc
    modules: dict[str, dict[str, float | int]] = {}
    for name, info in (data.get("files") or {}).items():
        summary = info.get("summary") if isinstance(info, dict) else None
        if not isinstance(summary, dict):
            continue
        statements = int(summary.get("num_statements", 0))
        if statements < min_statements:
            continue
        modules[str(name)] = {
            "percent": round(float(summary.get("percent_covered", 0.0)), 2),
            "statements": statements,
        }
    return {
        "overall_percent": overall,
        "num_statements": int(totals.get("num_statements", 0)),
        "num_branches": int(totals.get("num_branches", 0)),
        "modules": dict(sorted(modules.items())),
    }


def compare_coverage(
    current: dict[str, Any],
    baseline: dict[str, Any],
    *,
    tolerance: float = COVERAGE_TOLERANCE,
) -> list[str]:
    errors: list[str] = []
    base_overall = float(baseline.get("overall_percent", 0.0))
    current_overall = float(current.get("overall_percent", 0.0))
    if current_overall + tolerance < base_overall:
        errors.append(f"overall coverage regressed: {current_overall:.2f}% < {base_overall:.2f}%")
    base_modules = baseline.get("modules") or {}
    current_modules = current.get("modules") or {}
    for name, item in base_modules.items():
        expected = float(item.get("percent", 0.0)) if isinstance(item, dict) else float(item)
        actual_item = current_modules.get(name)
        if not isinstance(actual_item, dict):
            errors.append(f"coverage module disappeared: {name}")
            continue
        actual = float(actual_item.get("percent", 0.0))
        if actual + tolerance < expected:
            errors.append(f"module coverage regressed: {name}: {actual:.2f}% < {expected:.2f}%")
    return errors


def run_probe(runs: int = 3) -> dict[str, Any]:
    if runs < 1:
        raise ValueError("runs must be at least 1")
    results: dict[str, list[float]] = {scenario.name: [] for scenario in SCENARIOS}
    budgets: dict[str, int] = {}
    for scenario in SCENARIOS:
        for _ in range(runs):
            with _serve(scenario.responder) as (base, hits):
                context, executor, _, _ = pipeline.create_context(include_env=False, artifact_root=None)
                started = time.perf_counter()
                try:
                    result = Bypass403Adapter().scan(
                        context,
                        [Target(url=base + "/admin")],
                        {"mode": "fast"},
                    )
                finally:
                    executor.close()
                elapsed = time.perf_counter() - started
            network_requests = int(result.stats.get("network_requests", -1))
            if network_requests != len(hits):
                raise ValueError(
                    f"{scenario.name}: executor counted {network_requests}, server saw {len(hits)}"
                )
            if network_requests != scenario.expected_requests:
                raise ValueError(
                    f"{scenario.name}: expected {scenario.expected_requests} requests, got {network_requests}"
                )
            results[scenario.name].append(elapsed)
            budgets[scenario.name] = network_requests
    return {
        "runs": runs,
        "request_budget": budgets,
        "latency_seconds": {
            name: round(statistics.median(values), 4) for name, values in results.items()
        },
    }


def compare_probe(current: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    expected_budget = baseline.get("request_budget") or {}
    actual_budget = current.get("request_budget") or {}
    for name, expected in expected_budget.items():
        actual = actual_budget.get(name)
        if actual != expected:
            errors.append(f"request budget changed: {name}: {actual!r} != {expected!r}")
    base_latency = baseline.get("latency_seconds") or {}
    actual_latency = current.get("latency_seconds") or {}
    base_env = baseline.get("environment") or {}
    if not environment_matches(base_env, environment_snapshot()):
        return errors + ["performance baseline environment differs; run --record on this environment"]
    for name, expected in base_latency.items():
        actual = float(actual_latency.get(name, 0.0))
        limit = float(expected) * PERFORMANCE_TOLERANCE
        if actual > limit:
            errors.append(
                f"latency regression: {name}: {actual:.4f}s > {limit:.4f}s "
                f"({PERFORMANCE_TOLERANCE:.1f}x baseline)"
            )
    return errors


def make_baseline(coverage: dict[str, Any], probe: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "captured_at": date.today().isoformat(),
        "environment": environment_snapshot(),
        "coverage": coverage,
        "request_budget": probe["request_budget"],
        "latency_seconds": probe["latency_seconds"],
        "probe_runs": probe["runs"],
        "tolerances": {
            "coverage_points": COVERAGE_TOLERANCE,
            "latency_factor": PERFORMANCE_TOLERANCE,
        },
    }


def run_coverage(pytest_args: list[str] | None = None) -> dict[str, Any]:
    command = [sys.executable, "-m", "coverage", "run", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    command.extend(pytest_args or [])
    subprocess.run(command, cwd=ROOT, check=True)
    json_path = DEFAULT_COVERAGE
    json_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [sys.executable, "-m", "coverage", "json", "-o", str(json_path)],
        cwd=ROOT,
        check=True,
    )
    return load_json(json_path)


def evaluate(
    current_coverage: dict[str, Any],
    current_probe: dict[str, Any] | None,
    baseline: dict[str, Any],
) -> list[str]:
    errors = compare_coverage(current_coverage, baseline.get("coverage") or {})
    if current_probe is not None:
        baseline_probe = {
            "request_budget": baseline.get("request_budget") or {},
            "latency_seconds": baseline.get("latency_seconds") or {},
            "environment": baseline.get("environment") or {},
        }
        errors.extend(compare_probe(current_probe, baseline_probe))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SurfaceScope quality baseline checker")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--coverage-json", type=Path, default=DEFAULT_COVERAGE)
    parser.add_argument("--run-coverage", action="store_true", help="run coverage.py before checking")
    parser.add_argument("--record", action="store_true", help="write the current measurements as baseline")
    parser.add_argument("--runs", type=int, default=3, help="loopback latency repetitions")
    parser.add_argument("--no-probe", action="store_true", help="skip loopback request/latency checks")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.run_coverage:
            coverage_data = coverage_snapshot(run_coverage())
        else:
            coverage_data = coverage_snapshot(load_json(args.coverage_json))
        probe = None if args.no_probe else run_probe(args.runs)
        if args.record:
            if probe is None:
                raise ValueError("--record requires the loopback probe; remove --no-probe")
            baseline = make_baseline(coverage_data, probe)
            args.baseline.parent.mkdir(parents=True, exist_ok=True)
            args.baseline.write_text(json.dumps(baseline, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"quality baseline written: {args.baseline}")
            return 0
        baseline_data = load_json(args.baseline)
        errors = evaluate(coverage_data, probe, baseline_data)
        report = {
            "baseline": str(args.baseline),
            "coverage": coverage_data,
            "probe": probe,
            "errors": errors,
        }
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if errors:
            print("quality: FAILED", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1
        print(
            "quality: ok "
            f"(coverage={coverage_data['overall_percent']:.2f}%, "
            f"probe={'skipped' if probe is None else 'passed'})"
        )
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"quality: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
