from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_quality.py"
_SPEC = importlib.util.spec_from_file_location("surfacescope_check_quality", SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
check_quality = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = check_quality
_SPEC.loader.exec_module(check_quality)


def _coverage(overall: float = 80.0, module: float = 75.0) -> dict:
    return {
        "overall_percent": overall,
        "modules": {"src/surfacescope/example.py": {"percent": module, "statements": 50}},
    }


def test_coverage_snapshot_keeps_significant_modules_and_drops_tiny_files() -> None:
    data = {
        "totals": {"percent_covered": 82.456, "num_statements": 100, "num_branches": 20},
        "files": {
            "src/surfacescope/example.py": {
                "summary": {"percent_covered": 75.555, "num_statements": 50}
            },
            "src/surfacescope/tiny.py": {
                "summary": {"percent_covered": 20.0, "num_statements": 4}
            },
        },
    }

    snapshot = check_quality.coverage_snapshot(data)

    assert snapshot["overall_percent"] == 82.46
    assert snapshot["modules"] == {"src/surfacescope/example.py": {"percent": 75.56, "statements": 50}}


def test_compare_coverage_rejects_overall_and_module_regressions() -> None:
    baseline = _coverage(80.0, 75.0)
    current = _coverage(78.0, 72.0)

    errors = check_quality.compare_coverage(current, baseline)

    assert any("overall coverage regressed" in error for error in errors)
    assert any("module coverage regressed" in error for error in errors)


def test_compare_coverage_allows_recorded_tolerance() -> None:
    baseline = _coverage(80.0, 75.0)
    current = _coverage(79.6, 74.6)

    assert check_quality.compare_coverage(current, baseline) == []


def test_compare_probe_rejects_budget_drift_and_latency_regression() -> None:
    baseline = {
        "request_budget": {"uniform_403": 29},
        "latency_seconds": {"uniform_403": 0.1},
        "environment": check_quality.environment_snapshot(),
    }
    current = {
        "request_budget": {"uniform_403": 30},
        "latency_seconds": {"uniform_403": 0.3},
    }

    errors = check_quality.compare_probe(current, baseline)

    assert any("request budget changed" in error for error in errors)
    assert any("latency regression" in error for error in errors)


def test_compare_probe_requires_same_environment_for_latency_policy(monkeypatch) -> None:
    baseline = {
        "request_budget": {"uniform_403": 29},
        "latency_seconds": {"uniform_403": 0.1},
        "environment": {"os": "linux", "python": "3.10.12", "branch_coverage": "true"},
    }
    current = {"request_budget": {"uniform_403": 29}, "latency_seconds": {"uniform_403": 0.1}}

    monkeypatch.setattr(
        check_quality,
        "environment_snapshot",
        lambda: {"os": "linux", "python": "3.10.99", "branch_coverage": "true"},
    )
    assert check_quality.compare_probe(current, baseline) == []

    monkeypatch.setattr(
        check_quality,
        "environment_snapshot",
        lambda: {"os": "linux", "python": "3.11.0", "branch_coverage": "true"},
    )
    errors = check_quality.compare_probe(current, baseline)
    assert any("environment differs" in error for error in errors)


def test_probe_scenarios_have_unique_names_and_positive_budgets() -> None:
    names = [scenario.name for scenario in check_quality.SCENARIOS]

    assert len(names) == len(set(names))
    assert all(scenario.expected_requests > 0 for scenario in check_quality.SCENARIOS)
