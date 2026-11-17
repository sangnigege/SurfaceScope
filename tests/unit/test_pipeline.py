from __future__ import annotations

from surfacescope import pipeline
from surfacescope.models import Finding, Target


def _context():
    return pipeline.create_context(include_env=False, artifact_root=None)


def test_component_dependency_order_is_deterministic() -> None:
    assert pipeline._ordered_components(["finger", "bypass", "dirsearch", "jsfinder"]) == [
        "dirsearch",
        "jsfinder",
        "bypass403",
        "finger",
    ]


def test_bypass_budget_follows_mode_unless_explicitly_overridden() -> None:
    context, executor, _, _ = pipeline.create_context(
        include_env=False,
        artifact_root=None,
        overrides={"bypass": {"mode": "balanced"}},
    )
    try:
        assert executor.budget_usage("bypass403")["max_total"] == 40000
        assert executor.budget_usage("bypass403")["max_per_host"] == 1200
    finally:
        executor.close()

    context, executor, _, _ = pipeline.create_context(
        include_env=False,
        artifact_root=None,
        overrides={"bypass": {"mode": "full", "max_total_requests": 9, "max_requests_per_host": 3}},
    )
    try:
        assert executor.budget_usage("bypass403")["max_total"] == 9
        assert executor.budget_usage("bypass403")["max_per_host"] == 3
    finally:
        executor.close()


def test_403_handoff_uses_blocked_findings_not_every_root() -> None:
    context, executor, _, _ = _context()
    try:
        context.options["components"] = ["dirsearch", "bypass403"]
        context.results.add_findings(
            [
                Finding(module="dirsearch", kind="path", target="http://example.test/admin", metadata={"status": 403}),
                Finding(module="dirsearch", kind="path", target="http://example.test/public", metadata={"status": 200}),
            ]
        )
        targets = [Target(url="http://example.test/", scope="http://example.test")]

        selected = pipeline._targets_for_component("bypass403", targets, context)

        assert [target.url for target in selected] == ["http://example.test/admin"]
        assert selected[0].scope == "http://example.test"
    finally:
        executor.close()


def test_403_handoff_can_use_unverified_endpoint_findings() -> None:
    context, executor, _, _ = _context()
    try:
        context.options["components"] = ["jsfinder", "bypass403"]
        context.results.add_findings(
            [
                Finding(module="jsfinder", kind="endpoint", target="http://example.test/api/private"),
                Finding(module="jsfinder", kind="endpoint", target="http://evil.test/out-of-scope"),
            ]
        )
        targets = [Target(url="http://example.test/", scope="http://example.test")]

        selected = pipeline._targets_for_component("bypass403", targets, context)

        assert [target.url for target in selected] == ["http://example.test/api/private"]
    finally:
        executor.close()


def test_403_handoff_does_not_fall_back_when_discovery_found_nothing() -> None:
    context, executor, _, _ = _context()
    try:
        context.options["components"] = ["dirsearch", "bypass403"]
        targets = [Target(url="http://example.test/", scope="http://example.test")]

        assert pipeline._targets_for_component("bypass403", targets, context) == []
    finally:
        executor.close()


def test_403_only_scan_keeps_explicit_roots() -> None:
    context, executor, _, _ = _context()
    try:
        context.options["components"] = ["bypass403"]
        targets = [Target(url="http://example.test/private", scope="http://example.test")]

        assert pipeline._targets_for_component("bypass403", targets, context) == targets
    finally:
        executor.close()
