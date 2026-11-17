from __future__ import annotations

from pathlib import Path

from surfacescope.console import render_scan_result
from surfacescope.models import ComponentResult, Finding
from surfacescope.pipeline import PipelineResult


def _result() -> PipelineResult:
    components = ["dirsearch", "jsfinder", "packer", "swagger", "bypass403", "finger"]
    component_results = {
        "dirsearch": ComponentResult(
            stats={"tested": 0, "findings": 0, "blocked": 0, "network_requests": 0}
        ),
        "jsfinder": ComponentResult(stats={"targets": 1, "assets": 1, "endpoints": 2, "findings": 3}),
        "packer": ComponentResult(),
        "swagger": ComponentResult(),
        "bypass403": ComponentResult(
            stats={
                "mode": "fast",
                "targets": 0,
                "generated_variants": 65,
                "candidate_variants": 27,
                "variants_tested": 0,
                "accepted": 0,
                "request_budget": {
                    "configured": True,
                    "max_total": 12000,
                    "max_per_host": 600,
                    "total": 1,
                    "by_host": {"127.0.0.1": 1},
                },
            }
        ),
        "finger": ComponentResult(stats={"pages_probed": 1, "skipped_unusable_pages": 1}),
    }
    component_results["finger"].findings.append(
        Finding(
            module="finger",
            kind="fingerprint",
            target="http://127.0.0.1:8000/\x1b[2J",
            evidence="Server: Demo\r\ninjected",
            metadata={
                "cms": "Demo",
                "status": 200,
                "sources": [
                    "http://127.0.0.1:8000/",
                    "http://127.0.0.1:8000/admin",
                ],
            },
        )
    )
    return PipelineResult(
        run_id="run-1",
        output_dir=Path("reports"),
        component_result=ComponentResult(),
        report_paths=[Path("reports/run-1.json")],
        run_meta={
            "run_id": "run-1",
            "targets": ["http://127.0.0.1:8000/"],
            "profile": "chromium-desktop-stable",
            "components": components,
            "audit": {"counts": {"network_sent": 0, "cache_hit": 0}},
        },
        component_results=component_results,
    )


def test_terminal_report_renders_every_enabled_component_and_zero_counts() -> None:
    output = render_scan_result(_result(), color=False)

    for title in (
        "DIRSEARCH / PATH DISCOVERY",
        "JSFINDER / JS & ENDPOINTS",
        "PACKER / WEBPACK ANALYSIS",
        "SWAGGER / OPENAPI",
        "BYPASS403 / ACCESS CONTROL",
        "FINGER / TECHNOLOGY",
    ):
        assert title in output
    assert "tested=0" in output
    assert "generated=65" in output
    assert "initial=27" in output
    assert "assets=1" in output
    assert "endpoints=2" in output
    assert "findings=0" in output
    assert "(no findings)" in output
    assert "[Demo]" in output
    assert "host=1/600" in output
    assert "total=1/12000" in output
    assert "sources=2" in output
    assert "reports" in output
    assert "run-1.json" in output
    assert "\x1b" not in output
    assert "\r" not in output


def test_terminal_report_color_is_explicit_and_control_safe() -> None:
    plain = render_scan_result(_result(), color=False)
    colored = render_scan_result(_result(), color=True)

    assert "\x1b[" not in plain
    assert "\x1b[" in colored
    assert "\x1b[2J" not in plain
    assert "injected" in plain
