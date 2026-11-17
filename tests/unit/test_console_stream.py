from __future__ import annotations

import io
from pathlib import Path

from surfacescope.console import ConsoleStream, render_scan_result
from surfacescope.models import ComponentResult, Finding
from surfacescope.pipeline import PipelineResult


class _Tty(io.StringIO):
    def isatty(self) -> bool:  # pragma: no cover - trivial stub
        return True


def _result() -> PipelineResult:
    finger = ComponentResult(stats={"rules": 10, "pages_probed": 1, "matches": 1, "findings": 1})
    finger.findings.append(
        Finding(
            module="finger",
            kind="fingerprint",
            target="https://example.com/",
            evidence="header: server: demo",
            confidence=0.8,
            metadata={"cms": "Demo", "status": 200},
        )
    )
    dirsearch = ComponentResult(stats={"tested": 10, "findings": 1, "blocked": 0})
    dirsearch.findings.append(
        Finding(
            module="dirsearch",
            kind="path",
            target="https://example.com/admin/",
            source_target="https://example.com/",
            confidence=0.9,
            response_summary={"status": 200, "length": 1024},
        )
    )
    return PipelineResult(
        run_id="run-1",
        output_dir=Path("reports"),
        component_result=ComponentResult(findings=[*dirsearch.findings, *finger.findings]),
        report_paths=[Path("reports/run-1.json")],
        run_meta={
            "run_id": "run-1",
            "targets": ["https://example.com/"],
            "profile": "chromium-desktop-stable",
            "components": ["dirsearch", "finger"],
            "audit": {"counts": {"network_sent": 11, "cache_hit": 0}},
        },
        component_results={"dirsearch": dirsearch, "finger": finger},
    )


def test_banner_and_finger_table_are_rendered() -> None:
    output = render_scan_result(_result(), color=False)

    assert "/ ___|" in output
    assert "SurfaceScope" in output
    assert "STATUS" in output and "TECHNOLOGY" in output and "SOURCES" in output
    assert "[Demo]" in output
    # dirsearch findings print the path, not the full URL
    assert "/admin/" in output
    assert "https://example.com/admin/" not in output
    assert "\r" not in output
    assert "\x1b" not in output


def test_console_stream_prints_header_component_and_summary_in_order() -> None:
    output = io.StringIO()
    stream = ConsoleStream(output, color=False, progress_stream=_Tty())

    stream.header(_result().run_meta)
    result = _result()
    stream.component(1, "dirsearch", result.component_results["dirsearch"])
    stream.summary(result)

    text = output.getvalue()

    assert text.index("SurfaceScope") < text.index("[1] DIRSEARCH") < text.index("SUMMARY")


def test_progress_line_is_throttled_and_tty_only() -> None:
    tty = _Tty()
    output = io.StringIO()
    stream = ConsoleStream(output, color=False, progress_stream=tty, progress_interval=10)

    stream.progress("dirsearch", 5, 100)
    assert tty.getvalue() == ""

    stream.progress("dirsearch", 10, 100)
    assert "\r" in tty.getvalue()
    assert "10/100" in tty.getvalue()

    stream.progress("dirsearch", 100, 100)
    assert "100/100" in tty.getvalue()

    stream.clear_progress()
    assert stream._progress_visible is False


def test_progress_is_silent_for_non_tty_streams() -> None:
    output = io.StringIO()
    stderr = io.StringIO()
    stream = ConsoleStream(output, color=False, progress_stream=stderr)

    stream.progress("dirsearch", 10, 100)

    assert stderr.getvalue() == ""
