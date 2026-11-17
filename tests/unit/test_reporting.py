from __future__ import annotations

import json

import pytest

import surfacescope.reporting.writer as writer_module
from surfacescope.errors import ConfigurationError
from surfacescope.models import ComponentResult, Finding
from surfacescope.reporting.writer import ReportWriter


def _finding(
    *,
    module: str = "dirsearch",
    kind: str = "path",
    target: str = "https://example.test/admin",
    evidence: str = "status=200",
    severity: str = "low",
    confidence: float = 0.7,
    method: str = "GET",
    timestamp: str = "2026-01-01T00:00:00+00:00",
) -> Finding:
    return Finding(
        module=module,
        kind=kind,
        target=target,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        request_summary={"method": method, "scope": "https://example.test"},
        timestamp=timestamp,
    )


def test_writer_writes_all_formats_and_deduplicates(tmp_path) -> None:
    duplicate = _finding()
    result = ComponentResult(
        findings=[
            duplicate,
            _finding(confidence=0.9, severity="high"),
            _finding(evidence="status=403", target="https://example.test/private"),
        ],
        stats={"requests": 3},
    )
    writer = ReportWriter(tmp_path)

    paths = writer.write(
        "run/unsafe",
        result,
        {"generated_at": "2026-01-01T00:00:00+00:00"},
        fmt=["json", "md", "html", "csv"],
    )

    assert [path.suffix for path in paths] == [".json", ".md", ".html", ".csv"]
    assert all(path.parent == tmp_path for path in paths)
    report = json.loads(paths[0].read_text(encoding="utf-8"))
    assert report["schema_version"] == 1
    assert report["summary"]["findings"] == 2
    assert report["summary"]["components"] == {"requests": 3}
    assert report["findings"][0]["severity"] == "high"
    assert report["findings"][0]["metadata"]["duplicate_count"] == 2


def test_report_content_is_stable_for_identical_input(tmp_path) -> None:
    result = ComponentResult(findings=[_finding()])
    meta = {"generated_at": "2026-01-01T00:00:00+00:00"}
    first = ReportWriter(tmp_path).write("stable", result, meta)
    first_text = first[0].read_text(encoding="utf-8")
    second = ReportWriter(tmp_path).write("stable", result, meta)

    assert second[0].read_text(encoding="utf-8") == first_text


def test_markdown_html_and_csv_escape_untrusted_fields(tmp_path) -> None:
    finding = _finding(
        target="=1+1",
        evidence='<script>alert("x")</script>',
        severity="high",
    )
    paths = ReportWriter(tmp_path).write(
        "escape",
        ComponentResult(findings=[finding]),
        {"generated_at": "2026-01-01T00:00:00+00:00"},
        fmt=["md", "html", "csv"],
    )
    markdown = paths[1].read_text(encoding="utf-8")
    html_output = paths[2].read_text(encoding="utf-8")
    csv_output = paths[3].read_text(encoding="utf-8")

    assert "<script>" not in markdown
    assert "&lt;script&gt;" in html_output
    assert "'=1+1" in csv_output
    assert csv_output.endswith("\n")
    assert "\r" not in csv_output


def test_failed_multi_format_commit_leaves_no_partial_report(tmp_path, monkeypatch) -> None:
    original_replace = writer_module.os.replace

    def fail_markdown(source, destination) -> None:
        if str(destination).endswith(".md"):
            raise OSError("simulated report commit failure")
        original_replace(source, destination)

    monkeypatch.setattr(writer_module.os, "replace", fail_markdown)

    with pytest.raises(OSError, match="simulated"):
        ReportWriter(tmp_path).write(
            "atomic",
            ComponentResult(findings=[_finding()]),
            {"generated_at": "2026-01-01T00:00:00+00:00"},
            fmt=["md"],
        )

    assert not (tmp_path / "atomic.json").exists()
    assert not (tmp_path / "atomic.md").exists()


def test_unknown_report_format_is_rejected(tmp_path) -> None:
    with pytest.raises(ConfigurationError, match="unsupported report format"):
        ReportWriter(tmp_path).write("bad", ComponentResult(), {}, fmt=["xml"])
