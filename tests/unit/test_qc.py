from __future__ import annotations

from surfacescope.models import ResponseSnapshot
from surfacescope.quality.qc import QualityController


def _snapshot(url: str, status: int, text: str = "ok") -> ResponseSnapshot:
    body = text.encode("utf-8")
    return ResponseSnapshot(
        request_id="test",
        url=url,
        final_url=url,
        method="GET",
        status=status,
        headers={"content-type": "text/plain"},
        body=body,
        text=text,
        elapsed=0.0,
    )


def test_status_suffix_filter_rejects_matching_path() -> None:
    qc = QualityController(status_suffix_filters={403: (".htaccess",)})

    decision = qc.discovery(_snapshot("http://example.test/.htaccess", 403), None)

    assert decision.accepted is False
    assert "suffix filter" in decision.reason


def test_status_suffix_filter_keeps_unrelated_path() -> None:
    qc = QualityController(status_suffix_filters={403: (".htaccess",)})

    decision = qc.discovery(_snapshot("http://example.test/admin", 403), None)

    assert decision.accepted is True


def test_bypass_accepts_only_a_successful_status_with_distinct_content() -> None:
    qc = QualityController()
    baseline = _snapshot("http://example.test/admin", 403, "denied")

    for status in (301, 302, 400, 401, 405, 422, 500, 502):
        decision = qc.bypass(baseline, _snapshot("http://example.test/admin", status, f"status-{status}"))
        assert decision.accepted is False, status

    accepted = qc.bypass(baseline, _snapshot("http://example.test/admin", 200, "admin console"))
    assert accepted.accepted is True
