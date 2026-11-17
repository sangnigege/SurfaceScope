from __future__ import annotations

from types import SimpleNamespace

from surfacescope.adapters.finger_adapter import FingerAdapter
from surfacescope.components.finger import (
    FingerMatcher,
    favicon_hashes,
    favicon_href,
    parse_title,
)
from surfacescope.models import ResponseSnapshot, Target

RULES = [
    {"cms": "Demo", "method": "keyword", "location": "title", "keyword": ["Demo Panel"], "logic": "or"},
    {"cms": "Nginx", "method": "keyword", "location": "header", "keyword": ["Server: nginx"], "logic": "and"},
    {"cms": "Both", "method": "keyword", "location": "body", "keyword": ["alpha", "beta"], "logic": "and"},
    {"cms": "Any", "method": "keyword", "location": "body", "keyword": ["gamma", "delta"], "logic": "or"},
    {"cms": "Favicon", "method": "faviconhash", "keyword": ["12345"]},
    {
        "cms": "Versioned",
        "method": "regula",
        "location": "body",
        "keyword": [r"Version/([0-9.]+)"],
        "version_regex": r"Version/([0-9.]+)",
    },
]


def test_title_parse_and_favicon_href() -> None:
    html = '<html><head><title>  Demo &amp; Panel </title><link href="/static/a.png" rel="shortcut icon"></head></html>'

    assert parse_title(html) == "Demo & Panel"
    assert favicon_href(html) == "/static/a.png"


def test_matcher_supports_locations_logic_regex_and_versions() -> None:
    matcher = FingerMatcher(RULES)
    matches = matcher.match(
        url="https://example.test/app",
        text="<title>Demo Panel</title> alpha beta gamma Version/1.2.3",
        headers={"Server": "nginx", "X-Test": "1"},
    )
    found = {match.cms: match for match in matches}

    assert set(found) == {"Demo", "Nginx", "Both", "Any", "Versioned"}
    assert found["Demo"].confidence > 0.8
    assert found["Versioned"].version == "1.2.3"
    assert found["Any"].evidence == ("gamma",)


def test_favicon_hashes_are_stable_and_rule_matching_uses_all_representations() -> None:
    hashes = favicon_hashes(b"icon-bytes")
    matcher = FingerMatcher([{"cms": "Favicon", "method": "faviconhash", "keyword": [hashes["fofa"]]}])

    matches = matcher.match(url="https://example.test/", text="", headers={}, favicon_hash_values=set(hashes.values()))

    assert matches[0].cms == "Favicon"
    assert matches[0].confidence == 0.95


def test_header_keyword_matching_requires_token_boundaries() -> None:
    matcher = FingerMatcher(
        [
            {
                "cms": "HP-ProCurve-Switch",
                "method": "keyword",
                "location": "header",
                "keyword": ["eHTTP"],
                "logic": "or",
            }
        ]
    )

    assert matcher.match(url="http://example.test/", text="", headers={"Server": "SimpleHTTP/0.6"}) == []
    matches = matcher.match(url="http://example.test/", text="", headers={"Server": "eHTTP/1.0"})
    assert [match.cms for match in matches] == ["HP-ProCurve-Switch"]


def test_low_signal_body_keywords_do_not_match_alone() -> None:
    matcher = FingerMatcher(
        [
            {
                "cms": "Discuz",
                "method": "keyword",
                "location": "body",
                "keyword": ["cache/", "Discuz!"],
                "logic": "or",
            }
        ]
    )

    assert matcher.match(
        url="http://example.test/",
        text="<title>Directory listing for /</title><a href='cache/'>cache/</a>",
        headers={},
    ) == []
    matches = matcher.match(url="http://example.test/", text="cache/ Discuz!", headers={})
    assert [match.cms for match in matches] == ["Discuz"]


def test_low_signal_body_keywords_remain_required_for_and_rules() -> None:
    matcher = FingerMatcher(
        [
            {
                "cms": "Demo",
                "method": "keyword",
                "location": "body",
                "keyword": ["cache/", "DemoMarker"],
                "logic": "and",
            }
        ]
    )

    assert matcher.match(url="http://example.test/", text="DemoMarker", headers={}) == []
    matches = matcher.match(url="http://example.test/", text="cache/ DemoMarker", headers={})
    assert [match.cms for match in matches] == ["Demo"]


def test_url_only_rules_require_specific_path_evidence() -> None:
    matcher = FingerMatcher(
        [
            {
                "cms": "Kubernetes-Dashboard",
                "method": "keyword",
                "location": "url",
                "keyword": ["/api/v1"],
                "logic": "and",
            },
            {
                "cms": "Kubernetes-Dashboard",
                "method": "keyword",
                "location": "url",
                "keyword": ["/api/v1/csrftoken"],
                "logic": "and",
            },
        ]
    )

    assert matcher.match(url="https://example.test/api/v1/users", text="", headers={}) == []
    matches = matcher.match(
        url="https://example.test/api/v1/csrftoken",
        text="",
        headers={},
    )
    assert [match.cms for match in matches] == ["Kubernetes-Dashboard"]
    assert matches[0].evidence == ("/api/v1/csrftoken",)


def test_url_keyword_matching_respects_path_segment_boundaries() -> None:
    matcher = FingerMatcher(
        [
            {
                "cms": "Jupyter",
                "method": "keyword",
                "location": "url",
                "keyword": ["/tree"],
                "logic": "and",
            }
        ]
    )

    assert matcher.match(url="https://example.test/street", text="", headers={}) == []
    matches = matcher.match(url="https://example.test/tree", text="", headers={})
    assert [match.cms for match in matches] == ["Jupyter"]


def test_generic_header_tokens_cannot_identify_php_fpm_alone() -> None:
    matcher = FingerMatcher(
        [
            {
                "cms": "PHP-FPM",
                "method": "keyword",
                "location": "header",
                "keyword": ["PHP", "X-Powered-By: PHP"],
                "logic": "and",
            },
            {
                "cms": "PHP",
                "method": "keyword",
                "location": "header",
                "keyword": ["PHP/", "x-powered-by: php"],
                "logic": "and",
            },
        ]
    )

    matches = matcher.match(
        url="https://example.test/",
        text="",
        headers={"X-Powered-By": "PHP/8.2.12"},
    )

    assert [match.cms for match in matches] == ["PHP"]


class _FingerResults:
    def __init__(self, findings=None) -> None:
        self._items = list(findings or [])

    def get_snapshot(self, *_args, **_kwargs):
        return None

    def add_snapshot(self, _snapshot) -> None:
        return None

    def findings(self):
        return list(self._items)


class _FingerExecutor:
    def __init__(self, status: int) -> None:
        self.status = status
        self.calls: list[str] = []

    def get(self, url: str, **_kwargs) -> ResponseSnapshot:
        self.calls.append(url)
        body = b"<title>Demo Panel</title>"
        return ResponseSnapshot(
            request_id="request-1",
            url=url,
            final_url=url,
            method="GET",
            status=self.status,
            headers={"Content-Type": "text/html", "Server": "Demo"},
            body=body,
            text=body.decode(),
            elapsed=0.01,
        )


def test_finger_adapter_skips_404_and_server_error_pages() -> None:
    for status in (404, 503):
        adapter = FingerAdapter()
        adapter._rules = [
            {
                "cms": "Demo",
                "method": "keyword",
                "location": "title",
                "keyword": ["Demo Panel"],
            }
        ]
        executor = _FingerExecutor(status)
        context = SimpleNamespace(
            config=SimpleNamespace(section=lambda _name: {"max_endpoints": 10, "scan_discovered": False}),
            profile=SimpleNamespace(id="test-profile"),
            executor=executor,
            results=_FingerResults(),
        )

        result = adapter.scan(context, [Target(url="http://example.test/missing")], {})

        assert result.findings == []
        assert result.stats["skipped_unusable_pages"] == 1
        assert executor.calls == ["http://example.test/missing"]


def test_finger_adapter_collapses_repeated_cms_across_pages() -> None:
    from surfacescope.models import Finding

    adapter = FingerAdapter()
    adapter._rules = [
        {
            "cms": "Demo",
            "method": "keyword",
            "location": "title",
            "keyword": ["Demo Panel"],
        }
    ]
    executor = _FingerExecutor(200)
    results = _FingerResults(
        [
            Finding(
                module="jsfinder",
                kind="endpoint",
                target="http://example.test/admin",
                auth_scope="http://example.test",
                metadata={"source_target": "http://example.test/"},
            )
        ]
    )
    context = SimpleNamespace(
        config=SimpleNamespace(
            section=lambda _name: {"max_endpoints": 10, "scan_discovered": True}
        ),
        profile=SimpleNamespace(id="test-profile"),
        executor=executor,
        results=results,
    )

    result = adapter.scan(context, [Target(url="http://example.test/")], {})

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.metadata["cms"] == "Demo"
    assert finding.metadata["occurrences"] == 2
    assert finding.metadata["sources"] == [
        "http://example.test/",
        "http://example.test/admin",
    ]
    assert "http://example.test/" in executor.calls
    assert "http://example.test/admin" in executor.calls
