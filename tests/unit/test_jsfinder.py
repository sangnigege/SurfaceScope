from __future__ import annotations

import warnings
from types import SimpleNamespace

from bs4 import MarkupResemblesLocatorWarning

from surfacescope.adapters.jsfinder_adapter import JSFinderAdapter, _extract_urls
from surfacescope.components.jsfinder import base_href, extract_script_urls
from surfacescope.components.swagger import document_links
from surfacescope.models import ResponseSnapshot, Target


def test_extract_urls_strips_statement_delimiters() -> None:
    found = _extract_urls(
        'const endpoint = "https://example.com/api;";',
        "https://example.com/app.js",
        "https://example.com/",
    )

    assert "https://example.com/api" in found


def test_extract_urls_resolves_relative_paths_and_rejects_foreign_hosts() -> None:
    found = _extract_urls(
        'fetch("/api/v1"); fetch("https://other.example/api");',
        "https://example.com/app.js",
        "https://example.com/",
    )

    assert "https://example.com/api/v1" in found
    assert "https://other.example/api" not in found


def test_non_html_responses_do_not_emit_bs4_filename_warnings() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert base_href("denied", "https://example.test/admin") == "https://example.test/admin"
        assert extract_script_urls(
            "denied", "https://example.test/admin", "https://example.test/"
        ) == []
        assert document_links("denied", "https://example.test/admin") == []

    assert not any(
        issubclass(item.category, MarkupResemblesLocatorWarning) for item in caught
    )


class _Results:
    def get_snapshot(self, *_args, **_kwargs):
        return None

    def add_snapshot(self, _snapshot) -> None:
        return None


class _Executor:
    def __init__(self) -> None:
        self.requested: list[str] = []

    def get(self, url: str, **_kwargs) -> ResponseSnapshot:
        self.requested.append(url)
        if url.endswith("/"):
            body = b'<script src="/a.js"></script><script src="/b.js"></script>'
            content_type = "text/html"
        else:
            body = b"fetch('/api/from-script')"
            content_type = "application/javascript"
        return ResponseSnapshot(
            request_id=url,
            url=url,
            final_url=url,
            method="GET",
            status=200,
            headers={"Content-Type": content_type},
            body=body,
            text=body.decode(),
            elapsed=0.01,
        )


def test_jsfinder_adapter_limits_script_urls_without_slicing_a_dict_view() -> None:
    executor = _Executor()
    context = SimpleNamespace(
        results=_Results(),
        executor=executor,
        profile=SimpleNamespace(id="test-profile"),
    )

    result = JSFinderAdapter().scan(
        context,
        [Target(url="http://example.test/")],
        {"max_assets": 1},
    )

    assert result.errors == []
    assert executor.requested == ["http://example.test/", "http://example.test/a.js"]


class _SharedEndpointExecutor:
    def __init__(self) -> None:
        self.requested: list[str] = []

    def get(self, url: str, **_kwargs) -> ResponseSnapshot:
        self.requested.append(url)
        if url in {"http://example.test/one", "http://example.test/two"}:
            name = url.rsplit("/", 1)[-1]
            body = f'<script src="/{name}.js"></script>'
            content_type = "text/html"
        else:
            body = "fetch('/api/same')"
            content_type = "application/javascript"
        return ResponseSnapshot(
            request_id=url,
            url=url,
            final_url=url,
            method="GET",
            status=200,
            headers={"Content-Type": content_type},
            body=body.encode(),
            text=body,
            elapsed=0.01,
        )


def test_jsfinder_deduplicates_one_endpoint_observed_from_multiple_targets() -> None:
    executor = _SharedEndpointExecutor()
    context = SimpleNamespace(
        results=_Results(),
        executor=executor,
        profile=SimpleNamespace(id="test-profile"),
    )

    result = JSFinderAdapter().scan(
        context,
        [
            Target(url="http://example.test/one"),
            Target(url="http://example.test/two"),
        ],
        {"max_assets": 10},
    )

    endpoints = [
        finding
        for finding in result.findings
        if finding.kind == "endpoint" and finding.target == "http://example.test/api/same"
    ]
    assert len(endpoints) == 1
    assert endpoints[0].target == "http://example.test/api/same"
    assert len(endpoints[0].metadata["provenance"]) == 2
    assert endpoints[0].metadata["occurrences"] == 2
    assert result.stats["endpoints"] == 1
