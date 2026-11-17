from __future__ import annotations

from types import SimpleNamespace

from surfacescope.adapters.packer_adapter import PackerAdapter
from surfacescope.components.packer import analyse_document, extract_endpoints
from surfacescope.errors import BudgetExceeded, CancelledError
from surfacescope.models import ResponseSnapshot, Target
from surfacescope.result_store import ResultStore


class _Audit:
    def __init__(self) -> None:
        self.network = 0

    def counts(self) -> dict[str, int]:
        return {"network_sent": self.network}


class _Executor:
    def __init__(self, responses: dict[str, tuple[int, str]]) -> None:
        self.responses = responses
        self.audit = _Audit()
        self.calls: list[tuple[str, dict]] = []

    def get(self, url: str, **kwargs):
        self.audit.network += 1
        self.calls.append((url, kwargs))
        status, text = self.responses.get(url, (200, ""))
        body = text.encode()
        return ResponseSnapshot(
            request_id="test",
            url=url,
            final_url=url,
            method="GET",
            status=status,
            headers={"Content-Type": "application/javascript"},
            body=body,
            text=text,
            elapsed=0.0,
        )

    def run_many(self, worker, items, *, max_workers=25):
        for item in items:
            yield worker(item)

    def budget_usage(self, _scope: str) -> dict:
        return {"configured": True}


class _Config:
    def __init__(self, **packer) -> None:
        self.packer = {
            "max_assets": 20,
            "max_endpoints": 20,
            "probe_endpoints": False,
            "fetch_sourcemaps": False,
            **packer,
        }

    def section(self, name: str):
        if name == "packer":
            return self.packer
        if name == "run":
            return {"threads": 2}
        return {}


def _context(executor: _Executor, **packer) -> SimpleNamespace:
    return SimpleNamespace(
        config=_Config(**packer),
        executor=executor,
        results=ResultStore(),
        profile=SimpleNamespace(id="test-profile"),
        capabilities=SimpleNamespace(get=lambda _name: SimpleNamespace(available=False)),
    )


def test_analyse_document_extracts_chunks_markers_and_methods() -> None:
    html = '<script src="/static/app.js"></script><div id="__NEXT_DATA__"></div>'
    document = analyse_document(html, "http://example.test/", "http://example.test/")
    endpoints = extract_endpoints(
        'axios.post("/api/save"); fetch("/api/read"); const chunk="/static/main.js";',
        "http://example.test/app.js",
        "http://example.test/",
    )

    assert document.scripts == ["http://example.test/static/app.js"]
    assert "__NEXT_DATA__" in document.markers
    assert {(endpoint.method, endpoint.url) for endpoint in endpoints} == {
        ("POST", "http://example.test/api/save"),
        ("GET", "http://example.test/api/read"),
    }


def test_packer_probes_bind_each_endpoint_to_its_source_target() -> None:
    executor = _Executor(
        {
            "http://example.test/one": (200, '<script src="/one/app.js"></script><script>fetch("/api/one")</script>'),
            "http://example.test/two": (200, '<script src="/two/app.js"></script><script>fetch("/api/two")</script>'),
            "http://example.test/one/app.js": (200, "webpackJsonp fetch('/api/one')"),
            "http://example.test/two/app.js": (200, "webpackJsonp fetch('/api/two')"),
            "http://example.test/api/one": (403, "denied"),
            "http://example.test/api/two": (200, "ok"),
        }
    )
    context = _context(executor)

    result = PackerAdapter().scan(
        context,
        [
            Target(url="http://example.test/one", scope="scope-one"),
            Target(url="http://example.test/two", scope="scope-two"),
        ],
        {"probe_endpoints": True},
    )

    probe_calls = [(url, kwargs) for url, kwargs in executor.calls if url.startswith("http://example.test/api/")]
    assert {kwargs["auth_scope"] for _, kwargs in probe_calls} == {"scope-one", "scope-two"}
    assert result.stats["probed_endpoints"] == 2
    assert any(finding.target == "http://example.test/api/one" for finding in result.findings)
    assert any(finding.target == "http://example.test/api/two" for finding in result.findings)


def test_packer_deduplicates_one_endpoint_observed_from_multiple_targets() -> None:
    executor = _Executor(
        {
            "http://example.test/one": (200, '<script>fetch("/api/same")</script>'),
            "http://example.test/two": (200, '<script>fetch("/api/same")</script>'),
        }
    )

    result = PackerAdapter().scan(
        _context(executor),
        [
            Target(url="http://example.test/one"),
            Target(url="http://example.test/two"),
        ],
        {},
    )

    endpoints = [finding for finding in result.findings if finding.kind == "packer_endpoint"]
    assert len(endpoints) == 1
    assert endpoints[0].target == "http://example.test/api/same"
    assert len(endpoints[0].metadata["provenance"]) == 2
    assert endpoints[0].metadata["occurrences"] == 2
    assert result.stats["endpoints"] == 1


def test_passive_packer_reports_secrets_and_upload_markers_without_active_mode() -> None:
    executor = _Executor(
        {
            "http://example.test/": (
                200,
                '<script>const first="AKIA1234567890ABCDEF"; const second="AKIAABCDEF1234567890"; '
                "const form = new FormData(); fetch('/api/read');</script>",
            )
        }
    )

    result = PackerAdapter().scan(_context(executor), [Target(url="http://example.test/")], {})

    kinds = {finding.kind for finding in result.findings}
    assert {"packer_secret", "packer_upload_surface", "packer_endpoint"} <= kinds
    secret_findings = [finding for finding in result.findings if finding.kind == "packer_secret"]
    assert result.stats["secrets_found"] == 2
    assert len(secret_findings) == 2
    assert len({finding.dedupe_key for finding in secret_findings}) == 2
    assert result.stats["active"] is False
    assert "dynamic_runtime" not in result.stats
    assert executor.audit.network == 1


def test_secret_quota_counts_only_unique_findings() -> None:
    executor = _Executor(
        {
            "http://example.test/": (
                200,
                '<script src="/app.js"></script>'
                '<script>const duplicate="AKIA1234567890ABCDEF";</script>',
            ),
            "http://example.test/app.js": (
                200,
                'const duplicate="AKIA1234567890ABCDEF"; '
                'const unique="AKIAABCDEF1234567890";',
            ),
        }
    )

    result = PackerAdapter().scan(
        _context(executor, max_secrets=2),
        [Target(url="http://example.test/")],
        {},
    )

    secret_findings = [finding for finding in result.findings if finding.kind == "packer_secret"]
    assert result.stats["secrets_found"] == 2
    assert len(secret_findings) == 2
    assert len({finding.dedupe_key for finding in secret_findings}) == 2


def test_inferred_get_paths_are_not_probed() -> None:
    executor = _Executor(
        {"http://example.test/": (200, '<script>const route="/api/inferred";</script>')}
    )

    result = PackerAdapter().scan(
        _context(executor),
        [Target(url="http://example.test/")],
        {"probe_endpoints": True},
    )

    assert [url for url, _ in executor.calls if url.startswith("http://example.test/api/")] == []
    assert any(finding.kind == "packer_endpoint" for finding in result.findings)
    assert result.stats["probed_endpoints"] == 0


def test_context_get_paths_are_not_probed_by_default() -> None:
    executor = _Executor(
        {
            "http://example.test/": (
                200,
                '<script>fetch("/api/explicit"); '
                'const cfg={method:"get", url:"/api/context"};</script>',
            )
        }
    )

    result = PackerAdapter().scan(
        _context(executor),
        [Target(url="http://example.test/")],
        {"probe_endpoints": True},
    )

    probed = {url for url, _ in executor.calls if url.startswith("http://example.test/api/")}
    assert probed == {"http://example.test/api/explicit"}
    assert any(finding.target == "http://example.test/api/context" for finding in result.findings)


def test_context_get_paths_require_an_explicit_probe_opt_in() -> None:
    executor = _Executor(
        {
            "http://example.test/": (
                200,
                '<script>fetch("/api/explicit"); '
                'const cfg={method:"get", url:"/api/context"};</script>',
            )
        }
    )

    PackerAdapter().scan(
        _context(executor),
        [Target(url="http://example.test/")],
        {"probe_endpoints": True, "probe_context_methods": True},
    )

    probed = {url for url, _ in executor.calls if url.startswith("http://example.test/api/")}
    assert probed == {"http://example.test/api/explicit", "http://example.test/api/context"}


class _BudgetExecutor:
    def get(self, url: str, **kwargs):
        raise BudgetExceeded(f"budget stopped before {url}")


class _CancelledExecutor:
    def get(self, url: str, **kwargs):
        raise CancelledError("scan cancelled")


def test_passive_budget_exhaustion_is_reported_without_network_errors() -> None:
    result = PackerAdapter().scan(
        _context(_BudgetExecutor()),
        [Target(url="http://example.test/")],
        {},
    )

    assert result.stats["budget_stopped"] is True
    assert result.errors == []


def test_passive_cancellation_propagates() -> None:
    try:
        PackerAdapter().scan(
            _context(_CancelledExecutor()),
            [Target(url="http://example.test/")],
            {},
        )
    except CancelledError:
        pass
    else:
        raise AssertionError("cancellation must not be converted into a component error")


def test_endpoint_provenance_prefers_explicit_evidence() -> None:
    endpoints = extract_endpoints(
        'const route="/api/same"; fetch("/api/same");',
        "http://example.test/app.js",
        "http://example.test/",
    )

    same = [endpoint for endpoint in endpoints if endpoint.url == "http://example.test/api/same"]
    assert len(same) == 1
    assert same[0].method_source == "explicit"
