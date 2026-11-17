from __future__ import annotations

from types import SimpleNamespace

from surfacescope.adapters.packer_adapter import PackerAdapter
from surfacescope.components.packer import (
    Endpoint,
    classify_surface,
    evaluate_cors,
    evaluate_unauthorized,
    find_secrets,
    looks_like_sql_error,
    redact_secret,
    sql_probe_urls,
    upload_markers,
)
from surfacescope.models import RequestSpec, ResponseSnapshot, Target
from surfacescope.result_store import ResultStore


def _snapshot(url: str, status: int, text: str = "ok", headers: dict[str, str] | None = None) -> ResponseSnapshot:
    return ResponseSnapshot(
        request_id="test",
        url=url,
        final_url=url,
        method="GET",
        status=status,
        headers={"Content-Type": "text/plain", **(headers or {})},
        body=text.encode(),
        text=text,
        elapsed=0.0,
    )


def test_secret_extraction_redacts_values() -> None:
    text = 'const key="AKIA1234567890ABCDEF"; const token="<redacted>";'
    secrets = find_secrets(text, "http://example.test/app.js")

    assert any(secret.kind == "aws-access-key" for secret in secrets)
    assert all("AKIA1234567890ABCDEF" not in secret.preview for secret in secrets)
    assert redact_secret("short") == "<redacted>"


def test_cors_and_unauthorized_decisions_require_evidence() -> None:
    reflected = _snapshot(
        "http://example.test/api",
        200,
        headers={
            "Access-Control-Allow-Origin": "https://origin.surfacescope.invalid",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    assert evaluate_cors(reflected).accepted is True
    assert evaluate_cors(
        _snapshot("http://example.test/api", 200, headers={"Access-Control-Allow-Origin": "*"})
    ).accepted is False
    assert evaluate_cors(
        _snapshot(
            "http://example.test/api",
            200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )
    ).accepted is False
    assert evaluate_cors(
        _snapshot(
            "http://example.test/api",
            200,
            headers={
                "Access-Control-Allow-Origin": "https://origin.surfacescope.invalid",
            },
        )
    ).accepted is False
    assert evaluate_cors(_snapshot("http://example.test/api", 200)).accepted is False

    assert evaluate_unauthorized(
        _snapshot("http://example.test/api", 403),
        _snapshot("http://example.test/api", 200),
    ).accepted is True
    assert evaluate_unauthorized(
        _snapshot("http://example.test/api", 401),
        _snapshot("http://example.test/api", 401),
    ).accepted is False


def test_sql_probes_are_limited_to_query_parameters() -> None:
    probes = sql_probe_urls("http://example.test/api?q=1&page=2")

    assert len(probes) == 2
    assert probes[0][1] == "q"
    assert "surfacescope%27" in probes[0][0]
    assert sql_probe_urls("http://example.test/api") == []
    assert looks_like_sql_error("You have an error in your SQL syntax") is True


def test_surface_classification_is_passive_and_bounded() -> None:
    endpoints = [
        Endpoint("http://example.test/api/upload", "POST", "http://example.test/app.js"),
        Endpoint("http://example.test/auth/login", "POST", "http://example.test/app.js"),
        Endpoint("http://example.test/admin/users", "GET", "http://example.test/app.js"),
        Endpoint("http://example.test/public", "GET", "http://example.test/app.js"),
    ]

    candidates = classify_surface(endpoints)

    assert [(item.category, item.endpoint.url) for item in candidates] == [
        ("upload", "http://example.test/api/upload"),
        ("authentication", "http://example.test/auth/login"),
        ("sensitive", "http://example.test/admin/users"),
    ]
    assert upload_markers("FormData(); Content-Type: multipart/form-data") is True
    assert upload_markers("fetch('/api')") is False


class _Executor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict | RequestSpec]] = []

    def get(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        if url.endswith("/app.js"):
            return _snapshot(url, 200, 'fetch("/api/private?q=1")')
        if "/api/private" in url:
            if kwargs.get("headers"):
                return _snapshot(url, 403, "denied")
            return _snapshot(url, 200, "public")
        return _snapshot(url, 200, '<script src="/app.js"></script>')

    def request(self, spec: RequestSpec):
        self.calls.append((spec.url, spec))
        if spec.metadata.get("technique") == "cors":
            return _snapshot(
                spec.url,
                200,
                headers={
                    "Access-Control-Allow-Origin": "https://origin.surfacescope.invalid",
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        return _snapshot(spec.url, 403, "denied")


class _Config:
    def section(self, name: str):
        if name == "packer":
            return {
                "max_assets": 10,
                "max_endpoints": 10,
                "max_active_checks": 10,
                "probe_endpoints": False,
                "fetch_sourcemaps": False,
            }
        return {}


def _context(executor: _Executor) -> SimpleNamespace:
    return SimpleNamespace(
        config=_Config(),
        executor=executor,
        results=ResultStore(),
        profile=SimpleNamespace(id="test-profile"),
        capabilities=SimpleNamespace(get=lambda _name: SimpleNamespace(available=False)),
    )


def test_active_checks_use_the_shared_executor_and_bind_findings() -> None:
    executor = _Executor()
    result = PackerAdapter().scan(
        _context(executor),
        [Target(url="http://example.test/", headers={"Authorization": "Bearer test"}, scope="scope-one")],
        {"probe_endpoints": True, "active": True},
    )

    kinds = {finding.kind for finding in result.findings}
    assert {"packer_cors", "packer_unauthorized"} <= kinds
    assert any(isinstance(call[1], RequestSpec) for call in executor.calls)
    assert all(
        finding.metadata.get("auth_scope") == "scope-one"
        for finding in result.findings
        if finding.kind in {"packer_cors", "packer_unauthorized"}
    )
    cors_specs = [
        call[1]
        for call in executor.calls
        if isinstance(call[1], RequestSpec)
        and call[1].metadata.get("technique") == "cors"
    ]
    assert cors_specs[0].metadata["site"] == "cross-site"
    assert cors_specs[0].metadata["origin"] == "https://origin.surfacescope.invalid"


def test_active_findings_and_cors_checks_are_isolated_by_auth_scope() -> None:
    executor = _Executor()
    targets = [
        Target(
            url="http://example.test/",
            headers={"Authorization": "Bearer one"},
            scope="scope-one",
        ),
        Target(
            url="http://example.test/",
            headers={"Authorization": "Bearer two"},
            scope="scope-two",
        ),
    ]

    result = PackerAdapter().scan(
        _context(executor),
        targets,
        {"probe_endpoints": True, "active": True},
    )

    cors_findings = [finding for finding in result.findings if finding.kind == "packer_cors"]
    assert len(cors_findings) == 2
    assert {finding.auth_scope for finding in cors_findings} == {"scope-one", "scope-two"}
    assert len({finding.target_id for finding in cors_findings}) == 2

    cors_calls = [
        call
        for call in executor.calls
        if isinstance(call[1], RequestSpec) and call[1].metadata.get("technique") == "cors"
    ]
    assert len(cors_calls) == 2


def test_anonymous_probe_keeps_the_original_target_proxy_identity() -> None:
    executor = _Executor()
    target = Target(
        url="http://example.test/",
        headers={"Authorization": "Bearer test"},
        scope="scope-one",
        proxy="http://127.0.0.1:8081",
    )

    PackerAdapter().scan(
        _context(executor),
        [target],
        {"probe_endpoints": True, "active": True},
    )

    anonymous_calls = [
        call[1]
        for call in executor.calls
        if isinstance(call[1], dict)
        and call[1].get("metadata", {}).get("technique") == "anonymous-baseline"
    ]
    assert len(anonymous_calls) == 1
    assert anonymous_calls[0]["target_id"] == target.identity
    assert anonymous_calls[0]["auth_scope"] == "scope-one#anonymous"
    assert anonymous_calls[0]["auth_origin"] == "http://example.test"
