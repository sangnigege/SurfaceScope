from __future__ import annotations

from types import SimpleNamespace

from surfacescope.adapters.bypass403_adapter import Bypass403Adapter, _normalized_site_path
from surfacescope.assets import AssetManifest
from surfacescope.components.bypass403.catalog import MODE_POLICIES, BypassCatalog
from surfacescope.models import RequestSpec, ResponseSnapshot, Target
from surfacescope.result_store import ResultStore


class _Audit:
    def __init__(self) -> None:
        self.network = 0

    def counts(self) -> dict[str, int]:
        return {"network_sent": self.network}


class _Executor:
    def __init__(
        self,
        responses: dict[str, tuple[int, str]] | None = None,
        gets: dict[str, tuple[int, str]] | None = None,
    ) -> None:
        self.audit = _Audit()
        self.responses = responses or {}
        self.get_responses = gets or {}
        self.gets: list[tuple[str, dict]] = []
        self.requests: list[RequestSpec] = []

    @staticmethod
    def _snapshot(url: str, status: int, text: str) -> ResponseSnapshot:
        body = text.encode()
        return ResponseSnapshot(
            request_id="test",
            url=url,
            final_url=url,
            method="GET",
            status=status,
            headers={"Content-Type": "text/plain"},
            body=body,
            text=text,
            elapsed=0.0,
        )

    def get(self, url: str, **kwargs):
        self.audit.network += 1
        self.gets.append((url, kwargs))
        if ".surfacescope-qc-" in url:
            return self._snapshot(url, 403, "denied")
        status, text = self.get_responses.get(url, (403, "denied"))
        return self._snapshot(url, status, text)

    def request(self, spec: RequestSpec) -> ResponseSnapshot:
        self.audit.network += 1
        self.requests.append(spec)
        technique = spec.metadata.get("technique", "")
        status, text = self.responses.get(
            (spec.url, technique),
            self.responses.get(technique, (403, "denied")),
        )
        return self._snapshot(spec.url, status, text)

    def budget_usage(self, _scope: str) -> dict:
        return {"configured": True}


class _Config:
    def __init__(self, **bypass) -> None:
        self.bypass = {
            "mode": "fast",
            "initial_variants_per_url": 0,
            "max_variants_per_url": 0,
            **bypass,
        }

    def section(self, name: str):
        return self.bypass if name == "bypass" else {}


def _context(executor: _Executor, **config) -> SimpleNamespace:
    return SimpleNamespace(
        config=_Config(**config),
        results=ResultStore(),
        executor=executor,
        profile=SimpleNamespace(id="test-profile"),
        manifest=AssetManifest(),
    )


def _catalog() -> BypassCatalog:
    return BypassCatalog(AssetManifest())


def test_catalog_mode_contract_is_pinned_and_ordered() -> None:
    catalog = _catalog()
    quick = catalog.variants("https://example.test/admin", "quick")
    fast = catalog.variants("https://example.test/admin", "fast")
    balanced = catalog.variants("https://example.test/admin", "balanced")
    full = catalog.variants("https://example.test/admin", "full")

    assert len(quick) == 2
    assert len(fast) == 65
    assert len(balanced) == 313
    assert len(full) == 1698
    assert MODE_POLICIES["quick"].initial_variants == 2
    assert MODE_POLICIES["fast"].initial_variants == 27
    assert len(fast) <= MODE_POLICIES["fast"].max_variants
    assert len(balanced) > len(fast)
    assert len(full) > len(balanced)
    assert {variant.category for variant in balanced} >= {"referer"}
    referers = [variant for variant in balanced if variant.category == "referer"]
    assert len(referers) == 6
    assert all(variant.headers for variant in referers)
    assert all(next(iter(variant.headers.values())) == "https://example.test/admin" for variant in referers)

    initial = fast[: MODE_POLICIES["fast"].initial_variants]
    assert {
        "xff-loopback",
        "trailing-slash",
        "encoded-semicolon",
        "raw-semicolon",
        "x-original-url",
        "x-rewrite-url",
        "case-flip",
        "prefix-encoded-dot",
        "content-type-json",
        "host-localhost",
        "options-method",
        "method-override-header",
        "x-real-ip",
        "x-forwarded-proto-http",
        "host-trailing-dot",
        "user-agent-googlebot",
        "forwarded-loopback",
        "dual-url-header-confusion",
        "post-method",
        "suffix-json",
        "wildcard-star",
        "hop-by-hop-close",
        "follow-redirect",
        "host-url-combo",
        "proto-ssl-combo",
        "x-original-public",
        "encoded-first-char",
    } <= {variant.technique for variant in initial}


def test_upstream_transport_categories_are_explicitly_out_of_scope() -> None:
    catalog = _catalog()

    assert {"absolute_uri_variants", "duplicate_headers", "desync_payloads"} <= set(catalog.payloads)
    variants = catalog.variants("https://example.test/raw-check", "full")
    assert all(not variant.url.startswith("http://localhost") for variant in variants)
    assert all("HTTP/1.0" not in str(variant.data) for variant in variants)


def test_user_agent_variants_do_not_reuse_stale_browser_identities() -> None:
    catalog = _catalog()
    variants = catalog.variants("https://example.test/admin", "balanced")
    user_agents = {
        variant.headers["User-Agent"]
        for variant in variants
        if "User-Agent" in variant.headers
    }

    assert "curl/7.68.0" not in user_agents
    assert "python-requests/2.28" not in user_agents
    assert not any("Chrome/37" in value or "Chrome/42" in value for value in user_agents)
    assert any("Chrome/157.0.0.0" in value for value in user_agents)
    assert "curl/8.17.0" in user_agents


def test_upstream_http_categories_are_present_in_the_snapshot() -> None:
    payloads = _catalog().payloads
    required = {
        "fast_paths",
        "all_paths",
        "path_prefixes",
        "extensions",
        "wildcard_suffixes",
        "ip_headers",
        "ip_values",
        "url_override_headers",
        "url_override_variants",
        "host_override_headers",
        "host_localhost_headers",
        "typo_headers",
        "referer_variants",
        "content_types",
        "user_agents",
        "hop_by_hop",
        "methods",
        "case_switched_methods",
        "method_override_headers",
        "method_override_query",
        "post_body_tricks",
        "header_confusion",
        "forwarded_trust",
        "proto_confusion",
        "security_header_strip",
        "host_url_combo",
    }

    assert required <= set(payloads)
    assert len(payloads["all_paths"]) == 479
    assert len(payloads["referer_variants"]) == 6
    assert len(payloads["ip_headers"]) * len(payloads["ip_values"]) >= 1000


def test_root_equivalence_normalizes_dot_segments_and_encoded_dots() -> None:
    assert _normalized_site_path("/admin/..//") == "/"
    assert _normalized_site_path("/%2e%2e//") == "/"
    assert _normalized_site_path("/admin/../public") == "/public"
    assert _normalized_site_path("/admin") == "/admin"


def test_fast_uniform_denial_stops_after_the_curated_initial_set() -> None:
    executor = _Executor()
    result = Bypass403Adapter().scan(_context(executor), [Target(url="https://example.test/admin")], {})

    assert len(executor.requests) == 27
    assert result.stats["network_requests"] == 29
    assert result.stats["candidate_variants"] == 27
    assert result.stats["initial_variants"] == 27
    assert result.stats["adaptively_escalated"] is False
    assert result.stats["variants_tested"] == 27
    assert result.stats["accepted"] == 0


def test_fast_escalates_only_after_a_successful_or_redirect_delta() -> None:
    executor = _Executor({"xff-loopback": (302, "login redirect")})
    result = Bypass403Adapter().scan(_context(executor), [Target(url="https://example.test/admin")], {})

    assert result.stats["adaptively_escalated"] is True
    assert result.stats["generated_variants"] == 65
    assert result.stats["candidate_variants"] == 65
    assert result.stats["variants_tested"] == 65
    assert result.stats["network_requests"] == 67
    assert result.stats["accepted"] == 0


def test_a_404_delta_does_not_trigger_fast_escalation() -> None:
    executor = _Executor({"xff-loopback": (404, "not found variant")})
    result = Bypass403Adapter().scan(_context(executor), [Target(url="https://example.test/admin")], {})

    assert result.stats["adaptively_escalated"] is False
    assert result.stats["generated_variants"] == 65
    assert result.stats["candidate_variants"] == 27
    assert result.stats["variants_tested"] == 27


def test_fast_does_not_escalate_later_targets_after_one_target_escalates() -> None:
    executor = _Executor(
        {
            ("https://example.test/first", "xff-loopback"): (302, "login redirect"),
        }
    )
    result = Bypass403Adapter().scan(
        _context(executor),
        [
            Target(url="https://example.test/first"),
            Target(url="https://example.test/second"),
        ],
        {},
    )

    assert result.stats["escalated_targets"] == 1
    assert result.stats["generated_variants"] == 130
    assert result.stats["candidate_variants"] == 92
    assert result.stats["variants_tested"] == 92
    assert result.stats["network_requests"] == 96


def test_success_stops_immediately_and_records_finding() -> None:
    executor = _Executor({"xff-loopback": (200, "admin console")})
    result = Bypass403Adapter().scan(_context(executor), [Target(url="https://example.test/admin")], {})

    assert len(executor.requests) == 1
    assert result.stats["network_requests"] == 3
    assert len(result.findings) == 1
    assert result.findings[0].technique == "xff-loopback"
    assert result.findings[0].request_summary["headers"] == {"X-Forwarded-For": "127.0.0.1"}


def test_url_rewrite_must_differ_from_the_ordinary_root_page() -> None:
    executor = _Executor(
        {"x-original-url": (200, "ordinary home")},
        gets={"https://example.test/": (200, "ordinary home")},
    )
    result = Bypass403Adapter().scan(_context(executor), [Target(url="https://example.test/admin")], {})

    assert result.stats["accepted"] == 0
    assert result.stats["adaptively_escalated"] is False
    assert result.stats["network_requests"] == 30
    assert all(finding.technique != "x-original-url" for finding in result.findings)


def test_trailing_slash_hit_short_circuits_with_four_network_requests() -> None:
    executor = _Executor({"trailing-slash": (200, "admin console")})
    result = Bypass403Adapter().scan(_context(executor), [Target(url="https://example.test/admin")], {})

    assert len(executor.requests) == 2
    assert result.stats["network_requests"] == 4
    assert result.stats["accepted"] == 1
    assert result.findings[0].technique == "trailing-slash"


def test_trailing_slash_target_does_not_repeat_the_baseline_request() -> None:
    executor = _Executor()
    result = Bypass403Adapter().scan(
        _context(executor),
        [Target(url="https://example.test/admin/")],
        {},
    )

    wire_baseline_repeats = [
        spec
        for spec in executor.requests
        if spec.url == "https://example.test/admin/"
        and not spec.headers
        and spec.method == "GET"
        and spec.data is None
        and spec.allow_redirects is None
    ]
    assert wire_baseline_repeats == []
    assert any(spec.metadata["technique"] == "follow-redirect" for spec in executor.requests)
    assert len(executor.requests) == 27
    assert result.stats["network_requests"] == 29


def test_x_original_url_hit_with_root_calibration_costs_eight_requests() -> None:
    executor = _Executor(
        {"x-original-url": (200, "protected admin console")},
        gets={"https://example.test/": (403, "denied")},
    )
    result = Bypass403Adapter().scan(_context(executor), [Target(url="https://example.test/admin")], {})

    assert len(executor.requests) == 5
    assert result.stats["network_requests"] == 8
    assert result.stats["accepted"] == 1
    assert result.findings[0].technique == "x-original-url"


def test_quick_mode_sends_only_two_attack_requests() -> None:
    executor = _Executor()
    result = Bypass403Adapter().scan(
        _context(executor),
        [Target(url="https://example.test/admin")],
        {"mode": "quick"},
    )

    assert len(executor.requests) == 2
    assert result.stats["generated_variants"] == 2
    assert result.stats["candidate_variants"] == 2
    assert result.stats["network_requests"] == 4


def test_explicit_initial_and_variant_caps_override_mode_policy() -> None:
    executor = _Executor()
    result = Bypass403Adapter().scan(
        _context(executor, initial_variants_per_url=3, max_variants_per_url=4),
        [Target(url="https://example.test/admin")],
        {},
    )

    assert len(executor.requests) == 3
    assert result.stats["generated_variants"] == 4
    assert result.stats["candidate_variants"] == 3
