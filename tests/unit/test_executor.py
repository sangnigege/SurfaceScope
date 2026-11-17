from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from surfacescope.errors import BudgetExceeded, CancelledError, RequestError
from surfacescope.models import RequestSpec
from surfacescope.traffic.executor import RequestExecutor, _budget_host
from surfacescope.traffic.profiles import RequestProfileRegistry


class _OriginService:
    def __init__(self) -> None:
        self.requests: list[dict[str, str]] = []
        self.redirect_url: str | None = None
        self.lock = threading.Lock()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _handler(self):
        service = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                with service.lock:
                    service.requests.append({"path": self.path, **dict(self.headers.items())})
                if self.path.startswith("/set-cookie"):
                    self.send_response(200)
                    self.send_header("Set-Cookie", "sid=from-server; Path=/")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path.startswith("/redirect-same"):
                    self.send_response(302)
                    self.send_header("Location", "/redirect-final")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path.startswith("/redirect-cross") and service.redirect_url:
                    self.send_response(302)
                    self.send_header("Location", service.redirect_url)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path.startswith("/no-store"):
                    self.send_response(200)
                    self.send_header("Cache-Control", "no-store, max-age=60")
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"ok")
                    return
                if self.path.startswith("/private"):
                    self.send_response(200)
                    self.send_header("Cache-Control", "private, max-age=60")
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"ok")
                    return
                if self.path.startswith("/server-error"):
                    self.send_response(503)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"no")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_args) -> None:
                return

        return Handler


@pytest.fixture()
def services():
    first = _OriginService()
    second = _OriginService()
    try:
        yield first, second
    finally:
        first.close()
        second.close()


@pytest.fixture()
def executor():
    profile = RequestProfileRegistry().get()
    instance = RequestExecutor(profile, timeout=2, max_workers=4)
    try:
        yield instance
    finally:
        instance.close()


def _spec(url: str, *, target_id: str = "target-a", **kwargs) -> RequestSpec:
    return RequestSpec(url=url, target_id=target_id, profile_id="chromium-desktop-stable", **kwargs)


def test_target_proxy_is_bound_to_target_identity(executor) -> None:
    executor.register_target_proxy("target-a", "http://127.0.0.1:8081")

    assert executor._target_proxies["target-a"] == {
        "http": "http://127.0.0.1:8081",
        "https": "http://127.0.0.1:8081",
    }


def test_environment_proxy_is_not_implicitly_trusted(services, executor, monkeypatch) -> None:
    first, _ = services
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "")

    snapshot = executor.request(_spec(first.base + "/env-proxy;probe", cache_policy="no-store"))

    assert snapshot.status == 200
    assert first.requests[-1]["path"] == "/env-proxy;probe"


def test_preserved_wire_path_keeps_query_params(services, executor) -> None:
    first, _ = services

    snapshot = executor.request(
        _spec(
            first.base + "/encoded%2Fpath;probe",
            params={"q": "a b"},
            metadata={"preserve_path_encoding": True},
            cache_policy="no-store",
        )
    )

    assert snapshot.status == 200
    assert first.requests[-1]["path"] == "/encoded%2Fpath;probe?q=a+b"


def test_registered_target_origin_is_bound_to_target_identity(executor) -> None:
    executor.register_target(
        "target-a",
        url="https://app.example.test/base",
        proxy="http://127.0.0.1:8081",
    )

    assert executor._target_origins["target-a"] == "https://app.example.test"
    assert executor._target_proxies["target-a"]["https"] == "http://127.0.0.1:8081"


def test_same_origin_keeps_explicit_auth_and_uses_browser_headers(services, executor) -> None:
    first, _ = services
    snapshot = executor.request(
        _spec(
            first.base + "/same",
            auth_scope=first.base,
            headers={"Authorization": "Bearer test-token"},
            cookies={"session": "secret"},
        )
    )

    received = first.requests[-1]
    assert snapshot.status == 200
    assert received["Authorization"] == "Bearer test-token"
    assert "session=secret" in received.get("Cookie", "")
    assert received["Sec-Fetch-Site"] == "none"
    assert received["Sec-Fetch-Mode"] == "navigate"
    assert "Content-Type" not in received
    assert received["User-Agent"] == executor.profile.user_agent
    assert snapshot.target_id == "target-a"
    assert snapshot.auth_scope == first.base


def test_explicit_attack_can_keep_content_type_on_a_get(services, executor) -> None:
    first, _ = services
    executor.request(
        _spec(
            first.base + "/content-api",
            headers={"Content-Type": "application/json"},
            metadata={"keep_content_type": True},
            cache_policy="no-store",
        )
    )

    assert first.requests[-1]["Content-Type"] == "application/json"


def test_cross_origin_strips_auth_cookies_and_sets_cross_site(services, executor) -> None:
    first, second = services
    executor.request(
        _spec(
            second.base + "/cross",
            auth_scope=first.base,
            headers={
                "Authorization": "Bearer test-token",
                "Cookie": "manual=secret",
                "X-API-Key": "api-secret",
            },
            cookies={"session": "secret"},
        )
    )

    received = second.requests[-1]
    assert "Authorization" not in received
    assert "Cookie" not in received
    assert "X-API-Key" not in received
    assert received["Sec-Fetch-Site"] == "cross-site"
    assert executor.audit.counts()["cross_origin_sent"] == 1


def test_named_auth_scope_cannot_leak_credentials_to_another_origin(services, executor) -> None:
    first, second = services
    executor.register_target("target-a", url=first.base)

    executor.request(
        _spec(
            second.base + "/cross-named-scope",
            auth_scope="user-a",
            headers={"Authorization": "Bearer test-token", "Cookie": "manual=secret"},
            cookies={"session": "secret"},
        )
    )

    received = second.requests[-1]
    assert "Authorization" not in received
    assert "Cookie" not in received
    assert received["Sec-Fetch-Site"] == "cross-site"


def test_followed_cross_origin_redirect_rebuilds_headers_and_sessions(services) -> None:
    first, second = services
    first.redirect_url = second.base + "/landing"
    profile = RequestProfileRegistry().get()
    following = RequestExecutor(profile, timeout=2, max_workers=4, follow_redirects=True)
    try:
        following.request(_spec(first.base + "/set-cookie", auth_scope=first.base))
        snapshot = following.request(
            _spec(
                first.base + "/redirect-cross",
                auth_scope=first.base,
                headers={"Authorization": "Bearer test-token", "Cookie": "manual=secret"},
                cookies={"session": "secret"},
            )
        )
    finally:
        following.close()

    first_hop = next(request for request in first.requests if request["path"] == "/redirect-cross")
    second_hop = second.requests[-1]
    assert snapshot.status == 200
    assert snapshot.final_url == second.base + "/landing"
    assert snapshot.history == [first.base + "/redirect-cross"]
    assert first_hop["Authorization"] == "Bearer test-token"
    assert "Authorization" not in second_hop
    assert "Cookie" not in second_hop
    assert second_hop["Sec-Fetch-Site"] == "same-site"
    assert second_hop["Referer"] == first.base + "/"
    assert "Authorization" not in snapshot.request_headers
    assert following.audit.counts()["network_sent"] == 3
    assert following.audit.counts()["cross_origin_sent"] == 1
    assert following.audit.counts()["redirects_followed"] == 1


def test_followed_same_origin_redirect_keeps_auth_and_recomputes_hop_headers(services) -> None:
    first, _ = services
    profile = RequestProfileRegistry().get()
    following = RequestExecutor(profile, timeout=2, max_workers=4, follow_redirects=True)
    try:
        snapshot = following.request(
            _spec(
                first.base + "/redirect-same",
                auth_scope=first.base,
                headers={"Authorization": "Bearer test-token"},
                cookies={"session": "secret"},
            )
        )
    finally:
        following.close()

    redirect_hop = first.requests[-2]
    final_hop = first.requests[-1]
    assert snapshot.status == 200
    assert snapshot.final_url == first.base + "/redirect-final"
    assert snapshot.history == [first.base + "/redirect-same"]
    assert redirect_hop["Sec-Fetch-Site"] == "none"
    assert final_hop["Authorization"] == "Bearer test-token"
    assert "session=secret" in final_hop.get("Cookie", "")
    assert final_hop["Sec-Fetch-Site"] == "same-origin"
    assert final_hop["Referer"] == first.base + "/redirect-same"


def test_redirects_are_not_followed_by_default(services, executor) -> None:
    first, second = services
    first.redirect_url = second.base + "/should-not-be-requested"

    snapshot = executor.request(_spec(first.base + "/redirect-cross", auth_scope=first.base))

    assert snapshot.status == 302
    assert snapshot.final_url == first.base + "/redirect-cross"
    assert snapshot.history == []
    assert second.requests == []


def test_zero_max_redirects_returns_first_redirect_instead_of_raising(services) -> None:
    first, second = services
    first.redirect_url = second.base + "/should-not-be-requested"
    profile = RequestProfileRegistry().get()
    following = RequestExecutor(
        profile,
        timeout=2,
        max_workers=4,
        follow_redirects=True,
        max_redirects=0,
    )
    try:
        snapshot = following.request(
            _spec(
                first.base + "/redirect-cross",
                auth_scope=first.base,
                cache_policy="no-store",
            )
        )
    finally:
        following.close()

    assert snapshot.status == 302
    assert snapshot.final_url == first.base + "/redirect-cross"
    assert snapshot.history == []
    assert second.requests == []
    assert following.audit.counts()["redirect_rejected"] == 1


def test_each_redirect_hop_consumes_request_budget(services) -> None:
    first, second = services
    first.redirect_url = second.base + "/landing"
    profile = RequestProfileRegistry().get()
    following = RequestExecutor(profile, timeout=2, max_workers=4, follow_redirects=True)
    following.configure_budget("tiny", max_total=1)
    try:
        with pytest.raises(BudgetExceeded):
            following.request(
                _spec(
                    first.base + "/redirect-cross",
                    auth_scope=first.base,
                    budget_scope="tiny",
                    cache_policy="no-store",
                )
            )
    finally:
        following.close()

    assert following.audit.counts()["network_sent"] == 1


def test_sessions_are_partitioned_by_auth_scope(services, executor) -> None:
    first, _ = services
    executor.request(_spec(first.base + "/set-cookie", auth_scope="scope-a"))
    executor.request(_spec(first.base + "/scope-a", auth_scope="scope-a"))
    executor.request(_spec(first.base + "/scope-b", auth_scope="scope-b", target_id="target-b"))

    scope_a = first.requests[-2]
    scope_b = first.requests[-1]
    assert "sid=from-server" in scope_a.get("Cookie", "")
    assert "Cookie" not in scope_b


def test_request_cache_is_shared_and_inflight_is_bounded(services, executor) -> None:
    first, _ = services
    spec = _spec(first.base + "/cached", auth_scope=first.base)

    first_result = executor.request(spec)
    second_result = executor.request(spec)

    assert first_result.from_cache is False
    assert second_result.from_cache is True
    assert len(first.requests) == 1
    assert executor.audit.counts()["cache_hit"] == 1


def test_cache_key_includes_wire_metadata(services, executor) -> None:
    first, _ = services
    url = first.base + "/metadata-cache"
    one = executor.request(
        _spec(url, auth_scope=first.base, metadata={"referer": "https://one.example.test/"})
    )
    two = executor.request(
        _spec(url, auth_scope=first.base, metadata={"referer": "https://two.example.test/"})
    )

    assert one.from_cache is False
    assert two.from_cache is False
    assert len(first.requests) == 2
    assert first.requests[0]["Referer"] == "https://one.example.test/"
    assert first.requests[1]["Referer"] == "https://two.example.test/"


def test_cross_origin_clears_destination_session_cookies(services, executor) -> None:
    first, second = services
    executor.request(_spec(second.base + "/set-cookie", auth_scope=second.base))
    executor.request(
        _spec(
            second.base + "/cross-after-cookie",
            auth_scope="",
            auth_origin=first.base,
        )
    )

    received = second.requests[-1]
    assert "Cookie" not in received


def test_budget_host_normalises_default_ports() -> None:
    assert _budget_host("http://Example.test:80/a") == "example.test"
    assert _budget_host("https://example.test:443/a") == "example.test"
    assert _budget_host("https://example.test:8443/a") == "example.test:8443"


def test_responses_that_mutate_or_forbid_storage_are_not_cached(services, executor) -> None:
    first, _ = services
    for path in ("/set-cookie", "/no-store", "/private", "/server-error"):
        spec = _spec(first.base + path, auth_scope=first.base)
        first_result = executor.request(spec)
        second_result = executor.request(spec)
        assert first_result.from_cache is False
        assert second_result.from_cache is False

    assert len(first.requests) == 8


def test_budget_is_enforced_at_request_level(services, executor) -> None:
    first, _ = services
    executor.configure_budget("tiny", max_total=1)
    executor.request(_spec(first.base + "/one", budget_scope="tiny", cache_policy="no-store"))

    with pytest.raises(BudgetExceeded):
        executor.request(_spec(first.base + "/two", budget_scope="tiny", cache_policy="no-store"))


def test_parent_and_component_budgets_are_reserved_atomically(services, executor) -> None:
    first, _ = services
    executor.configure_budget("default", max_total=10)
    executor.configure_budget("child", max_total=1)
    executor.request(
        _spec(first.base + "/one", budget_scope="child", cache_policy="no-store")
    )

    with pytest.raises(BudgetExceeded, match="scope child"):
        executor.request(
            _spec(first.base + "/two", budget_scope="child", cache_policy="no-store")
        )

    assert executor.budget_usage("default")["total"] == 1
    assert executor.budget_usage("child")["total"] == 1


def test_run_many_reuses_one_pool_and_propagates_worker_errors(executor) -> None:
    first_batch = sorted(executor.run_many(lambda value: value * 2, range(3), max_workers=2))
    pool_after_first = executor._pool
    second_batch = sorted(executor.run_many(lambda value: value + 1, range(3), max_workers=2))

    assert first_batch == [0, 2, 4]
    assert second_batch == [1, 2, 3]
    assert pool_after_first is executor._pool

    with pytest.raises(ValueError, match="boom"):
        list(executor.run_many(lambda _value: (_ for _ in ()).throw(ValueError("boom")), [1]))


def test_cancel_and_close_stop_new_work(services, executor) -> None:
    first, _ = services
    executor.cancel()
    with pytest.raises(CancelledError):
        executor.request(_spec(first.base + "/cancelled", cache_policy="no-store"))
    with pytest.raises(CancelledError):
        list(executor.run_many(lambda value: value, [1]))

    executor.close()
    executor.close()
    assert executor.closed is True
    with pytest.raises(RequestError, match="closed"):
        executor.request(_spec(first.base + "/closed"))
    with pytest.raises(RequestError, match="closed"):
        list(executor.run_many(lambda value: value, [1]))
