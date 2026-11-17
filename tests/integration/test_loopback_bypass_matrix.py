from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from surfacescope import pipeline
from surfacescope.adapters.bypass403_adapter import Bypass403Adapter
from surfacescope.models import Target

Responder = Callable[[str, object, str], tuple[int, str, dict[str, str]]]


def _reply(status: int, body: str, **headers: str) -> tuple[int, str, dict[str, str]]:
    return status, body, headers


def _is_qc(path: str) -> bool:
    return path.startswith("/.surfacescope-qc-")


def _positive(predicate: Callable[[str, object, str], bool]) -> Responder:
    def respond(path: str, headers: object, method: str) -> tuple[int, str, dict[str, str]]:
        if _is_qc(path):
            return _reply(403, "denied")
        if predicate(path, headers, method):
            return _reply(200, "admin console")
        if path == "/":
            return _reply(404, "root not found")
        return _reply(403, "denied")

    return respond


def _header(name: str, value: str) -> Callable[[str, object, str], bool]:
    return lambda _path, headers, _method: headers.get(name) == value


def _uniform_denial(_path: str, _headers: object, _method: str) -> tuple[int, str, dict[str, str]]:
    return _reply(403, "denied")


def _login_redirect(path: str, _headers: object, _method: str) -> tuple[int, str, dict[str, str]]:
    if path == "/admin":
        return _reply(403, "denied")
    return _reply(302, "login", Location="/login")


def _rate_limited(path: str, _headers: object, _method: str) -> tuple[int, str, dict[str, str]]:
    if path == "/admin":
        return _reply(403, "denied")
    return _reply(429, "slow down")


def _soft_404(path: str, _headers: object, _method: str) -> tuple[int, str, dict[str, str]]:
    if path == "/admin":
        return _reply(403, "denied")
    return _reply(200, "not found page", **{"Content-Type": "text/html"})


def _root_page(path: str, headers: object, _method: str) -> tuple[int, str, dict[str, str]]:
    if _is_qc(path):
        return _reply(403, "denied")
    if path == "/" or headers.get("X-Original-URL") or headers.get("X-Rewrite-URL"):
        return _reply(200, "ordinary home page", **{"Content-Type": "text/html"})
    return _reply(403, "denied")


def _waf_noise(path: str, headers: object, _method: str) -> tuple[int, str, dict[str, str]]:
    if path == "/admin" and "X-Forwarded-For" not in headers:
        return _reply(403, "denied")
    if _is_qc(path):
        return _reply(403, "denied")
    return _reply(403, "denied " + ("x" * 256))


@contextmanager
def _serve(responder: Responder) -> Iterator[tuple[str, list[tuple[str, str, dict[str, str]]]]]:
    hits: list[tuple[str, str, dict[str, str]]] = []

    class Handler(BaseHTTPRequestHandler):
        def _dispatch(self) -> None:
            hits.append((self.command, self.path, dict(self.headers.items())))
            status, body, headers = responder(self.path, self.headers, self.command)
            payload = body.encode("utf-8")
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        do_GET = _dispatch
        do_POST = _dispatch
        do_PUT = _dispatch
        do_PATCH = _dispatch
        do_DELETE = _dispatch
        do_OPTIONS = _dispatch
        do_HEAD = _dispatch
        do_TRACE = _dispatch

        def log_message(self, *_args) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", hits
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@dataclass(frozen=True)
class _Case:
    name: str
    responder: Responder
    technique: str | None
    network_requests: int


_CASES = (
    _Case("xff", _positive(_header("X-Forwarded-For", "127.0.0.1")), "xff-loopback", 3),
    _Case("trailing-slash", _positive(lambda path, _, __: path == "/admin/"), "trailing-slash", 4),
    _Case(
        "encoded-semicolon",
        _positive(lambda path, _, __: path.lower() == "/admin%3b"),
        "encoded-semicolon",
        5,
    ),
    _Case(
        "raw-semicolon",
        _positive(lambda path, _, __: path == "/admin;"),
        "raw-semicolon",
        6,
    ),
    _Case(
        "x-original-url",
        _positive(lambda path, headers, _: path == "/" and headers.get("X-Original-URL") == "/admin"),
        "x-original-url",
        8,
    ),
    _Case(
        "x-rewrite-url",
        _positive(lambda path, headers, _: path == "/" and headers.get("X-Rewrite-URL") == "/admin"),
        "x-rewrite-url",
        9,
    ),
    _Case("case-flip", _positive(lambda path, _, __: path == "/ADMIN"), "case-flip", 9),
    _Case(
        "prefix-encoded-dot",
        _positive(lambda path, _, __: path.lower() == "/%2e/admin"),
        "prefix-encoded-dot",
        10,
    ),
    _Case(
        "content-type-json",
        _positive(lambda _, headers, __: headers.get("Content-Type") == "application/json"),
        "content-type-json",
        11,
    ),
    _Case("host-localhost", _positive(_header("Host", "localhost")), "host-localhost", 12),
    _Case(
        "options-method",
        _positive(lambda path, _, method: path == "/admin" and method == "OPTIONS"),
        "options-method",
        13,
    ),
    _Case(
        "method-override-header",
        _positive(
            lambda path, headers, method: (
                path == "/admin"
                and method == "POST"
                and headers.get("X-HTTP-Method-Override") == "PUT"
            )
        ),
        "method-override-header",
        14,
    ),
    _Case("x-real-ip", _positive(_header("X-Real-IP", "127.0.0.1")), "x-real-ip", 15),
    _Case(
        "x-forwarded-proto",
        _positive(_header("X-Forwarded-Proto", "http")),
        "x-forwarded-proto-http",
        16,
    ),
    _Case(
        "host-trailing-dot",
        _positive(lambda _, headers, __: headers.get("Host", "").endswith(".")),
        "host-trailing-dot",
        17,
    ),
    _Case(
        "googlebot",
        _positive(lambda _, headers, __: "Googlebot" in headers.get("User-Agent", "")),
        "user-agent-googlebot",
        18,
    ),
    _Case(
        "forwarded",
        _positive(lambda _, headers, __: headers.get("Forwarded", "").startswith("for=127.0.0.1")),
        "forwarded-loopback",
        19,
    ),
    _Case(
        "dual-url-header",
        _positive(
            lambda path, headers, _: (
                path == "/admin"
                and headers.get("X-Original-URL") == "/admin"
                and headers.get("X-Rewrite-URL") == "/admin"
            )
        ),
        "dual-url-header-confusion",
        21,
    ),
    _Case(
        "post-method",
        _positive(
            lambda path, headers, method: (
                path == "/admin"
                and method == "POST"
                and not headers.get("X-HTTP-Method-Override")
                and not headers.get("Content-Type")
            )
        ),
        "post-method",
        21,
    ),
    _Case("suffix-json", _positive(lambda path, _, __: path == "/admin.json"), "suffix-json", 22),
    _Case("wildcard-star", _positive(lambda path, _, __: path == "/admin/*"), "wildcard-star", 23),
    _Case("hop-by-hop-close", _positive(_header("Connection", "close, X-Forwarded-For")), "hop-by-hop-close", 24),
    _Case(
        "host-url-combo",
        _positive(
            lambda path, headers, _: (
                path == "/admin"
                and headers.get("X-Forwarded-Host") == "127.0.0.1"
                and bool(headers.get("X-Original-URL"))
            )
        ),
        "host-url-combo",
        27,
    ),
    _Case(
        "proto-ssl",
        _positive(
            lambda _, headers, __: (
                headers.get("X-Forwarded-Proto") == "https"
                and headers.get("X-Forwarded-Ssl") == "on"
            )
        ),
        "proto-ssl-combo",
        27,
    ),
    _Case(
        "x-original-public",
        _positive(lambda _path, headers, _: headers.get("X-Original-URL") == "/public"),
        "x-original-public",
        29,
    ),
    _Case(
        "encoded-first-char",
        _positive(lambda path, _, __: path.lower() == "/%61dmin"),
        "encoded-first-char",
        29,
    ),
    _Case("uniform-403", _uniform_denial, None, 29),
    _Case("login-302", _login_redirect, None, 29),
    _Case("rate-limit-429", _rate_limited, None, 29),
    _Case("soft-404", _soft_404, None, 29),
    _Case("ordinary-root-page", _root_page, None, 30),
    _Case("waf-length-noise", _waf_noise, None, 29),
)


@pytest.mark.parametrize("case", _CASES, ids=[case.name for case in _CASES])
def test_fast_mode_loopback_matrix(case: _Case) -> None:
    with _serve(case.responder) as (base, hits):
        context, executor, _, _ = pipeline.create_context(include_env=False, artifact_root=None)
        try:
            result = Bypass403Adapter().scan(
                context,
                [Target(url=base + "/admin")],
                {"mode": "fast"},
            )
        finally:
            executor.close()

    techniques = [finding.technique for finding in result.findings]
    if case.technique is None:
        assert techniques == []
    else:
        assert techniques == [case.technique], [path for _method, path, _headers in hits]
    assert result.stats["network_requests"] == case.network_requests
    assert len(hits) == case.network_requests


def test_fast_mode_does_not_send_a_root_calibration_for_non_2xx_rewrite_miss() -> None:
    responder = _positive(lambda _path, _headers, _method: False)
    with _serve(responder) as (base, hits):
        context, executor, _, _ = pipeline.create_context(include_env=False, artifact_root=None)
        try:
            result = Bypass403Adapter().scan(
                context,
                [Target(url=base + "/admin")],
                {"mode": "fast"},
            )
        finally:
            executor.close()

    assert result.findings == []
    assert result.stats["network_requests"] == 29
    root_hops = [headers for method, path, headers in hits if method == "GET" and path == "/"]
    calibrations = [
        headers
        for headers in root_hops
        if not any(key.lower() in {"x-original-url", "x-rewrite-url"} for key in headers)
    ]
    assert calibrations == []
    assert len(root_hops) == 2


def test_balanced_mode_rejects_traversal_that_normalizes_to_a_public_root() -> None:
    def responder(path: str, _headers: object, _method: str) -> tuple[int, str, dict[str, str]]:
        if _is_qc(path):
            return _reply(403, "denied")
        if path == "/":
            return _reply(200, "public home page")
        return _reply(403, "denied")

    with _serve(responder) as (base, _hits):
        context, executor, _, _ = pipeline.create_context(include_env=False, artifact_root=None)
        try:
            result = Bypass403Adapter().scan(
                context,
                [Target(url=base + "/admin")],
                {"mode": "balanced"},
            )
        finally:
            executor.close()

    assert result.findings == []
    assert result.stats["accepted"] == 0
