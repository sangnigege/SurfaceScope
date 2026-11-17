from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from surfacescope import pipeline
from surfacescope.adapters.bypass403_adapter import Bypass403Adapter
from surfacescope.models import Target


class _Handler(BaseHTTPRequestHandler):
    hits: list[str] = []

    def _record(self) -> None:
        self.hits.append(f"{self.command} {self.path}")

    def _deny(self) -> None:
        self.send_response(403)
        self.end_headers()
        self.wfile.write(b"denied")

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback
        self._record()
        if self.path in {"/admin/", "/admin/."} or self.path.startswith("/admin/..;/"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"admin console")
            return
        self._deny()

    def do_POST(self) -> None:  # noqa: N802 - stdlib callback
        self._record()
        self._deny()

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib callback
        self._record()
        self._deny()

    def log_message(self, *_args) -> None:
        return


def _server():
    _Handler.hits = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_loopback_bypass_stops_after_first_success() -> None:
    server, thread = _server()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        context, executor, _, _ = pipeline.create_context(include_env=False, artifact_root=None)
        try:
            result = Bypass403Adapter().scan(
                context,
                [Target(url=base + "/admin")],
                {"mode": "fast"},
            )
        finally:
            executor.close()

        assert len(result.findings) == 1
        assert result.findings[0].technique == "trailing-slash"
        assert result.stats["variants_tested"] == 2
        assert len(_Handler.hits) == 4
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_loopback_bypass_uniform_denial_skips_root_calibration() -> None:
    server, thread = _server()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        context, executor, _, _ = pipeline.create_context(include_env=False, artifact_root=None)
        try:
            result = Bypass403Adapter().scan(
                context,
                [Target(url=base + "/private")],
                {"mode": "fast"},
            )
        finally:
            executor.close()

        assert result.stats["variants_tested"] == 27
        assert result.stats["accepted"] == 0
        assert result.stats["network_requests"] == 29
        assert len(_Handler.hits) == 29
        assert sum(hit.startswith("POST ") for hit in _Handler.hits) == 2
        assert sum(hit.startswith("OPTIONS ") for hit in _Handler.hits) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

def test_loopback_bypass_reports_variant_progress() -> None:
    server, thread = _server()
    events: list[tuple[str, int, int]] = []
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        context, executor, _, _ = pipeline.create_context(
            include_env=False,
            artifact_root=None,
            progress=lambda name, done, total: events.append((name, done, total)),
        )
        try:
            Bypass403Adapter().scan(context, [Target(url=base + "/admin")], {"mode": "fast"})
        finally:
            executor.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert events, "bypass403 did not report progress"
    assert all(name == "bypass403" for name, _, _ in events)
    assert events[-1][1] >= 1
    assert all(total >= done for _, done, total in events)