from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from surfacescope import pipeline
from surfacescope.adapters.swagger_adapter import SwaggerAdapter
from surfacescope.models import Target


class _Handler(BaseHTTPRequestHandler):
    methods: list[tuple[str, str]] = []

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self.methods.append((self.command, self.path))
        if self.path == "/swagger.json":
            spec = {
                "openapi": "3.0.3",
                "servers": [{"url": "/"}],
                "paths": {
                    "/ping": {"get": {"operationId": "ping"}},
                    "/health": {"head": {"operationId": "health"}},
                    "/write": {"post": {"operationId": "write"}},
                },
            }
            self._send(200, json.dumps(spec).encode())
            return
        self._send(200, b"<html>ok</html>", "text/html")

    def do_HEAD(self) -> None:  # noqa: N802
        self.methods.append((self.command, self.path))
        self._send(200, b"")

    def log_message(self, *_args) -> None:
        return


def test_swagger_probe_uses_declared_safe_methods_without_unsafe_writes() -> None:
    _Handler.methods = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        context, executor, _, _ = pipeline.create_context(include_env=False, artifact_root=None)
        try:
            result = SwaggerAdapter().scan(context, [Target(url=base + "/")], {"max_requests": 20})
        finally:
            executor.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert ("GET", "/ping") in _Handler.methods
    assert ("HEAD", "/health") in _Handler.methods
    assert ("POST", "/write") not in _Handler.methods
    assert result.stats["documents_parsed"] == 1
    assert result.stats["methods"] == {"GET": 1, "HEAD": 1}
