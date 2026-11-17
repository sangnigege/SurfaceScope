from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from surfacescope import pipeline
from surfacescope.adapters.packer_adapter import PackerAdapter
from surfacescope.models import Target

_PAGE = (
    "<html><head><title>demo</title></head><body>"
    '<script src="/static/app.js"></script>'
    '<script src="/static/vendor.js"></script>'
    "</body></html>"
)
_SCRIPT = "fetch('/api/users');\nconst buildId = 'demo';\n"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib callback
        if self.path in {"/", "/index.html"}:
            body, ctype = _PAGE, "text/html; charset=utf-8"
        elif self.path.startswith("/static/"):
            body, ctype = _SCRIPT, "application/javascript"
        else:
            self.send_error(404)
            return
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args) -> None:
        return


def _server() -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_loopback_packer_reports_asset_progress() -> None:
    server = _server()
    events: list[tuple[str, int, int]] = []
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        context, executor, _, _ = pipeline.create_context(
            include_env=False,
            artifact_root=None,
            progress=lambda name, done, total: events.append((name, done, total)),
        )
        try:
            PackerAdapter().scan(context, [Target(url=base + "/")], {"max_assets": 4})
        finally:
            executor.close()
    finally:
        server.shutdown()
        server.server_close()

    assert events, "packer did not report progress"
    assert all(name == "packer" for name, _, _ in events)
    assert all(total >= done >= 1 for _, done, total in events)
