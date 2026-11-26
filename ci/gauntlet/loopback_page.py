"""A local development page on the loopback interface, for cases that open one in a browser.

Ordinary browser work starts on a page the developer serves on this machine. The egress collector
must never be that page: any request it receives fails a protection case. This server answers
``GET`` with one small, fixed document and keeps nothing about the request.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = (
    b"<!doctype html><html><head><title>Local preview</title></head>"
    b"<body><h1 id='heading'>Local preview</h1></body></html>"
)


class LoopbackPage:
    """Serve one fixed page on ``127.0.0.1`` for the life of a case."""

    def __init__(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                """Keep the case output free of request logs."""
                return

            def do_GET(self):
                """Answer every path with the fixed page."""
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(PAGE)))
                self.end_headers()
                self.wfile.write(PAGE)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        """The page's address, with the port the operating system picked."""
        return f"http://127.0.0.1:{self.server.server_port}/"

    def __enter__(self) -> LoopbackPage:
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
