"""Owned loopback HTTP barrier on the native executor's qualified curl route."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class NativeEffectBarrier:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.server = None
        self.worker = None

    def __enter__(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/active":
                    self.send_error(404)
                    return
                owner.entered.set()
                if not owner.release.wait(30):
                    self.send_error(504)
                    return
                try:
                    self.send_response(200)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()
                except (BrokenPipeError, ConnectionResetError):
                    pass  # The deliberately cancelled native client has gone.

            def log_message(self, *_args):
                pass

        for port in [*range(3000, 3011), *range(8000, 8011)]:
            try:
                self.server = HTTPServer(("127.0.0.1", port), Handler)
            except OSError:
                continue
            break
        assert self.server is not None, "owned HTTP barrier needs a free qualified development port"
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}/active"
        self.worker = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.worker.start()
        return self

    def __exit__(self, *_args):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=5)
        assert not self.worker.is_alive(), "owned HTTP barrier did not stop"
