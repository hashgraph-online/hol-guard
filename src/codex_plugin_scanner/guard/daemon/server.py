"""Local Guard daemon helpers."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..store import GuardStore


class _GuardDaemonHttpServer(ThreadingHTTPServer):
    store: GuardStore


class _GuardDaemonHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        if self.path == "/healthz":
            self._write_json(
                {
                    "ok": True,
                    "receipts": len(store.list_receipts(limit=500)),
                    "tables": store.list_table_names(),
                }
            )
            return
        if self.path == "/receipts":
            self._write_json({"items": store.list_receipts(limit=200)})
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _write_json(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class GuardDaemonServer:
    """Small local daemon for health and receipt introspection."""

    def __init__(self, store: GuardStore, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = _GuardDaemonHttpServer((host, port), _GuardDaemonHandler)
        self._server.store = store
        self.port = int(self._server.server_address[1])
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
