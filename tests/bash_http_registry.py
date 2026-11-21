"""Disposable HTTP registry for real CLI and SDK execution lanes."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


@dataclass
class Registry:
    port: int
    requests: list[tuple[str, str]]

    def helper(self) -> str:
        source = Path(__file__).parent / "fixtures" / "script_approvals" / "fixture-http-registry"
        return source.read_text().replace("127.0.0.1:3001", f"127.0.0.1:{self.port}")


@contextmanager
def local_registry() -> Iterator[Registry]:
    requests: list[tuple[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(("GET", self.path))
            parts = self.path.strip("/").split("/")
            if len(parts) != 2 or parts[0] not in {"alpha", "beta"} or parts[1] not in {"list", "inspect"}:
                self.send_error(404)
                return
            repository, action = parts
            body = (
                f"{repository}/current\n{repository}/obsolete\n"
                if action == "list"
                else f"{repository}\tlocal metadata\n"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_DELETE(self) -> None:
            requests.append(("DELETE", self.path))
            self.send_error(403)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - base class signature
            pass

    server = None
    for port in [*range(3000, 3011), *range(8000, 8011)]:
        try:
            server = HTTPServer(("127.0.0.1", port), Handler)
        except OSError:
            continue
        break
    assert server is not None, "the isolated registry needs a free development port"
    worker = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    worker.start()
    try:
        yield Registry(server.server_port, requests)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        assert not worker.is_alive()
