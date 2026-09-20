"""A deterministic, isolated authorization failure for native hook subprocesses."""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlencode

_CHILD_NETWORK_GUARD = """\
import json
import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlsplit

_root = Path(os.environ["HOL_GUARD_TEST_NETWORK_GUARD_DIR"])
_endpoint = urlsplit(json.loads(os.environ["HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON"])["sync_url"])
_address = ("127.0.0.1", _endpoint.port)
assert _endpoint.hostname == _address[0] and _endpoint.scheme == "http"

def _audit(event, args):
    if event == "socket.getaddrinfo":
        allowed = (args[0], args[1]) == _address
    elif event in {"socket.gethostbyname", "socket.gethostbyaddr"}:
        allowed = args[0] == _address[0]
    elif event == "socket.getnameinfo":
        allowed = args[0] == _address
    elif event in {"socket.connect", "socket.sendto", "socket.sendmsg"}:
        allowed = args[-1] == _address
    elif event == "socket.bind":
        # urllib3 probes IPv6 support on a socket it immediately closes.
        allowed = args[0].family == socket.AF_INET6 and args[-1] == ("::1", 0)
    else:
        return
    if not allowed:
        with (_root / "denied.txt").open("a", encoding="utf-8") as output:
            output.write(event + "\\n")
        raise RuntimeError("The hook fixture refused an unexpected network operation.")

sys.addaudithook(_audit)
(_root / "installed.txt").write_text("installed", encoding="utf-8")
"""


@contextmanager
def expired_cloud_authorization(workspace_id: str) -> Iterator[dict[str, str]]:
    """Keep the real child on a known 401 path without contacting a live issuer."""

    assert os.environ.get("PYTEST_CURRENT_TEST"), "This helper is only for pytest subprocesses."
    query = urlencode({"workspaceId": workspace_id})
    evaluate_route = ("POST", f"/api/guard/supply-chain/evaluate?{query}")
    expected_routes = {
        ("GET", f"/api/guard/supply-chain/bundle?{query}"),
        evaluate_route,
    }
    observed_routes: list[tuple[str, str]] = []

    class AuthorizationExpiredHandler(BaseHTTPRequestHandler):
        def reject_authorization(self) -> None:
            route = (self.command, self.path)
            observed_routes.append(route)
            body = b'{"error":"invalid_token"}'
            self.send_response(401 if route in expected_routes else 500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            self.reject_authorization()

        def do_POST(self) -> None:
            self.reject_authorization()

        def log_message(self, message_format: str, *args: object) -> None:
            return

    with HTTPServer(("127.0.0.1", 0), AuthorizationExpiredHandler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory(prefix="guard-hook-auth-fixture-") as directory:
                root = Path(directory)
                (root / "sitecustomize.py").write_text(_CHILD_NETWORK_GUARD, encoding="utf-8")
                inherited_pythonpath = os.environ.get("PYTHONPATH")
                pythonpath = directory + (os.pathsep + inherited_pythonpath if inherited_pythonpath else "")
                yield {
                    **os.environ,
                    "PYTHONPATH": pythonpath,
                    "HOL_GUARD_TEST_NETWORK_GUARD_DIR": directory,
                    "HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON": json.dumps(
                        {
                            "sync_url": f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
                            "access_token": "fixture-expired-session",
                        }
                    ),
                }
                assert (root / "installed.txt").read_text(encoding="utf-8") == "installed"
                assert not (root / "denied.txt").exists(), "The child attempted an unexpected network operation."
                assert evaluate_route in observed_routes, "The child did not use the controlled authorization fixture."
                assert all(route in expected_routes for route in observed_routes)
        finally:
            server.shutdown()
            thread.join(timeout=2)
            assert not thread.is_alive(), "The authorization fixture did not shut down."
