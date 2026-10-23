"""Real local synthetic PR/package service transport, outside agent custody."""
from __future__ import annotations

import argparse
import http.client
import http.server
import json
import os
import threading
from pathlib import Path

if __package__:
    from .developer_model_relay import LoopbackHTTPServer, UnixConnection, UnixHTTPServer, handler_factory
else:
    from developer_model_relay import LoopbackHTTPServer, UnixConnection, UnixHTTPServer, handler_factory

PACKAGE_ROUTES = {("GET", "/zod"), ("GET", "/zod/3.23.8"), ("GET", "/zod/-/zod-3.23.8.tgz")}
PR_ROUTES = {("POST", "/local/pulls")}


class ProviderHTTPServer(UnixHTTPServer):
    # Provider mutations must finish before the controller freezes final state.
    daemon_threads = False


class ProviderRelay:
    def __init__(self, socket_path: Path, *, service=None, packages=False):
        if not socket_path.is_absolute() or socket_path.exists():
            raise ValueError("provider transport needs a fresh owned Unix socket")
        self.path = socket_path
        if packages:
            handler = handler_factory(lambda: http.client.HTTPConnection("127.0.0.1", 8002, timeout=10),
                                      allowed_routes=PACKAGE_ROUTES)
        else:
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass

                def do_POST(self):
                    if self.path != "/local/pulls":
                        self.send_error(404)
                        return
                    try:
                        size = int(self.headers.get("Content-Length", "0"))
                        if not 1 <= size <= 8192 or self.headers.get("Transfer-Encoding"):
                            raise ValueError("bounded fixed JSON request required")
                        request = json.loads(self.rfile.read(size))
                        if not isinstance(request, dict) or set(request) - {
                                "repository_id", "head_branch", "base", "title"}:
                            raise ValueError("unknown PR arguments; caller SHA/actor is not accepted")
                        record = service.open_pull(request.get("repository_id", "run-repository"),
                            head_branch=request["head_branch"], base=request.get("base", "main"),
                            title=request["title"])
                        data = json.dumps(record, sort_keys=True).encode()
                        self.send_response(201)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                    except (ValueError, KeyError, OSError) as error:
                        self.send_error(400, str(error)[:256])

            handler = Handler
        self.server = ProviderHTTPServer(str(socket_path), handler)
        os.chmod(socket_path, 0o666)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.path.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fixed synthetic provider bridge in isolated agent namespace")
    parser.add_argument("--socket", required=True)
    parser.add_argument("--kind", choices=("packages", "pulls"), required=True)
    args = parser.parse_args(argv)
    if not Path(args.socket).is_absolute():
        parser.error("provider socket must be absolute")
    routes, port = (PACKAGE_ROUTES, 8002) if args.kind == "packages" else (PR_ROUTES, 8003)
    LoopbackHTTPServer(("127.0.0.1", port), handler_factory(lambda: UnixConnection(args.socket),
                                                        allowed_routes=routes)).serve_forever()


if __name__ == "__main__":
    main()
