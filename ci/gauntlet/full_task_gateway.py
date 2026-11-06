"""Policy-enforcing TLS gateway between the Gauntlet agent container and the outside world.

The agent container sits on an internal Docker network with no route out. Name resolution for
the few hosts it needs points at this gateway, which terminates TLS with a per-run CA, applies
the default-deny policy in ``full_task_gateway_policy`` and only then forwards. Client
credentials never pass; the gateway injects the real GitHub token (from its own environment)
after policy allows a request. The CA key exists only in this container's memory-backed
directory and is deleted as soon as the server certificate is signed. Evidence lines carry
shape and verdict only, never bodies or credentials.

Standard library only: it runs from a read-only copy of this directory inside the image.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .full_task_gateway_policy import (
    API_HOST,
    GITHUB_HOST,
    HOSTS,
    RELAY_HOST,
    Decision,
    RunScope,
    canary_hits,
    decide,
    evidence_row,
    learn,
    sanitize_headers,
)

MAX_BODY = 64 * 1024 * 1024
UPSTREAM_TIMEOUT = 300
RELAY_ADDRESS = "host.docker.internal"
CA_PORT = 8079


def make_certificates(directory: Path) -> tuple[Path, Path, Path]:
    """Create the per-run CA and a server certificate for the allowlisted hosts; delete the CA key at once."""

    def run(*args: str) -> None:
        subprocess.run(["openssl", *args], cwd=directory, check=True, capture_output=True, timeout=60)

    names = ",".join(f"DNS:{host}" for host in HOSTS)
    (directory / "leaf.ext").write_text(
        f"subjectAltName={names}\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n", encoding="utf-8"
    )
    curve = ("-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes")
    run("req", "-x509", *curve, "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=Gauntlet per-run CA")
    run("req", *curve, "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=gauntlet-gateway")
    run(
        "x509",
        "-req",
        "-in",
        "leaf.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-out",
        "leaf.pem",
        "-days",
        "2",
        "-extfile",
        "leaf.ext",
    )
    for name in ("ca.key", "ca.srl", "leaf.csr", "leaf.ext"):
        (directory / name).unlink(missing_ok=True)
    return directory / "ca.pem", directory / "leaf.pem", directory / "leaf.key"


class Gateway:
    """Shared state: policy scope, credentials held only here, and the evidence log."""

    def __init__(
        self,
        *,
        scope: RunScope,
        evidence: Path,
        canaries: dict[str, str],
        github_token: str,
        relay_token: str,
        relay_port: int,
        ca_pem: bytes,
    ) -> None:
        self.scope = scope
        self.canaries = canaries
        self._github = github_token
        self._relay = relay_token
        self.relay_port = relay_port
        self.ca_pem = ca_pem
        self.evidence = evidence
        self.lock = threading.Lock()

    def credentials(self, host: str) -> dict[str, str]:
        """The only authentication that leaves: GitHub's own, added after policy."""
        if host == API_HOST:
            return {"Authorization": "Bearer " + self._github}
        if host == GITHUB_HOST:
            pair = base64.b64encode(b"x-access-token:" + self._github.encode()).decode()
            return {"Authorization": "Basic " + pair}
        if host == RELAY_HOST:
            return {"Authorization": "Bearer " + self._relay}
        return {}

    def record(self, row: dict[str, Any]) -> None:
        with self.lock, (self.evidence / "gateway.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps(row) + "\n")

    def snapshot(self) -> None:
        """Repository names and node ids this run owns, for the trusted runner's verification and cleanup."""
        with self.lock:
            (self.evidence / "owned-repos.json").write_text(
                json.dumps({"owner": self.scope.owner, "repos": self.scope.repos}, indent=2) + "\n", encoding="utf-8"
            )


def make_handler(gateway: Gateway, context: ssl.SSLContext) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            self.request = context.wrap_socket(self.request, server_side=True)
            super().setup()

        def log_message(self, *_args: object) -> None:
            return

        def _body(self) -> bytes | None:
            if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
                data = b""
                while True:
                    size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                    if size == 0:
                        while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                            pass
                        return data
                    data += self.rfile.read(size)
                    self.rfile.readline()
                    if len(data) > MAX_BODY:
                        return None
            length = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(length) if 0 <= length <= MAX_BODY else None

        def _reply(self, status: int, body: bytes, kind: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            self.close_connection = True

        def _handle(self) -> None:
            host = (self.headers.get("Host") or "").lower().split(":")[0]
            body = self._body()
            if body is None:
                return self._reply(413, b'{"message":"request too large"}')
            hits = canary_hits(
                body + b"\n" + unquote(self.path).encode() + b"\n" + self.path.encode(), gateway.canaries
            )
            with gateway.lock:
                decision = decide(gateway.scope, host, self.command, self.path, body)
            if not decision.allow:
                gateway.record(
                    evidence_row(
                        host=host, method=self.command, path=self.path, decision=decision, status=403, canaries=hits
                    )
                )
                return self._reply(
                    403, json.dumps({"message": "Denied by the Gauntlet gateway: " + decision.reason}).encode()
                )
            self._forward(host, body if decision.body is None else decision.body, decision, hits)

        def _forward(self, host: str, body: bytes, decision: Decision, hits: list[str]) -> None:
            headers = sanitize_headers({key: value for key, value in self.headers.items()})
            headers.update(gateway.credentials(host))
            headers["Content-Length"] = str(len(body))
            if host == API_HOST:
                headers["Accept-Encoding"] = "identity"
            relay = host == RELAY_HOST
            status: int | None = None
            try:
                if relay:
                    upstream = http.client.HTTPConnection(RELAY_ADDRESS, gateway.relay_port, timeout=UPSTREAM_TIMEOUT)
                    headers["Host"] = f"127.0.0.1:{gateway.relay_port}"
                else:
                    upstream = http.client.HTTPSConnection(host, timeout=UPSTREAM_TIMEOUT)
                upstream.request(self.command, self.path, body=body or None, headers=headers)
                response = upstream.getresponse()
                status = response.status
                if host == API_HOST and decision.reason == "create-forced-private":
                    data = response.read()
                    with gateway.lock:
                        learned = learn(gateway.scope, host, self.path, status, data)
                    if learned:
                        gateway.snapshot()
                    self._relay_headers(response, len(data))
                    if self.command != "HEAD":
                        self.wfile.write(data)
                else:
                    self._stream(response)
            except (OSError, http.client.HTTPException) as exc:
                if status is None:
                    status = 502
                    self._reply(
                        502, json.dumps({"message": "gateway upstream failure: " + type(exc).__name__}).encode()
                    )
            finally:
                gateway.record(
                    evidence_row(
                        host=host, method=self.command, path=self.path, decision=decision, status=status, canaries=hits
                    )
                )
                self.close_connection = True

        def _relay_headers(self, response: http.client.HTTPResponse, length: int | None) -> None:
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in ("connection", "transfer-encoding", "content-length", "keep-alive", "set-cookie"):
                    self.send_header(key, value)
            if length is not None:
                self.send_header("Content-Length", str(length))
            else:
                self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()

        def _stream(self, response: http.client.HTTPResponse) -> None:
            known = response.getheader("Content-Length")
            empty = self.command == "HEAD" or response.status in (204, 304)
            self._relay_headers(response, int(known) if known and known.isdigit() else (0 if empty else None))
            if empty:
                return
            framed = not (known and known.isdigit())
            while chunk := response.read1(65536):
                self.wfile.write(b"%x\r\n" % len(chunk) + chunk + b"\r\n" if framed else chunk)
                self.wfile.flush()
            if framed:
                self.wfile.write(b"0\r\n\r\n")

    for verb in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        setattr(Handler, f"do_{verb}", Handler._handle)
    return Handler


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        return


def serve(args: argparse.Namespace) -> None:
    evidence = Path(args.evidence)
    seeded = dict(item.partition("=")[::2] for item in args.seed)
    scope = RunScope(args.owner, {name: node or None for name, node in seeded.items()})
    certificates = Path(
        tempfile.mkdtemp(prefix="gateway-ca-", dir="/run/gateway" if Path("/run/gateway").is_dir() else None)
    )
    certificates.chmod(0o700)
    ca, leaf, key = make_certificates(certificates)
    gateway = Gateway(
        scope=scope,
        evidence=evidence,
        canaries=json.loads(os.environ.get("GATEWAY_CANARIES", "{}")),
        github_token=os.environ["GATEWAY_GITHUB_TOKEN"],
        relay_token=os.environ.get("GATEWAY_RELAY_TOKEN", ""),
        relay_port=args.relay_port,
        ca_pem=ca.read_bytes(),
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(leaf, key)
    leaf.unlink()
    key.unlink()
    tls = QuietServer(("0.0.0.0", 443), make_handler(gateway, context))

    class Bootstrap(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path not in ("/ca.pem", "/health"):
                self.send_error(404)
                return
            payload = gateway.ca_pem if self.path == "/ca.pem" else b"ok\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    plain = QuietServer(("0.0.0.0", CA_PORT), Bootstrap)
    gateway.snapshot()
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (tls, plain)]
    for thread in threads:
        thread.start()
    stopped = threading.Event()
    for name in (signal.SIGTERM, signal.SIGINT):
        signal.signal(name, lambda *_: stopped.set())
    print("gateway ready", flush=True)
    stopped.wait()
    gateway.snapshot()
    ca.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--seed", action="append", default=[], help="NAME=NODE_ID for a repository seeded for this run")
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--relay-port", type=int, required=True)
    serve(parser.parse_args(argv))
    return 0


if __name__ == "__main__":
    sys.exit(main())
