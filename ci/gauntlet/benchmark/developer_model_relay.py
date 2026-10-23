"""Fixed local-model HTTP transport across an isolated agent's Unix socket.

The agent container has network=none. Only these two OpenAI routes can reach
the declared credential-free local model; no general network proxy is exposed.
"""
from __future__ import annotations

import argparse
import http.client
import http.server
import os
import socket
import socketserver
import threading
import time
from pathlib import Path

ROUTES = {("GET", "/v1/models"), ("POST", "/v1/chat/completions")}
MAX_BODY = 2 * 1024 * 1024


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("benchmark-model", timeout=180)
        self.socket_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def handler_factory(connection_factory, authorize=lambda: True, *, allowed_routes=ROUTES,
                    request_validator=None, response_observer=None, drain_after_disconnect=False):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_):
            pass

        def do_GET(self):
            self.forward()

        def do_POST(self):
            self.forward()

        def _drain_denied_body(self):
            """Let a bounded in-flight POST finish before returning a refusal."""
            if self.command != 'POST' or self.headers.get('Transfer-Encoding'):
                return
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if 0 <= size <= MAX_BODY:
                    self.connection.settimeout(2)
                    self.rfile.read(size)
            except (OSError, ValueError):
                pass

        def forward(self):
            if (self.command, self.path) not in allowed_routes:
                self.send_error(403, "fixed local model route only")
                return
            if not authorize():
                self._drain_denied_body()
                self.send_error(403, "fixed local model route only")
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            if not 0 <= size <= MAX_BODY or self.headers.get("Transfer-Encoding"):
                self.send_error(413)
                return
            self.connection.settimeout(180)
            data = self.rfile.read(size)
            if len(data) != size:
                self.send_error(400)
                return
            if request_validator is not None:
                try:
                    request_validator(self.command, self.path, data)
                except (ValueError, PermissionError):
                    self.send_error(403, 'controller request validation refused')
                    return
            connection = None
            provider_socket = None
            observed, complete, response = bytearray(), False, None
            delivery_complete, drain_deadline = True, None
            try:
                connection = connection_factory()
                connection.request(self.command, self.path, body=data,
                                   headers={"Content-Type": "application/json", "Content-Length": str(size)})
                response = connection.getresponse()
                if drain_after_disconnect:
                    provider_socket = getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None)
                    if provider_socket is None:
                        raise ValueError('actual provider socket required for bounded response drain')
                    track = getattr(connection, 'observe_provider_socket', None)
                    if track is not None:
                        track(provider_socket)

                def write_downstream(action):
                    nonlocal delivery_complete, drain_deadline
                    if not delivery_complete:
                        return
                    try:
                        action()
                    except OSError:
                        if not drain_after_disconnect:
                            raise
                        delivery_complete, self.close_connection = False, True
                        drain_deadline = time.monotonic() + 5

                def headers():
                    self.send_response(response.status)
                    self.send_header("Content-Type", response.getheader("Content-Type", "application/json"))
                    self.send_header("Connection", "close")
                    self.end_headers()

                write_downstream(headers)
                transferred = 0
                while True:
                    if drain_deadline is not None:
                        remaining = drain_deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError('same provider response drain deadline exceeded')
                        provider_socket.settimeout(remaining)
                    chunk = response.read1(16_384)
                    if not chunk:
                        complete = True
                        break
                    transferred += len(chunk)
                    if transferred > 8 * 1024 * 1024:
                        raise ValueError("model response exceeds transport bound")
                    if response_observer is not None:
                        observed.extend(chunk)
                    def write_chunk(data=chunk):
                        self.wfile.write(data)
                        self.wfile.flush()
                    write_downstream(write_chunk)
            except (OSError, ValueError, http.client.HTTPException):
                self.close_connection = True
            finally:
                try:
                    if response_observer is not None:
                        metadata = ({'delivery_complete': complete and delivery_complete}
                                    if drain_after_disconnect else {})
                        response_observer(self.command, self.path, response.status if response else None,
                            response.getheader('Content-Type', '') if response else '',
                            bytes(observed), complete, **metadata)
                finally:
                    if response is not None:
                        response.close()
                    if provider_socket is not None:
                        forget = getattr(connection, 'forget_provider_socket', None)
                        if forget is not None:
                            forget(provider_socket)
                    if connection is not None:
                        connection.close()

    return Handler


class BoundedThreads(socketserver.ThreadingMixIn):
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        request.settimeout(180)
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, *args):
        try:
            super().process_request_thread(*args)
        finally:
            self.slots.release()


class UnixHTTPServer(BoundedThreads, http.server.HTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "benchmark-model", 0


class FixedModelRelay:
    def __init__(self, path: Path, *, host: str, port: int, max_requests: int = 100):
        if not path.is_absolute() or path.exists() or host != "192.168.5.2" or port != 8001:
            raise ValueError("relay requires fresh owned socket and exact local Lima model endpoint")
        self.path, self.count = path, 0
        self.lock = threading.Lock()

        def authorize():
            with self.lock:
                self.count += 1
                return self.count <= max_requests

        self.server = UnixHTTPServer(str(path), handler_factory(
            lambda: http.client.HTTPConnection(host, port, timeout=180), authorize))
        os.chmod(path, 0o666)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.path.unlink()


class LoopbackHTTPServer(BoundedThreads, http.server.HTTPServer):
    pass


def main(argv=None):
    parser = argparse.ArgumentParser(description="Agent namespace loopback-to-Unix fixed model bridge")
    parser.add_argument("--socket", required=True)
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args(argv)
    if not Path(args.socket).is_absolute() or not 1024 <= args.port <= 65535:
        parser.error("bounded absolute model socket and unprivileged port required")
    server = LoopbackHTTPServer(("127.0.0.1", args.port), handler_factory(
        lambda: UnixConnection(args.socket)))
    server.serve_forever()


if __name__ == "__main__":
    main()
