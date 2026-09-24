"""Disposable side-effect targets for installed-host evaluation.

This module supplies local targets and observations. It does not run a Guard
adapter or turn a synthetic action into installed-host enforcement evidence.
"""

from __future__ import annotations

import socket
import sys
from dataclasses import dataclass
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import BoundedSemaphore, Lock, Thread
from uuid import uuid4

from codex_plugin_scanner.guard.evaluation_preflight import EvaluationSetup

_MAX_ACTIVE_RECEIVER_CONNECTIONS = 8


@dataclass(frozen=True)
class FileWitnessPair:
    denied_target: Path
    allowed_target: Path
    denied_tool: tuple[str, str] | None = None
    allowed_tool: tuple[str, str] | None = None


@dataclass(frozen=True)
class NetworkWitnessPair:
    denied_url: str
    allowed_url: str


@dataclass(frozen=True)
class WitnessObservation:
    receiver_ready: bool
    denied_reached: bool
    allowed_reached: bool

    @property
    def receiver_conditions_met(self) -> bool:
        """Receiver conditions only; this says nothing about which process acted."""
        return self.receiver_ready and not self.denied_reached and self.allowed_reached


class LocalSideEffectWitness:
    """Own an isolated temporary directory and an ephemeral loopback receiver."""

    def __init__(self, *, setup: EvaluationSetup | None = None) -> None:
        self._setup = setup
        self._temporary: TemporaryDirectory[str] | None = None
        self._server: ThreadingHTTPServer | None = None
        self._thread: Thread | None = None
        self._lock = Lock()
        self._hits: dict[str, int] = {}
        self._file_pairs: set[tuple[Path, Path]] = set()
        self._network_pairs: set[tuple[str, str]] = set()
        self._file_ready = False
        self._network_ready = False
        self._overloaded = False

    def __enter__(self) -> LocalSideEffectWitness:
        if self._temporary is not None:
            raise RuntimeError("Witness is already active")
        parent_dir = None
        if self._setup is not None:
            root = self._setup.root_path
            workspace = self._setup.workspace
            token = self._setup.marker_token
            marker = root / ".hol-guard-evaluation-owned" if root is not None else None
            if (
                self._setup.report.status != "passed"
                or root is None
                or workspace is None
                or token is None
                or marker is None
                or not root.name.startswith("hol-guard-eval-")
                or not workspace.is_dir()
                or workspace.parent != root
                or not marker.is_file()
                or marker.read_text(encoding="utf-8") != token
            ):
                raise ValueError("Witness requires a live owned evaluation setup")
            parent_dir = workspace
        self._temporary = TemporaryDirectory(prefix="hol-guard-evaluation-witness-", dir=parent_dir)
        self._file_pairs.clear()
        self._network_pairs.clear()
        self._hits.clear()
        self._file_ready = False
        self._network_ready = False
        self._overloaded = False
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self) -> None:
                self.request.settimeout(2.0)
                super().setup()

            def do_GET(self) -> None:
                if self.path != "/health":
                    self.send_error(404)
                    return
                self.send_response(204)
                self.end_headers()

            def do_POST(self) -> None:
                token = self.path.removeprefix("/probe/")
                with owner._lock:
                    known = self.path.startswith("/probe/") and token in owner._hits
                if not known:
                    self.send_error(404)
                    return
                with owner._lock:
                    owner._hits[token] += 1
                if self.headers.get("Content-Length") != "0":
                    self.send_error(413)
                    return
                self.send_response(204)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib callback signature
                pass

        class BoundedReceiver(ThreadingHTTPServer):
            daemon_threads = True
            block_on_close = False
            request_queue_size = _MAX_ACTIVE_RECEIVER_CONNECTIONS

            def __init__(self) -> None:
                self._slots = BoundedSemaphore(_MAX_ACTIVE_RECEIVER_CONNECTIONS)
                super().__init__(("127.0.0.1", 0), Handler)

            def process_request(
                self, request: socket.socket | tuple[bytes, socket.socket], client_address: tuple[str, int]
            ) -> None:
                if not self._slots.acquire(blocking=False):
                    with owner._lock:
                        owner._overloaded = True
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, client_address)
                except BaseException:
                    self._slots.release()
                    raise

            def process_request_thread(
                self, request: socket.socket | tuple[bytes, socket.socket], client_address: tuple[str, int]
            ) -> None:
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    self._slots.release()

        try:
            self._server = BoundedReceiver()
            self._thread = Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None

    @property
    def root(self) -> Path:
        if self._temporary is None:
            raise RuntimeError("Witness is not active")
        return Path(self._temporary.name)

    def check_file_ready(self) -> bool:
        marker = self.root / "preflight"
        try:
            marker.write_bytes(b"ready")
            self._file_ready = marker.read_bytes() == b"ready"
        except OSError:
            self._file_ready = False
        finally:
            marker.unlink(missing_ok=True)
        return self._file_ready

    def check_network_ready(self) -> bool:
        if self._server is None:
            raise RuntimeError("Witness is not active")
        connection = HTTPConnection("127.0.0.1", self._server.server_port, timeout=2)
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            with self._lock:
                self._network_ready = response.status == 204 and not self._overloaded
        except OSError:
            self._network_ready = False
        finally:
            connection.close()
        return self._network_ready

    def new_file_pair(self) -> FileWitnessPair:
        case = uuid4().hex
        pair = FileWitnessPair(
            denied_target=self.root / f"{case}-denied.marker",
            allowed_target=self.root / f"{case}-allowed.marker",
        )
        self._file_pairs.add((pair.denied_target, pair.allowed_target))
        return pair

    def new_tool_pair(self) -> FileWitnessPair:
        pair = self.new_file_pair()
        denied_script = self.root / f"{uuid4().hex}-denied.py"
        allowed_script = self.root / f"{uuid4().hex}-allowed.py"
        for script, target in (
            (denied_script, pair.denied_target),
            (allowed_script, pair.allowed_target),
        ):
            script.write_text(
                "from pathlib import Path\n" + f"Path({str(target)!r}).write_bytes(b'hit')\n",
                encoding="utf-8",
            )
        return FileWitnessPair(
            denied_target=pair.denied_target,
            allowed_target=pair.allowed_target,
            denied_tool=(sys.executable, str(denied_script)),
            allowed_tool=(sys.executable, str(allowed_script)),
        )

    def new_network_pair(self) -> NetworkWitnessPair:
        if self._server is None:
            raise RuntimeError("Witness is not active")
        denied_token, allowed_token = uuid4().hex, uuid4().hex
        with self._lock:
            self._hits[denied_token] = 0
            self._hits[allowed_token] = 0
        base = f"http://127.0.0.1:{self._server.server_port}/probe/"
        pair = NetworkWitnessPair(base + denied_token, base + allowed_token)
        self._network_pairs.add((pair.denied_url, pair.allowed_url))
        return pair

    def observe_file_pair(self, pair: FileWitnessPair) -> WitnessObservation:
        if pair.denied_target.parent != self.root or pair.allowed_target.parent != self.root:
            raise ValueError("File witness targets must belong to this receiver")
        if (pair.denied_target, pair.allowed_target) not in self._file_pairs:
            raise ValueError("Unknown file witness pair")
        return WitnessObservation(
            receiver_ready=self._file_ready,
            denied_reached=pair.denied_target.exists(),
            allowed_reached=pair.allowed_target.exists(),
        )

    def observe_network_pair(self, pair: NetworkWitnessPair) -> WitnessObservation:
        if self._server is None:
            raise RuntimeError("Witness is not active")
        base = f"http://127.0.0.1:{self._server.server_port}/probe/"
        if not pair.denied_url.startswith(base) or not pair.allowed_url.startswith(base):
            raise ValueError("Network witness targets must belong to this receiver")
        if (pair.denied_url, pair.allowed_url) not in self._network_pairs:
            raise ValueError("Unknown network witness pair")
        denied_token = pair.denied_url.removeprefix(base)
        allowed_token = pair.allowed_url.removeprefix(base)
        with self._lock:
            if denied_token not in self._hits or allowed_token not in self._hits:
                raise ValueError("Unknown network witness token")
            denied_reached = self._hits[denied_token] > 0
            allowed_reached = self._hits[allowed_token] > 0
            receiver_ready = self._network_ready and not self._overloaded
        return WitnessObservation(receiver_ready, denied_reached, allowed_reached)
