"""Disposable side-effect targets for installed-host evaluation.

This module supplies local targets and observations. It does not run a Guard
adapter or turn a synthetic action into installed-host enforcement evidence.
"""

from __future__ import annotations

import os
import shutil
import socket
import stat
import sys
import weakref
from dataclasses import dataclass
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import BoundedSemaphore, Lock, Thread
from uuid import uuid4

from codex_plugin_scanner.guard.evaluation_preflight import EvaluationSetup, _safe_temp_parent

_MAX_ACTIVE_RECEIVER_CONNECTIONS = 8


def _rmtree_at(directory_fd: int, entry: str) -> None:
    try:
        details = os.stat(entry, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(details.st_mode):
        os.unlink(entry, dir_fd=directory_fd)
        return

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    child_fd = os.open(entry, flags, dir_fd=directory_fd)
    try:
        with os.scandir(child_fd) as entries:
            for child in entries:
                _rmtree_at(child_fd, child.name)
    finally:
        os.close(child_fd)
    os.rmdir(entry, dir_fd=directory_fd)


class _PinnedWitnessDirectory:
    """Remove a witness through the workspace descriptor used to create it."""

    def __init__(self, *, workspace_fd: int, entry: str, name: str) -> None:
        self._finalizer = weakref.finalize(self, _cleanup_pinned_witness, workspace_fd, entry)
        self.name = name

    def cleanup(self) -> None:
        self._finalizer()


def _cleanup_pinned_witness(workspace_fd: int, entry: str) -> None:
    try:
        if sys.version_info >= (3, 11):
            shutil.rmtree(entry, dir_fd=workspace_fd)
        else:
            _rmtree_at(workspace_fd, entry)
    finally:
        os.close(workspace_fd)


def _owned_witness_directory(setup: EvaluationSetup) -> _PinnedWitnessDirectory:
    root = setup.root_path
    workspace = setup.workspace
    token = setup.marker_token
    if (
        setup.report.status != "passed"
        or root is None
        or workspace != root / "workspace"
        or token is None
        or setup.root_identity is None
        or setup.workspace_identity is None
        or not root.is_absolute()
        or not root.name.startswith("hol-guard-eval-")
        or not _safe_temp_parent(root.parent)
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise ValueError("Witness requires a live owned evaluation setup")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        parent_fd = os.open(root.parent, flags)
        try:
            root_fd = os.open(root.name, flags, dir_fd=parent_fd)
            try:
                workspace_fd = os.open("workspace", flags, dir_fd=root_fd)
                try:
                    marker_fd = os.open(".hol-guard-evaluation-owned", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
                    try:
                        marker_info = os.fstat(marker_fd)
                        marker_matches = stat.S_ISREG(marker_info.st_mode) and os.read(marker_fd, 33) == token.encode()
                    finally:
                        os.close(marker_fd)
                    for descriptor, expected_identity in (
                        (root_fd, setup.root_identity),
                        (workspace_fd, setup.workspace_identity),
                    ):
                        details = os.fstat(descriptor)
                        if (
                            not stat.S_ISDIR(details.st_mode)
                            or stat.S_IMODE(details.st_mode) & 0o077
                            or (details.st_dev, details.st_ino) != expected_identity
                        ):
                            raise ValueError("Witness requires a live owned evaluation setup")
                        if hasattr(os, "getuid") and details.st_uid != os.getuid():
                            raise ValueError("Witness requires a live owned evaluation setup")
                    if not marker_matches or stat.S_IMODE(marker_info.st_mode) & 0o077:
                        raise ValueError("Witness requires a live owned evaluation setup")
                    if hasattr(os, "getuid") and marker_info.st_uid != os.getuid():
                        raise ValueError("Witness requires a live owned evaluation setup")
                    entry = f"hol-guard-evaluation-witness-{uuid4().hex}"
                    os.mkdir(entry, mode=0o700, dir_fd=workspace_fd)
                    return _PinnedWitnessDirectory(
                        workspace_fd=workspace_fd,
                        entry=entry,
                        name=str(workspace / entry),
                    )
                except BaseException:
                    os.close(workspace_fd)
                    raise
            finally:
                os.close(root_fd)
        finally:
            os.close(parent_fd)
    except (OSError, UnicodeError) as exc:
        raise ValueError("Witness requires a live owned evaluation setup") from exc


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
        self._temporary: TemporaryDirectory[str] | _PinnedWitnessDirectory | None = None
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
        if self._setup is not None and os.name != "nt":
            self._temporary = _owned_witness_directory(self._setup)
        elif self._setup is not None:
            try:
                root = self._setup.root_path
                workspace = self._setup.workspace
                token = self._setup.marker_token
                marker = root / ".hol-guard-evaluation-owned" if root is not None else None
                owned = not (
                    self._setup.report.status != "passed"
                    or root is None
                    or workspace is None
                    or token is None
                    or marker is None
                    or self._setup.root_identity is None
                    or self._setup.workspace_identity is None
                    or not root.name.startswith("hol-guard-eval-")
                    or root.is_symlink()
                    or (root.stat().st_dev, root.stat().st_ino) != self._setup.root_identity
                    or not workspace.is_dir()
                    or workspace.is_symlink()
                    or (workspace.stat().st_dev, workspace.stat().st_ino) != self._setup.workspace_identity
                    or workspace.parent != root
                    or not marker.is_file()
                    or marker.is_symlink()
                    or marker.read_text(encoding="utf-8") != token
                )
            except (OSError, UnicodeError) as exc:
                raise ValueError("Witness requires a live owned evaluation setup") from exc
            if not owned:
                raise ValueError("Witness requires a live owned evaluation setup")
            self._temporary = TemporaryDirectory(prefix="hol-guard-evaluation-witness-", dir=workspace)
        else:
            self._temporary = TemporaryDirectory(prefix="hol-guard-evaluation-witness-")
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
