"""Native runtime edge for the daemon's public port.

The daemon binds its public loopback port as before. When the native runtime
offers ``daemon-edge-v1``, the daemon serves its own routes on a private
loopback port and starts ``guard-runtime daemon-edge`` with the public
listening socket as its standard input. The edge accepts every connection on
the public port and relays it to the private one, so routes can move into the
runtime without changing the address any client, hook or state file names.

The edge's standard output is one end of a socket pair that only the daemon
otherwise holds, so the edge stops accepting the moment the daemon exits,
however it exits. The daemon keeps its own copy of the public socket. Connections queue in its
backlog while an edge restarts, and when no edge can run the daemon accepts on
the public socket itself, exactly as it did before the edge existed.

The daemon also writes one handshake line on that socket pair naming its auth
token and store. With it the edge answers a few token-authenticated reads from
the store itself and writes one byte back for each burst of them, so the daemon
still counts that traffic as activity. An edge without the handshake relays
everything, as before.
"""

from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol

EDGE_FEATURE = "daemon-edge-v1"
EDGE_COMMAND = "daemon-edge"
# Set to ``0`` to keep the daemon accepting on its public port itself.
EDGE_ENV = "HOL_GUARD_DAEMON_NATIVE_EDGE"

_RESTART_DELAYS_SECONDS = (0.05, 0.25, 1.0, 5.0)
# An edge that exits this soon after it started counts as failing to start.
_QUICK_EXIT_SECONDS = 5.0
_QUICK_EXITS_BEFORE_FALLBACK = 3
_STOP_TIMEOUT_SECONDS = 2.0
_FALLBACK_ACCEPT_POLL_SECONDS = 0.5


class _EdgeServer(Protocol):
    socket: socket.socket
    address_family: int
    request_queue_size: int

    def verify_request(self, request: Any, client_address: Any) -> bool: ...

    def process_request(self, request: Any, client_address: Any) -> None: ...

    def shutdown_request(self, request: Any) -> None: ...

    def handle_error(self, request: Any, client_address: Any) -> None: ...


def _edge_enabled() -> bool:
    return os.name == "posix" and os.environ.get(EDGE_ENV, "").strip() != "0"


def _resolve_executable(guard_home: Path) -> Path | None:
    from ..adapters.native_hook_bridge import native_hook_bridge_executable

    try:
        return native_hook_bridge_executable(EDGE_FEATURE, guard_home=guard_home)
    except Exception:
        return None


class _EdgeProcess:
    """An edge child and the daemon's end of its liveness socket.

    The edge exits as soon as this end closes, which the kernel does when the
    daemon exits for any reason.
    """

    def __init__(self, process: subprocess.Popen[bytes], liveness: socket.socket) -> None:
        self.process = process
        self.liveness = liveness

    @property
    def pid(self) -> int:
        return self.process.pid

    def wait(self) -> None:
        self.process.wait()

    def stop(self) -> None:
        _close_liveness(self.liveness)
        _stop_process(self.process)


def _close_liveness(liveness: socket.socket) -> None:
    # Shutting down first wakes the activity reader blocked on this socket.
    with suppress(OSError):
        liveness.shutdown(socket.SHUT_RDWR)
    with suppress(OSError):
        liveness.close()


def _read_activity(liveness: socket.socket, on_activity: Callable[[], None]) -> None:
    while True:
        try:
            chunk = liveness.recv(64)
        except OSError:
            return
        if not chunk:
            return
        with suppress(Exception):
            on_activity()


def _offer_handshake(
    liveness: socket.socket,
    handshake: Callable[[], bytes | None] | None,
    on_activity: Callable[[], None] | None,
) -> None:
    """Start the activity reader, then send the handshake.

    Without a running reader the edge's own answers would never reach the
    daemon's idle timer, so the edge then gets no handshake and relays.
    """

    if handshake is None or on_activity is None:
        return
    try:
        line = handshake()
    except Exception:
        return
    if line is None:
        return
    reader = threading.Thread(
        target=_read_activity, args=(liveness, on_activity), name="guard-daemon-native-edge-activity", daemon=True
    )
    try:
        reader.start()
    except RuntimeError:
        return
    with suppress(OSError):
        liveness.sendall(line)


def _spawn(
    executable: Path,
    public: socket.socket,
    upstream_port: int,
    handshake: Callable[[], bytes | None] | None = None,
    on_activity: Callable[[], None] | None = None,
) -> _EdgeProcess | None:
    try:
        liveness, child_end = socket.socketpair()
    except OSError:
        return None
    try:
        process = subprocess.Popen(
            (
                str(executable),
                EDGE_COMMAND,
                "--upstream-port",
                str(upstream_port),
                "--parent-pid",
                str(os.getpid()),
            ),
            cwd=executable.parent,
            env={},
            stdin=public.fileno(),
            stdout=child_end.fileno(),
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        liveness.close()
        return None
    finally:
        child_end.close()
    _offer_handshake(liveness, handshake, on_activity)
    return _EdgeProcess(process, liveness)


class NativeDaemonEdge:
    """Supervises the runtime edge that accepts on the daemon's public port."""

    def __init__(
        self,
        *,
        server: _EdgeServer,
        public: socket.socket,
        upstream_port: int,
        process: _EdgeProcess,
        resolve_executable: Callable[[], Path | None],
        handshake: Callable[[], bytes | None] | None = None,
        on_activity: Callable[[], None] | None = None,
    ) -> None:
        self._server = server
        self._handshake = handshake
        self._on_activity = on_activity
        self._public = public
        self._upstream_port = upstream_port
        self._process: _EdgeProcess | None = process
        self._started_at = time.monotonic()
        self._resolve_executable = resolve_executable
        self._lock = threading.Lock()
        self._closing = threading.Event()
        self.serving_in_process = False
        self._thread = threading.Thread(target=self._supervise, name="guard-daemon-native-edge", daemon=True)
        self._thread.start()

    @property
    def process_id(self) -> int | None:
        process = self._process
        return None if process is None else process.pid

    def _supervise(self) -> None:
        quick_exits = 0
        restarts = 0
        while not self._closing.is_set():
            process = self._process
            if process is None:
                break
            with suppress(Exception):
                process.wait()
            _close_liveness(process.liveness)
            if self._closing.is_set():
                return
            if time.monotonic() - self._started_at < _QUICK_EXIT_SECONDS:
                quick_exits += 1
            else:
                quick_exits = 0
                restarts = 0
            if quick_exits >= _QUICK_EXITS_BEFORE_FALLBACK:
                break
            delay = _RESTART_DELAYS_SECONDS[min(restarts, len(_RESTART_DELAYS_SECONDS) - 1)]
            restarts += 1
            if self._closing.wait(delay):
                return
            # Resolve again: an upgrade can replace the runtime while the
            # daemon runs.
            executable = self._resolve_executable()
            replacement = (
                None
                if executable is None
                else _spawn(executable, self._public, self._upstream_port, self._handshake, self._on_activity)
            )
            with self._lock:
                if self._closing.is_set():
                    if replacement is not None:
                        replacement.stop()
                    return
                self._process = replacement
                self._started_at = time.monotonic()
        with self._lock:
            self._process = None
            if self._closing.is_set():
                return
            self.serving_in_process = True
        self._serve_public_in_process()

    def _serve_public_in_process(self) -> None:
        public = self._public
        server = self._server
        with suppress(OSError):
            public.settimeout(_FALLBACK_ACCEPT_POLL_SECONDS)
        while not self._closing.is_set():
            try:
                request, client_address = public.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._closing.is_set():
                    return
                time.sleep(_FALLBACK_ACCEPT_POLL_SECONDS)
                continue
            # The same steps the server's own loop takes for an accepted request.
            try:
                if server.verify_request(request, client_address):
                    server.process_request(request, client_address)
                else:
                    server.shutdown_request(request)
            except Exception:
                server.handle_error(request, client_address)
                server.shutdown_request(request)

    def close(self) -> None:
        with self._lock:
            self._closing.set()
            process = self._process
            self._process = None
        if process is not None:
            process.stop()
        with suppress(OSError):
            self._public.close()
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=_STOP_TIMEOUT_SECONDS)


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    with suppress(OSError):
        process.terminate()
    try:
        process.wait(timeout=_STOP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        with suppress(OSError):
            process.kill()
        with suppress(Exception):
            process.wait(timeout=_STOP_TIMEOUT_SECONDS)


def start_native_daemon_edge(
    server: _EdgeServer,
    *,
    guard_home: Path,
    host: str,
    handshake: Callable[[], bytes | None] | None = None,
    on_activity: Callable[[], None] | None = None,
) -> NativeDaemonEdge | None:
    """Move the server onto a private port behind a native edge.

    Must run before the server starts serving. Returns ``None`` and leaves the
    server on its public socket when no edge can start.
    """

    if not _edge_enabled():
        return None
    executable = _resolve_executable(guard_home)
    if executable is None:
        return None
    public = server.socket
    private = socket.socket(server.address_family, socket.SOCK_STREAM)
    try:
        private.bind((host, 0))
        private.listen(server.request_queue_size)
        upstream_port = int(private.getsockname()[1])
    except OSError:
        private.close()
        return None
    process = _spawn(executable, public, upstream_port, handshake, on_activity)
    if process is None:
        private.close()
        return None
    server.socket = private
    try:
        return NativeDaemonEdge(
            server=server,
            public=public,
            upstream_port=upstream_port,
            process=process,
            resolve_executable=lambda: _resolve_executable(guard_home),
            handshake=handshake,
            on_activity=on_activity,
        )
    except BaseException as error:
        # Without a supervisor nothing would own the child or the public
        # socket, so stop the child and keep serving the public port.
        server.socket = public
        process.stop()
        private.close()
        if isinstance(error, Exception):
            return None
        raise


__all__ = [
    "EDGE_ENV",
    "EDGE_FEATURE",
    "NativeDaemonEdge",
    "start_native_daemon_edge",
]
