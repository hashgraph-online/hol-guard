"""Bounded HTTP request admission and execution."""

from __future__ import annotations

from . import server as _server


def handle_error(self: _server._GuardDaemonHTTPServer, request: _server.Any, client_address: _server.Any) -> None:
    """Suppress expected peer disconnects without hiding server defects."""

    import sys

    error = sys.exc_info()[1]
    if isinstance(error, _server._PEER_DISCONNECT_ERRORS) or (
        isinstance(error, OSError)
        and error.errno
        in {_server.errno.EBADF, _server.errno.ECONNABORTED, _server.errno.ECONNRESET, _server.errno.EPIPE}
    ):
        return
    self.diagnostics.record_exception("http_request_failed")


def refresh_extension_control_runtime(self: _server._GuardDaemonHTTPServer) -> _server.ExtensionControlRuntimeSnapshot:
    from ..native_command_control_authority_io import NativeCommandControlMutationRequiredError

    try:
        view = self.store.read_extension_control_authority_for_registry(
            _server.BUILT_IN_COMMAND_EXTENSION_REGISTRY, read_only=True
        )
    except NativeCommandControlMutationRequiredError:
        # The shared lease has unwound. Reread under the mutation lease only
        # when migration or recovery requires a durable authority change.
        view = self.store.read_extension_control_authority_for_registry(_server.BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    return self.extension_control_runtime.refresh(view)


def process_request(self: _server._GuardDaemonHTTPServer, request: _server.Any, client_address: _server.Any) -> None:
    request_socket = _server.cast(_server.socket.socket, request)
    if not self._guard_admit_request(request_socket):
        return
    admitted = self.connection_capacity.acquire(blocking=False)
    if not admitted:
        self._evict_oldest_unclassified_connection()
        admitted = self.connection_capacity.acquire(
            blocking=True,
            timeout=_server._DAEMON_CONNECTION_ADMISSION_WAIT_SECONDS,
        )
    if not admitted:
        with self.request_capacity_lock:
            self.rejected_requests += 1
        self.shutdown_request(request_socket)
        self._guard_release_request()
        return
    with _server.suppress(OSError):
        request_socket.settimeout(_server._DAEMON_REQUEST_READ_TIMEOUT_SECONDS)
    self._register_unclassified_connection(request_socket)
    with self.request_capacity_lock:
        self.active_requests += 1
    executor = (
        self.control_request_executor
        if self._transport_request_is_control(request_socket)
        else self.general_request_executor
    )
    if not executor.submit(request_socket, client_address):
        with self.request_capacity_lock:
            self.rejected_requests += 1
        self._discard_request(request_socket)


def _process_request_worker(
    self: _server._GuardDaemonHTTPServer, request_socket: _server.socket.socket, client_address: tuple[str, int]
) -> None:
    try:
        self.finish_request(request_socket, client_address)
        self.shutdown_request(request_socket)
    except BaseException:
        self.handle_error(request_socket, client_address)
        self.shutdown_request(request_socket)
    finally:
        self._release_request_capacity(request_socket)


def _discard_request(self: _server._GuardDaemonHTTPServer, request_socket: _server.socket.socket) -> None:
    self.shutdown_request(request_socket)
    self._release_request_capacity(request_socket)


def _release_request_capacity(self: _server._GuardDaemonHTTPServer, request: _server.socket.socket) -> None:
    self.classify_connection(request)
    with self.request_capacity_lock:
        was_active = self.request_accepted_at.pop(id(request), None) is not None
        self.active_connections.pop(id(request), None)
        if was_active:
            self.active_requests -= 1
        capacity_kind = self.request_capacity_kinds.pop(id(request), None)
    if capacity_kind is not None:
        self._request_capacity_for_kind(capacity_kind).release()
    if was_active:
        self.connection_capacity.release()
        self._guard_release_request()


def _register_unclassified_connection(self: _server._GuardDaemonHTTPServer, request: _server.socket.socket) -> None:
    accepted_at = _server.time.monotonic()
    deadline = accepted_at + _server._DAEMON_REQUEST_READ_TIMEOUT_SECONDS
    with self.request_capacity_lock:
        self.request_accepted_at[id(request)] = accepted_at
        self.active_connections[id(request)] = request
    with self.unclassified_connections_lock:
        self.unclassified_connections[id(request)] = (request, deadline)


def request_deadline(
    self: _server._GuardDaemonHTTPServer, request: _server.socket.socket, timeout_seconds: float
) -> float:
    with self.request_capacity_lock:
        accepted_at = self.request_accepted_at.get(id(request), _server.time.monotonic())
    return accepted_at + timeout_seconds


def _transport_request_is_control(request: _server.socket.socket) -> bool:
    try:
        request.setblocking(False)
        buffered = request.recv(4_096, _server.socket.MSG_PEEK)
    except (BlockingIOError, InterruptedError, OSError):
        return False
    finally:
        with _server.suppress(OSError):
            request.settimeout(_server._DAEMON_REQUEST_READ_TIMEOUT_SECONDS)
    request_line = buffered.splitlines()[0] if buffered else b""
    parts = request_line.split()
    if len(parts) < 2:
        return False
    try:
        path = parts[1].decode("ascii").split("?", 1)[0]
    except UnicodeDecodeError:
        return False
    return path in _server._DAEMON_CONTROL_PATHS or path in _server._DAEMON_CRITICAL_PATHS


def _stop_request_executors(self: _server._GuardDaemonHTTPServer) -> bool:
    if self.request_executors_stopped:
        return True
    with self.request_capacity_lock:
        requests = list(self.active_connections.values())
    for request in requests:
        self._close_unclassified_socket(request)
    general_stopped = self.general_request_executor.shutdown(timeout_seconds=5.0)
    control_stopped = self.control_request_executor.shutdown(timeout_seconds=5.0)
    self.request_executors_stopped = general_stopped and control_stopped
    return self.request_executors_stopped


def classify_connection(self: _server._GuardDaemonHTTPServer, request: _server.socket.socket) -> None:
    with self.unclassified_connections_lock:
        self.unclassified_connections.pop(id(request), None)


def _evict_oldest_unclassified_connection(self: _server._GuardDaemonHTTPServer) -> None:
    with self.unclassified_connections_lock:
        oldest = next(iter(self.unclassified_connections.values()), None)
    if oldest is not None:
        self._discard_request(oldest[0])
        with self.request_capacity_lock:
            self.rejected_requests += 1


def _close_unclassified_socket(request: _server.socket.socket) -> None:
    with _server.suppress(OSError):
        request.shutdown(_server.socket.SHUT_RDWR)
    with _server.suppress(OSError):
        request.close()


def start_unclassified_watchdog(self: _server._GuardDaemonHTTPServer) -> None:
    if self.unclassified_watchdog_thread is not None and self.unclassified_watchdog_thread.is_alive():
        return
    self.unclassified_watchdog_stop.clear()
    self.unclassified_watchdog_thread = _server.threading.Thread(
        target=self._watch_unclassified_connections,
        daemon=True,
        name="guard-unclassified-connection-watchdog",
    )
    self.unclassified_watchdog_thread.start()


def stop_unclassified_watchdog(self: _server._GuardDaemonHTTPServer) -> bool:
    self.unclassified_watchdog_stop.set()
    thread = self.unclassified_watchdog_thread
    if thread is not None:
        thread.join(timeout=1.0)
    if thread is None or not thread.is_alive():
        self.unclassified_watchdog_thread = None
    return self.unclassified_watchdog_thread is None


def _watch_unclassified_connections(self: _server._GuardDaemonHTTPServer) -> None:
    while not self.unclassified_watchdog_stop.wait(_server._DAEMON_UNCLASSIFIED_WATCHDOG_POLL_SECONDS):
        now = _server.time.monotonic()
        with self.unclassified_connections_lock:
            expired = [request for request, deadline in self.unclassified_connections.values() if deadline <= now]
        for request in expired:
            if self._buffered_request_headers_complete(request):
                self.classify_connection(request)
            else:
                self._close_unclassified_socket(request)


def _buffered_request_headers_complete(request: _server.socket.socket) -> bool:
    nonblocking_flag = getattr(_server.socket, "MSG_DONTWAIT", None)
    if nonblocking_flag is None:
        return False
    try:
        buffered = request.recv(65_536, _server.socket.MSG_PEEK | nonblocking_flag)
    except (BlockingIOError, InterruptedError, OSError):
        return False
    return b"\r\n\r\n" in buffered or b"\n\n" in buffered


def claim_request_capacity(self: _server._GuardDaemonHTTPServer, request: _server.socket.socket, path: str) -> bool:
    capacity_kind = self._request_capacity_kind(path)
    capacity = self._request_capacity_for_kind(capacity_kind)
    with self.request_capacity_lock:
        previous_kind = self.request_capacity_kinds.pop(id(request), None)
    if previous_kind is not None:
        self._request_capacity_for_kind(previous_kind).release()
    admitted = (
        capacity.acquire(timeout=_server._DAEMON_CONTROL_ADMISSION_WAIT_SECONDS)
        if capacity_kind in {"critical", "control"}
        else capacity.acquire(blocking=False)
    )
    if not admitted:
        with self.request_capacity_lock:
            self.rejected_requests += 1
        return False
    with self.request_capacity_lock:
        self.request_capacity_kinds[id(request)] = capacity_kind
    return True


def _request_capacity_for_kind(
    self: _server._GuardDaemonHTTPServer, capacity_kind: str
) -> _server.threading.BoundedSemaphore:
    if capacity_kind == "critical":
        return self.critical_request_capacity
    if capacity_kind == "control":
        return self.control_request_capacity
    return self.request_capacity


def _request_capacity_kind(path: str) -> str:
    path = path.split("?", 1)[0]
    if path in _server._DAEMON_CRITICAL_PATHS:
        return "critical"
    if path in _server._DAEMON_CONTROL_PATHS:
        return "control"
    return "general"


def canonical_hook_capacity_harness(harness: str) -> str:
    try:
        return _server.get_adapter(harness).harness
    except ValueError:
        return "other"


def daemon_host(self: _server._GuardDaemonHTTPServer) -> str:
    return str(self.server_address[0])


def daemon_port(self: _server._GuardDaemonHTTPServer) -> int:
    return int(self.server_address[1])


def publish_trust_state(self: _server._GuardDaemonHTTPServer, trust_status: dict[str, object] | None = None) -> None:
    _server.write_guard_daemon_state(
        self.store.guard_home,
        self.daemon_port(),
        self.auth_token,
        host=self.daemon_host(),
        state_id=self.runtime_session_id,
        started_at=self.runtime_started_at,
        trust_status=trust_status or self.store.get_cached_policy_integrity_state(),
    )
