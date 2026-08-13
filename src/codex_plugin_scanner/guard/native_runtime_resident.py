"""Authenticated, bounded resident transport for the Rust Guard runtime.

Linux and macOS use owner-private Unix sockets. Windows uses IPv4 loopback
because default named-pipe ACLs are not strong enough for hook material. Every
platform performs mutual HMAC authentication with a fresh per-generation
256-bit secret delivered only through inherited stdin.

Protocol v2 binds responses to the random request identifier, exact request
bytes, and the active process generation. Client admission and process starts
are non-blocking and bounded so overload or crash loops cannot amplify into
unbounded Python threads or child processes.
"""

from __future__ import annotations

import atexit
import hashlib
import hmac
import json
import os
import secrets
import socket
import stat
import threading
import time
from collections.abc import Mapping
from pathlib import Path

from .codex_hook_launch_runtime import run_isolated_hook_process
from .native_runtime_resilience import (
    native_record_resident_failure,
    native_record_restart,
    native_record_starting,
    native_runtime_health_snapshot,
)
from .native_runtime_supervisor import (
    NativeSupervisorSnapshot,
    native_supervisor_record_child_exit,
    native_supervisor_record_ready,
    native_supervisor_record_rotation,
    native_supervisor_record_start_failed,
    native_supervisor_record_stopped,
    native_supervisor_request_start,
    native_supervisor_snapshot,
)

_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_HEALTH_REQUEST_BYTES = 1024
_MAX_SOCKET_PATH_BYTES = 100
_START_TIMEOUT_SECONDS = 0.6
_SERVICE_LIFETIME_SECONDS = 7 * 24 * 60 * 60
_SERVICE_OUTPUT_LIMIT = 64 * 1024
_AUTH_TOKEN_BYTES = 32
_AUTH_NONCE_BYTES = 32
_AUTH_PROOF_BYTES = 32
_AUTH_TIMEOUT_SECONDS = 0.25
_FRAME_REQUEST_ID_BYTES = 32
_FRAME_DIGEST_BYTES = 32
_GENERATION_ID_BYTES = 16
_FRAME_OPERATION_BYTES = 1
_FRAME_RESERVED_BYTES = 3
_FRAME_DEADLINE_BYTES = 4
_REQUEST_HEADER_BYTES = (
    4
    + _FRAME_OPERATION_BYTES
    + _FRAME_RESERVED_BYTES
    + _FRAME_REQUEST_ID_BYTES
    + _FRAME_DIGEST_BYTES
    + 4
    + _FRAME_DEADLINE_BYTES
)
_RESPONSE_HEADER_BYTES = (
    4 + _FRAME_REQUEST_ID_BYTES + _FRAME_DIGEST_BYTES + _GENERATION_ID_BYTES + _FRAME_DIGEST_BYTES + 4
)
_REQUEST_MAGIC = b"HGR2"
_RESPONSE_MAGIC = b"HGS2"
_SERVER_PROOF_LABEL = b"hol-guard-resident-server-v1\x00"
_CLIENT_PROOF_LABEL = b"hol-guard-resident-client-v1\x00"
_OPERATION_HEALTH = 1
_OPERATION_EVALUATE = 2
_MAX_CLIENT_IN_FLIGHT = 16
_OVERLOAD_RESPONSE = b'{"error":"native_overloaded","retryable":true}'
_HEALTH_REQUEST = b'{"operation":"health","request":{}}'


class _ResidentService:
    def __init__(
        self,
        *,
        executable: Path,
        identity_sha256: str,
        guard_home: Path,
        environment: Mapping[str, str],
    ) -> None:
        self.executable = executable
        self.identity_sha256 = identity_sha256
        self.guard_home = guard_home
        self.environment = dict(environment)
        self.socket_path = _resident_socket_path(guard_home, identity_sha256)
        self.loopback_address = _select_loopback_address() if os.name == "nt" else None
        self._auth_token: bytes | None = None
        self._generation_id: bytes | None = None
        self._lock = threading.Lock()
        self._start_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._starts = 0
        self._generation = 0
        self._ready_generation = 0
        self._closed = False

    @property
    def starts(self) -> int:
        with self._lock:
            return self._starts

    @property
    def generation_id(self) -> bytes | None:
        with self._lock:
            return self._generation_id

    def request(self, payload: bytes, *, timeout_seconds: float) -> bytes | None:
        operation = _operation_for_payload(payload)
        max_bytes = _MAX_HEALTH_REQUEST_BYTES if operation == _OPERATION_HEALTH else _MAX_REQUEST_BYTES
        if len(payload) > max_bytes or timeout_seconds <= 0 or not self._transport_configured():
            return None
        if not _CLIENT_IN_FLIGHT.acquire(blocking=False):
            return _OVERLOAD_RESPONSE
        try:
            response = self._send(
                payload,
                operation=operation,
                timeout_seconds=min(timeout_seconds, 0.05),
            )
            if response is not None:
                return response
            if not self._ensure_started(timeout_seconds=min(timeout_seconds, _START_TIMEOUT_SECONDS)):
                return None
            return self._send(
                payload,
                operation=operation,
                timeout_seconds=timeout_seconds,
            )
        finally:
            _CLIENT_IN_FLIGHT.release()

    def prewarm(self, *, timeout_seconds: float) -> bool:
        return self._ensure_started(timeout_seconds=timeout_seconds)

    def _transport_configured(self) -> bool:
        with self._lock:
            if self._closed:
                return False
            if os.name == "nt":
                return self.loopback_address is not None
            return self.socket_path is not None

    def _send(
        self,
        payload: bytes,
        *,
        operation: int,
        timeout_seconds: float,
    ) -> bytes | None:
        with self._lock:
            if self._closed:
                return None
            loopback_address = self.loopback_address
            auth_token = self._auth_token
            generation_id = self._generation_id
            socket_path = self.socket_path
        if auth_token is None or generation_id is None:
            return None
        if os.name == "nt":
            if loopback_address is None:
                return None
            return _send_authenticated_loopback_request(
                loopback_address,
                auth_token,
                generation_id,
                payload,
                operation=operation,
                timeout_seconds=timeout_seconds,
            )
        if socket_path is None:
            return None
        return _send_authenticated_unix_request(
            socket_path,
            auth_token,
            generation_id,
            payload,
            operation=operation,
            timeout_seconds=timeout_seconds,
        )

    def _active_generation_is_alive(self) -> bool:
        with self._lock:
            thread = self._thread
            return (
                not self._closed
                and thread is not None
                and thread.is_alive()
                and self._auth_token is not None
                and self._generation_id is not None
            )

    def _wait_for_ready(self, *, deadline: float) -> bool:
        while time.monotonic() < deadline:
            if self._transport_accepts_authenticated_connections():
                return True
            if not self._active_generation_is_alive():
                return False
            time.sleep(0.01)
        return self._transport_accepts_authenticated_connections()

    def _ensure_started(self, *, timeout_seconds: float) -> bool:
        if timeout_seconds <= 0:
            return False
        health = native_runtime_health_snapshot(self.identity_sha256, self.guard_home)
        if health.circuit_open or health.state in {"integrity_failed", "quarantined"}:
            return False
        deadline = time.monotonic() + timeout_seconds
        if self._active_generation_is_alive() and self._wait_for_ready(deadline=deadline):
            return True
        acquired = self._start_lock.acquire(blocking=False)
        if not acquired:
            return self._wait_for_ready(deadline=deadline)
        try:
            if self._active_generation_is_alive() and self._wait_for_ready(deadline=deadline):
                return True
            with self._lock:
                if self._closed:
                    return False
                if os.name == "nt" and self.loopback_address is None:
                    return False
                if os.name != "nt" and self.socket_path is None:
                    return False
            permit = native_supervisor_request_start(self.identity_sha256, self.guard_home)
            if not permit.allowed:
                return self._wait_for_ready(deadline=deadline) if permit.reason == "native_start_in_flight" else False
            stop_event = threading.Event()
            auth_token = secrets.token_bytes(_AUTH_TOKEN_BYTES)
            generation_id = secrets.token_bytes(_GENERATION_ID_BYTES)
            with self._lock:
                if self._closed:
                    native_supervisor_record_start_failed(
                        self.identity_sha256,
                        self.guard_home,
                        generation=permit.generation,
                        reason="native_start_cancelled",
                    )
                    return False
                previous_stop = self._stop_event
                self._stop_event = stop_event
                self._auth_token = auth_token
                self._generation_id = generation_id
                self._generation = permit.generation
                if self._starts == 0:
                    native_record_starting(self.identity_sha256, self.guard_home)
                else:
                    native_record_restart(self.identity_sha256, self.guard_home)
                thread = threading.Thread(
                    target=self._run,
                    args=(stop_event, auth_token, generation_id, permit.generation),
                    name="hol-guard-native-runtime",
                    daemon=True,
                )
                self._thread = thread
                self._starts += 1
                thread.start()
            previous_stop.set()
            ready = self._wait_for_ready(deadline=deadline)
            if ready:
                with self._lock:
                    if self._generation == permit.generation:
                        self._ready_generation = permit.generation
                native_supervisor_record_ready(
                    self.identity_sha256,
                    self.guard_home,
                    generation=permit.generation,
                )
                return True
            stop_event.set()
            with self._lock:
                if self._generation == permit.generation:
                    self._auth_token = None
                    self._generation_id = None
            native_supervisor_record_start_failed(
                self.identity_sha256,
                self.guard_home,
                generation=permit.generation,
                reason="native_start_timeout",
            )
            return False
        finally:
            self._start_lock.release()

    def _transport_accepts_authenticated_connections(self) -> bool:
        response = self._send(
            _HEALTH_REQUEST,
            operation=_OPERATION_HEALTH,
            timeout_seconds=0.1,
        )
        if response is None:
            return False
        try:
            payload = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        return payload == {"status": "ready", "protocol_version": 2}

    def _run(
        self,
        stop_event: threading.Event,
        auth_token: bytes,
        generation_id: bytes,
        generation: int,
    ) -> None:
        if os.name == "nt":
            if self.loopback_address is None:
                return
            host, port = self.loopback_address
            command = (
                str(self.executable),
                "serve",
                "--tcp-loopback",
                f"{host}:{port}",
            )
        else:
            if self.socket_path is None:
                return
            command = (str(self.executable), "serve", "--socket", str(self.socket_path))
        result = run_isolated_hook_process(
            command,
            input_text=f"{auth_token.hex()}\n{generation_id.hex()}\n",
            cwd=self.executable.parent,
            environment=self.environment,
            timeout_seconds=_SERVICE_LIFETIME_SECONDS,
            output_limit=_SERVICE_OUTPUT_LIMIT,
            stop_event=stop_event,
        )
        with self._lock:
            current_generation = generation == self._generation
            was_ready = generation == self._ready_generation
            intentional_stop = self._closed or stop_event.is_set()
            if current_generation:
                self._auth_token = None
                self._generation_id = None
        if current_generation and not intentional_stop:
            if result.containment_failed:
                reason = "native_resident_containment_failed"
            elif result.output_limit_exceeded:
                reason = "native_resident_output_limit"
            elif result.timed_out:
                reason = "native_resident_lifetime_expired"
            elif result.returncode != 0:
                reason = "native_resident_exited"
            else:
                reason = "native_resident_stopped"
            native_record_resident_failure(
                self.identity_sha256,
                self.guard_home,
                reason=reason,
            )
            if was_ready:
                native_supervisor_record_child_exit(
                    self.identity_sha256,
                    self.guard_home,
                    generation=generation,
                    reason=reason,
                )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._stop_event.set()
            thread = self._thread
            generation = self._generation
            self._auth_token = None
            self._generation_id = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=1.5)
        _unlink_owned_socket(self.socket_path)
        with self._lock:
            if self._thread is thread:
                self._thread = None
        if generation:
            native_supervisor_record_stopped(
                self.identity_sha256,
                self.guard_home,
                generation=generation,
            )


_SERVICES_LOCK = threading.Lock()
_SERVICES: dict[tuple[str, str, str], _ResidentService] = {}
_CLIENT_IN_FLIGHT = threading.BoundedSemaphore(_MAX_CLIENT_IN_FLIGHT)


def _private_runtime_dir(guard_home: Path) -> Path | None:
    if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
        return None
    try:
        resolved_guard_home = guard_home.expanduser().resolve(strict=True)
        guard_metadata = resolved_guard_home.lstat()
        if stat.S_ISLNK(guard_metadata.st_mode) or not stat.S_ISDIR(guard_metadata.st_mode):
            return None
        runtime_dir = resolved_guard_home / "native-runtime"
        runtime_dir.mkdir(mode=0o700, exist_ok=True)
        metadata = runtime_dir.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            return None
        current_uid = os.getuid() if hasattr(os, "getuid") else None
        if current_uid is not None and getattr(metadata, "st_uid", current_uid) != current_uid:
            return None
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            runtime_dir.chmod(0o700)
            metadata = runtime_dir.lstat()
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                return None
        return runtime_dir.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None


def _resident_socket_path(guard_home: Path, identity_sha256: str) -> Path | None:
    runtime_dir = _private_runtime_dir(guard_home)
    if runtime_dir is None:
        return None
    suffix = identity_sha256[:16] if identity_sha256 else "unknown"
    socket_path = runtime_dir / f"hook-v2-{suffix}.sock"
    if len(os.fsencode(socket_path)) > _MAX_SOCKET_PATH_BYTES:
        return None
    return socket_path


def _select_loopback_address() -> tuple[str, int] | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            host, port = probe.getsockname()[:2]
            if host != "127.0.0.1" or not isinstance(port, int) or port <= 0:
                return None
            return host, port
    except OSError:
        return None


def _proof(token: bytes, label: bytes, nonce: bytes) -> bytes:
    return hmac.new(token, label + nonce, hashlib.sha256).digest()


def _read_exact(client: socket.socket, length: int) -> bytes | None:
    if length < 0:
        return None
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = client.recv(min(remaining, 64 * 1024))
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _authenticate_client(
    client: socket.socket,
    token: bytes,
    *,
    timeout_seconds: float,
) -> bool:
    if len(token) != _AUTH_TOKEN_BYTES or timeout_seconds <= 0:
        return False
    try:
        client.settimeout(min(timeout_seconds, _AUTH_TIMEOUT_SECONDS))
        nonce = secrets.token_bytes(_AUTH_NONCE_BYTES)
        client.sendall(nonce)
        server_proof = _read_exact(client, _AUTH_PROOF_BYTES)
        expected_server = _proof(token, _SERVER_PROOF_LABEL, nonce)
        if server_proof is None or not hmac.compare_digest(server_proof, expected_server):
            return False
        client.sendall(_proof(token, _CLIENT_PROOF_LABEL, nonce))
        client.settimeout(timeout_seconds)
        return True
    except (OSError, OverflowError):
        return False


def _operation_for_payload(payload: bytes) -> int:
    return _OPERATION_HEALTH if payload == _HEALTH_REQUEST else _OPERATION_EVALUATE


def _frame_request(
    payload: bytes,
    *,
    operation: int,
    timeout_seconds: float,
) -> tuple[bytes, bytes, bytes]:
    max_bytes = _MAX_HEALTH_REQUEST_BYTES if operation == _OPERATION_HEALTH else _MAX_REQUEST_BYTES
    if not payload or len(payload) > max_bytes or operation not in {_OPERATION_HEALTH, _OPERATION_EVALUATE}:
        raise ValueError("native resident payload is outside the accepted bound")
    request_id = secrets.token_bytes(_FRAME_REQUEST_ID_BYTES)
    digest = hashlib.sha256(payload).digest()
    deadline_ms = max(1, min(10_000, int(timeout_seconds * 1_000)))
    header = (
        _REQUEST_MAGIC
        + bytes((operation,))
        + b"\x00" * _FRAME_RESERVED_BYTES
        + request_id
        + digest
        + len(payload).to_bytes(4, "big")
        + deadline_ms.to_bytes(_FRAME_DEADLINE_BYTES, "big")
    )
    assert len(header) == _REQUEST_HEADER_BYTES
    return request_id, digest, header + payload


def _read_bound_response(
    client: socket.socket,
    *,
    request_id: bytes,
    request_digest: bytes,
    generation_id: bytes,
) -> bytes | None:
    header = _read_exact(client, _RESPONSE_HEADER_BYTES)
    if header is None or header[:4] != _RESPONSE_MAGIC:
        return None
    offset = 4
    response_request_id = header[offset : offset + _FRAME_REQUEST_ID_BYTES]
    offset += _FRAME_REQUEST_ID_BYTES
    response_request_digest = header[offset : offset + _FRAME_DIGEST_BYTES]
    offset += _FRAME_DIGEST_BYTES
    response_generation = header[offset : offset + _GENERATION_ID_BYTES]
    offset += _GENERATION_ID_BYTES
    response_digest = header[offset : offset + _FRAME_DIGEST_BYTES]
    length = int.from_bytes(header[-4:], "big")
    if not hmac.compare_digest(response_request_id, request_id):
        return None
    if not hmac.compare_digest(response_request_digest, request_digest):
        return None
    if not hmac.compare_digest(response_generation, generation_id):
        return None
    if length <= 0 or length > _MAX_RESPONSE_BYTES:
        return None
    response = _read_exact(client, length)
    if response is None:
        return None
    if not hmac.compare_digest(hashlib.sha256(response).digest(), response_digest):
        return None
    return response


def _send_authenticated_request(
    client: socket.socket,
    token: bytes,
    generation_id: bytes,
    payload: bytes,
    *,
    operation: int,
    timeout_seconds: float,
) -> bytes | None:
    if timeout_seconds <= 0 or len(generation_id) != _GENERATION_ID_BYTES:
        return None
    try:
        with client:
            if not _authenticate_client(client, token, timeout_seconds=timeout_seconds):
                return None
            request_id, request_digest, frame = _frame_request(
                payload,
                operation=operation,
                timeout_seconds=timeout_seconds,
            )
            client.sendall(frame)
            return _read_bound_response(
                client,
                request_id=request_id,
                request_digest=request_digest,
                generation_id=generation_id,
            )
    except (OSError, OverflowError, ValueError):
        return None


def _send_authenticated_loopback_request(
    address: tuple[str, int],
    token: bytes,
    generation_id: bytes,
    payload: bytes,
    *,
    operation: int,
    timeout_seconds: float,
) -> bytes | None:
    try:
        client = socket.create_connection(address, timeout=timeout_seconds)
    except (OSError, OverflowError):
        return None
    return _send_authenticated_request(
        client,
        token,
        generation_id,
        payload,
        operation=operation,
        timeout_seconds=timeout_seconds,
    )


def _send_authenticated_unix_request(
    socket_path: Path,
    token: bytes,
    generation_id: bytes,
    payload: bytes,
    *,
    operation: int,
    timeout_seconds: float,
) -> bytes | None:
    if not hasattr(socket, "AF_UNIX"):
        return None
    client: socket.socket | None = None
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(timeout_seconds)
        client.connect(str(socket_path))
    except (OSError, OverflowError):
        if client is not None:
            client.close()
        return None
    return _send_authenticated_request(
        client,
        token,
        generation_id,
        payload,
        operation=operation,
        timeout_seconds=timeout_seconds,
    )


def _service_for(
    *,
    executable: Path,
    identity_sha256: str,
    guard_home: Path,
    environment: Mapping[str, str],
) -> tuple[tuple[str, str, str], _ResidentService] | None:
    if os.name != "nt" and not hasattr(socket, "AF_UNIX"):
        return None
    try:
        resolved_executable = executable.resolve(strict=True)
        resolved_guard_home = guard_home.expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    key = (str(resolved_executable), identity_sha256, str(resolved_guard_home))
    with _SERVICES_LOCK:
        service = _SERVICES.get(key)
        if service is None:
            service = _ResidentService(
                executable=resolved_executable,
                identity_sha256=identity_sha256,
                guard_home=resolved_guard_home,
                environment=environment,
            )
            _SERVICES[key] = service
    return key, service


def _retire_stale_services(active_key: tuple[str, str, str]) -> None:
    executable, identity_sha256, guard_home = active_key
    stale: list[_ResidentService] = []
    with _SERVICES_LOCK:
        for key in tuple(_SERVICES):
            if key == active_key:
                continue
            if key[0] == executable and key[2] == guard_home and key[1] != identity_sha256:
                stale.append(_SERVICES.pop(key))
    for candidate in stale:
        candidate.close()
    if stale:
        active = _SERVICES.get(active_key)
        if active is not None:
            snapshot = native_supervisor_snapshot(active.identity_sha256, active.guard_home)
            native_supervisor_record_rotation(
                active.identity_sha256,
                active.guard_home,
                generation=snapshot.generation,
            )


def resident_native_request(
    *,
    executable: Path,
    identity_sha256: str,
    guard_home: Path,
    environment: Mapping[str, str],
    payload: bytes,
    timeout_seconds: float,
) -> bytes | None:
    """Send one bounded request to a lazily supervised native runtime."""

    resolved = _service_for(
        executable=executable,
        identity_sha256=identity_sha256,
        guard_home=guard_home,
        environment=environment,
    )
    if resolved is None:
        return None
    key, service = resolved
    response = service.request(payload, timeout_seconds=timeout_seconds)
    if response is not None and response != _OVERLOAD_RESPONSE:
        _retire_stale_services(key)
    return response


def prewarm_resident_native_runtime(
    *,
    executable: Path,
    identity_sha256: str,
    guard_home: Path,
    environment: Mapping[str, str],
    timeout_seconds: float = _START_TIMEOUT_SECONDS,
) -> bool:
    """Prewarm a compatible generation before retiring an older identity."""

    resolved = _service_for(
        executable=executable,
        identity_sha256=identity_sha256,
        guard_home=guard_home,
        environment=environment,
    )
    if resolved is None:
        return False
    key, service = resolved
    ready = service.prewarm(timeout_seconds=timeout_seconds)
    if ready:
        _retire_stale_services(key)
    return ready


def resident_service_starts(*, executable: Path, identity_sha256: str, guard_home: Path) -> int:
    """Return an aggregate-only lifecycle counter for tests and diagnostics."""

    try:
        key = (
            str(executable.resolve(strict=True)),
            identity_sha256,
            str(guard_home.expanduser().resolve(strict=True)),
        )
    except (OSError, RuntimeError, ValueError):
        return 0
    with _SERVICES_LOCK:
        service = _SERVICES.get(key)
    return service.starts if service is not None else 0


def resident_service_snapshot(
    *,
    identity_sha256: str,
    guard_home: Path,
) -> NativeSupervisorSnapshot:
    """Return privacy-safe aggregate supervision state."""

    return native_supervisor_snapshot(identity_sha256, guard_home)


def close_resident_native_runtimes() -> None:
    """Stop every resident runtime through the contained launcher path."""

    with _SERVICES_LOCK:
        services = list(_SERVICES.values())
        _SERVICES.clear()
    for service in services:
        service.close()


def _unlink_owned_socket(socket_path: Path | None) -> None:
    if socket_path is None:
        return
    try:
        metadata = socket_path.lstat()
        if stat.S_ISSOCK(metadata.st_mode):
            socket_path.unlink()
    except (FileNotFoundError, OSError):
        pass


atexit.register(close_resident_native_runtimes)


__all__ = [
    "close_resident_native_runtimes",
    "prewarm_resident_native_runtime",
    "resident_native_request",
    "resident_service_snapshot",
    "resident_service_starts",
]
