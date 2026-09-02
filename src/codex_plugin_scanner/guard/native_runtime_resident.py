"""Authenticated, bounded resident transport for the Rust Guard runtime.

Linux and macOS use an owner-private Unix socket. Windows uses IPv4 loopback
because default named-pipe ACLs are not strong enough for hook material. Every
platform also performs mutual HMAC authentication with a fresh per-child
256-bit secret delivered only through inherited stdin.

Protocol v2 binds each response to a random request identifier and the exact
request/response bytes. Client admission is non-blocking so resident overload
cannot amplify into Python thread or process growth.
"""

from __future__ import annotations

import atexit
import json
import os
import secrets
import socket
import threading
import time
from collections.abc import Mapping
from pathlib import Path

from .codex_hook_launch_runtime import run_isolated_hook_process
from .native_resident_client import close_native_residents
from .native_runtime_admission import native_resident_admission
from .native_runtime_resident_transport import (
    _AUTH_NONCE_BYTES as _AUTH_NONCE_BYTES,
)
from .native_runtime_resident_transport import (
    _AUTH_PROOF_BYTES as _AUTH_PROOF_BYTES,
)
from .native_runtime_resident_transport import (
    _AUTH_TOKEN_BYTES as _AUTH_TOKEN_BYTES,
)
from .native_runtime_resident_transport import (
    _CLIENT_PROOF_LABEL as _CLIENT_PROOF_LABEL,
)
from .native_runtime_resident_transport import (
    _MAX_REQUEST_BYTES as _MAX_REQUEST_BYTES,
)
from .native_runtime_resident_transport import (
    _SERVER_PROOF_LABEL as _SERVER_PROOF_LABEL,
)
from .native_runtime_resident_transport import (
    _authenticated_loopback_client as _authenticated_loopback_client,
)
from .native_runtime_resident_transport import (
    _proof as _proof,
)
from .native_runtime_resident_transport import (
    _prune_socket_credentials,
    _publish_socket_credential,
    _read_socket_credential,
    _resident_socket_path,
    _resident_start_lock,
    _select_loopback_address,
    _send_authenticated_loopback_request,
    _send_authenticated_unix_request,
    _socket_identity,
    _unix_socket_accepts_connections,
    _unlink_owned_socket,
    _unlink_socket_credential,
)
from .native_runtime_resident_transport import (
    _read_exact as _read_exact,
)
from .native_runtime_resilience import (
    native_record_resident_failure,
    native_record_restart,
    native_record_starting,
    native_runtime_health_snapshot,
)

_START_TIMEOUT_SECONDS = 0.6
_SERVICE_LIFETIME_SECONDS = 7 * 24 * 60 * 60
_SERVICE_OUTPUT_LIMIT = 64 * 1024
_MAX_CLIENT_IN_FLIGHT = 16
_OVERLOAD_RESPONSE = b'{"error":"native_overloaded","retryable":true}'
_HEALTH_REQUEST = b'{"operation":"health","request":{}}'
_StartedResident = tuple[bytes, threading.Event, int]


def _remaining_budget(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


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
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._starts = 0
        self._generation = 0
        self._closed = False
        self._owned_socket_identity: tuple[int, int] | None = None
        self._containment_confirmed = True

    @property
    def starts(self) -> int:
        with self._lock:
            return self._starts

    def request(self, payload: bytes, *, timeout_seconds: float) -> bytes | None:
        if len(payload) > _MAX_REQUEST_BYTES or timeout_seconds <= 0 or not self._transport_configured():
            return None
        if not _CLIENT_IN_FLIGHT.acquire(blocking=False):
            return _OVERLOAD_RESPONSE
        deadline = time.monotonic() + timeout_seconds
        try:
            response = self._send(
                payload,
                timeout_seconds=min(_remaining_budget(deadline), 0.05),
            )
            if response is not None:
                return response
            remaining = _remaining_budget(deadline)
            if remaining <= 0 or not self._ensure_started(timeout_seconds=min(remaining, _START_TIMEOUT_SECONDS)):
                return None
            remaining = _remaining_budget(deadline)
            if remaining <= 0:
                return None
            return self._send(payload, timeout_seconds=remaining)
        finally:
            _CLIENT_IN_FLIGHT.release()

    def _transport_configured(self) -> bool:
        with self._lock:
            if self._closed:
                return False
            if os.name == "nt":
                return self.loopback_address is not None
            return self.socket_path is not None

    def _send(self, payload: bytes, *, timeout_seconds: float) -> bytes | None:
        with self._lock:
            if self._closed:
                return None
            loopback_address = self.loopback_address
            auth_token = self._auth_token
            socket_path = self.socket_path
        if auth_token is None:
            return None
        if os.name == "nt":
            if loopback_address is None:
                return None
            return _send_authenticated_loopback_request(
                loopback_address,
                auth_token,
                payload,
                timeout_seconds=timeout_seconds,
            )
        if socket_path is None:
            return None
        return _send_authenticated_unix_request(
            socket_path,
            auth_token,
            payload,
            timeout_seconds=timeout_seconds,
        )

    def _retire_unusable_supervisor(self) -> None:
        """Release a live supervisor that is no longer serving.

        ``resident-stop`` kills the Rust process without joining this Python
        supervisor. The next request must start a new generation instead of
        waiting on the winding-down thread until the startup budget expires.
        """

        with self._lock:
            if self._closed:
                return
            thread = self._thread
            auth_token = self._auth_token
        if thread is None or not thread.is_alive():
            return
        if auth_token is not None and self._transport_accepts_authenticated_connections(timeout_seconds=0.05):
            return
        with self._lock:
            if self._thread is thread:
                self._stop_event.set()
                self._auth_token = None
                self._thread = None

    def _ensure_started(self, *, timeout_seconds: float) -> bool:
        if timeout_seconds <= 0:
            return False
        deadline = time.monotonic() + timeout_seconds
        health = native_runtime_health_snapshot(self.identity_sha256, self.guard_home)
        if health.circuit_open or health.state in {"integrity_failed", "quarantined"}:
            return False
        remaining = _remaining_budget(deadline)
        if remaining <= 0:
            return False
        with _resident_start_lock(self.socket_path, timeout_seconds=remaining) as acquired:
            if not acquired:
                return False
            if time.monotonic() >= deadline:
                return False
            with self._lock:
                if self._closed:
                    return False
                if os.name == "nt" and self.loopback_address is None:
                    return False
                if os.name != "nt" and self.socket_path is None:
                    return False
            self._retire_unusable_supervisor()
            with self._lock:
                if self._closed:
                    return False
                thread = self._thread
            if (
                os.name != "nt"
                and (thread is None or not thread.is_alive())
                and _unix_socket_accepts_connections(self.socket_path)
            ):
                return self._adopt_running_resident(timeout_seconds=min(_remaining_budget(deadline), 0.1))
            thread, started = self._start_thread_if_needed()
            if thread is None:
                return False
            return self._wait_until_ready(thread=thread, started=started, deadline=deadline)

    def _start_thread_if_needed(self) -> tuple[threading.Thread | None, _StartedResident | None]:
        with self._lock:
            if self._closed:
                return None, None
            thread = self._thread
            if thread is not None and thread.is_alive():
                return thread, None
            if os.name != "nt" and self.socket_path is not None:
                _prune_socket_credentials(self.socket_path)
            stop_event = threading.Event()
            auth_token = secrets.token_bytes(_AUTH_TOKEN_BYTES)
            self._stop_event = stop_event
            self._auth_token = auth_token
            self._containment_confirmed = False
            self._generation += 1
            generation = self._generation
            if self._starts == 0:
                native_record_starting(self.identity_sha256, self.guard_home)
            else:
                native_record_restart(self.identity_sha256, self.guard_home)
            thread = threading.Thread(
                target=self._run,
                args=(stop_event, auth_token, generation),
                name="hol-guard-native-runtime",
                daemon=True,
            )
            self._thread = thread
            self._starts += 1
            thread.start()
            return thread, (auth_token, stop_event, generation)

    def _wait_until_ready(
        self,
        *,
        thread: threading.Thread,
        started: _StartedResident | None,
        deadline: float,
    ) -> bool:
        while time.monotonic() < deadline:
            remaining = _remaining_budget(deadline)
            if remaining <= 0:
                break
            if self._transport_accepts_authenticated_connections(timeout_seconds=min(remaining, 0.1)):
                if started is None or os.name == "nt" or self._publish_started_credential(started):
                    return True
                break
            with self._lock:
                if self._closed or self._thread is not thread or not thread.is_alive():
                    break
            time.sleep(min(0.01, _remaining_budget(deadline)))
        if started is not None:
            self._cancel_start(started)
        return False

    def _cancel_start(self, started: _StartedResident) -> None:
        """Stop a resident that failed its bounded startup admission."""

        _auth_token, stop_event, generation = started
        stop_event.set()
        with self._lock:
            if self._generation == generation:
                self._auth_token = None

    def _publish_started_credential(self, started: _StartedResident) -> bool:
        auth_token, stop_event, generation = started
        # Snapshot both the destination and its identity with the generation;
        # a concurrent close/restart must not publish credentials to a
        # different socket instance.
        with self._lock:
            if self._closed or self._generation != generation:
                stop_event.set()
                return False
            socket_path = self.socket_path
            identity = _socket_identity(socket_path) if socket_path is not None else None
        if (
            socket_path is None
            or identity is None
            or not _publish_socket_credential(
                socket_path,
                expected_identity=identity,
                auth_token=auth_token,
            )
        ):
            stop_event.set()
            return False
        with self._lock:
            if self._generation == generation:
                self._owned_socket_identity = identity
        return True

    def _adopt_running_resident(self, *, timeout_seconds: float) -> bool:
        socket_path = self.socket_path
        if socket_path is None or timeout_seconds <= 0:
            return False
        identity = _socket_identity(socket_path)
        if identity is None:
            return False
        auth_token = _read_socket_credential(socket_path, expected_identity=identity)
        if auth_token is None:
            return False
        with self._lock:
            if self._closed:
                return False
            self._auth_token = auth_token
        if self._transport_accepts_authenticated_connections(timeout_seconds=timeout_seconds):
            return True
        with self._lock:
            if self._thread is None and self._auth_token == auth_token:
                self._auth_token = None
        return False

    def _transport_accepts_authenticated_connections(self, *, timeout_seconds: float) -> bool:
        if timeout_seconds <= 0:
            return False
        response = self._send(_HEALTH_REQUEST, timeout_seconds=timeout_seconds)
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
            input_text=auth_token.hex() + "\n",
            cwd=self.executable.parent,
            environment=self.environment,
            timeout_seconds=_SERVICE_LIFETIME_SECONDS,
            output_limit=_SERVICE_OUTPUT_LIMIT,
            stop_event=stop_event,
            parent_liveness=True,
        )
        with self._lock:
            current_generation = generation == self._generation
            intentional_stop = self._closed or stop_event.is_set()
            if current_generation:
                self._auth_token = None
                self._containment_confirmed = not result.containment_failed
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

    def close(self) -> bool:
        with self._lock:
            self._closed = True
            self._stop_event.set()
            thread = self._thread
            auth_token = self._auth_token
            self._auth_token = None
            owned_socket_identity = self._owned_socket_identity
        with _resident_start_lock(self.socket_path, timeout_seconds=1.5) as acquired:
            if thread is not None and thread.is_alive():
                thread.join(timeout=1.5)
            with self._lock:
                thread_stopped = thread is None or not thread.is_alive()
                contained = thread_stopped and self._containment_confirmed
            if acquired and contained:
                _unlink_socket_credential(
                    self.socket_path,
                    expected_identity=owned_socket_identity,
                    auth_token=auth_token,
                )
                _unlink_owned_socket(self.socket_path, expected_identity=owned_socket_identity)
            elif not contained:
                native_record_resident_failure(
                    self.identity_sha256,
                    self.guard_home,
                    reason="native_resident_containment_failed",
                )
        with self._lock:
            if contained and self._thread is thread:
                self._thread = None
            if contained and acquired:
                self._owned_socket_identity = None
        return contained


_SERVICES_LOCK = threading.Lock()
_SERVICES: dict[tuple[str, str, str], _ResidentService] = {}
_CLIENT_IN_FLIGHT = threading.BoundedSemaphore(_MAX_CLIENT_IN_FLIGHT)


@native_resident_admission
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
    return service.request(payload, timeout_seconds=timeout_seconds)


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


def close_resident_native_runtimes() -> None:
    """Stop every resident runtime through the contained launcher path."""
    with _SERVICES_LOCK:
        services = list(_SERVICES.items())
    for key, service in services:
        if service.close():
            with _SERVICES_LOCK:
                if _SERVICES.get(key) is service:
                    _SERVICES.pop(key, None)
    close_native_residents()


atexit.register(close_resident_native_runtimes)


__all__ = [
    "close_resident_native_runtimes",
    "resident_native_request",
    "resident_service_starts",
]
