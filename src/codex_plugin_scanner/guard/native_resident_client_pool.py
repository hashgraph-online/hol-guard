"""Bounded pool of persistent Rust resident client streams.

A pool owns the client streams for one runtime and Guard state root. A parked
stream is the client lease that keeps the managed resident up, so the pool
decides when a stream is borrowed, parked, trimmed, or retired.
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
import time
from collections.abc import Mapping
from contextvars import ContextVar
from pathlib import Path

from .native_process_stop_scope import native_process_stop_requested
from .native_resident_revival import (
    RESTART_BLOCKED_CODE,
    HoldKey,
    arm_restart_hold,
    clear_restart_hold,
    is_restart_blocked_frame,
    restart_blocked_frame,
    restart_hold_active,
)
from .native_resident_stream import _PersistentNativeClient

_RESIDENT_REQUEST_LOG = "HOL_GUARD_RESIDENT_REQUEST_LOG"
_BACKGROUND_REQUEST_LABEL: ContextVar[str | None] = ContextVar("_background_request_label", default=None)


@contextlib.contextmanager
def background_resident_requests(label: str):
    """Name this thread's resident calls for the request log that counts them.

    A daemon thread that drains its own queue spends round trips on its own
    schedule, so no hook request waits on them. The budget test reads the log
    to tell those apart from the calls a hook makes inline; without a name of
    their own they would look like per-request growth. Production leaves the
    log unset and nothing here runs.
    """

    token = _BACKGROUND_REQUEST_LABEL.set(label)
    try:
        yield
    finally:
        _BACKGROUND_REQUEST_LABEL.reset(token)


_BACKGROUND_LANE: ContextVar[bool] = ContextVar("_background_resident_lane", default=False)


@contextlib.contextmanager
def background_resident_lane():
    """Leave the last parked stream to the hook calls this thread runs beside.

    A daemon thread (policy publication, evidence drains) has seconds of budget;
    a hook has milliseconds. Opening a stream starts a client process, which a
    loaded host can take more than a second to do, so a hook that finds every
    parked stream borrowed by background work pays that start inside its own
    deadline. Calls made in this scope open a stream of their own rather than
    take the only parked one.
    """

    token = _BACKGROUND_LANE.set(True)
    try:
        yield
    finally:
        _BACKGROUND_LANE.reset(token)


def _record_resident_request(payload: bytes = b"") -> None:
    """Append one line when a test asks every process to count resident calls.

    The line is the operation name when the payload is a resident envelope, so
    a test can assert which ops a workload used; otherwise it is ``1``. A
    thread inside ``background_resident_requests`` writes that name instead.

    Hook workers are spawned processes, so an in-process monkeypatch cannot see
    their round trips. The variable is unset in production and the write then
    does not run. A configured log that cannot be written fails the request.
    """

    path = os.environ.get(_RESIDENT_REQUEST_LOG)
    if not path:
        return
    background = _BACKGROUND_REQUEST_LABEL.get()
    if background is not None:
        _append_resident_request(path, background.encode("ascii", "replace"))
        return
    label = b"1"
    try:
        operation = json.loads(payload).get("operation")
        if isinstance(operation, str) and operation.isidentifier():
            label = operation.encode("ascii", "replace")
    except (ValueError, AttributeError, UnicodeDecodeError):
        pass
    _append_resident_request(path, label)


def _append_resident_request(path: str, label: bytes) -> None:
    descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, label + b"\n")
    finally:
        os.close(descriptor)


_MAX_PERSISTENT_CLIENTS = 16
# Overlap fans out to _MAX_PERSISTENT_CLIENTS streams, and each parked stream
# keeps a child process alive. A stream parked this long behind a newer one is
# retired, so bursts keep their streams warm and a quiet process sheds them.
_IDLE_STREAM_TTL_SECONDS = 30.0
_LAST_FAILURE_CODE: ContextVar[str | None] = ContextVar(
    "native_resident_client_failure_code",
    default=None,
)
# The pool whose restart hold produced the current context's refusal. A caller
# deciding whether to wait out that hold needs the key it was armed under, not
# whichever runtime happens to hold the longest one.
_LAST_HOLD_KEY: ContextVar[HoldKey | None] = ContextVar(
    "native_resident_client_failure_hold_key",
    default=None,
)


def _is_resident_startup_error(response: bytes) -> bool:
    """True for the resident's own failure frame, which carries no request schema.

    A client that answered with it is bound to a resident that never came up
    (for example the state directory did not exist yet). Parking it would hand
    that stale failure to every later request for the same home.
    """

    if not response.startswith(b'{"error":"native_resident_'):
        return False
    try:
        decoded = json.loads(response)
    except ValueError:
        return False
    return isinstance(decoded, dict) and set(decoded) == {"error", "retryable"}


class _PersistentNativeClientPool:
    """Bounded lazy pool of streams for one executable and Guard state root.

    A stream carries one request at a time because its response frames have no
    request identifier. Multiple persistent streams therefore provide bounded
    parallel dispatch without changing the authenticated wire protocol.
    """

    def __init__(self, *, executable: Path, state_dir: Path, environment: Mapping[str, str]) -> None:
        self._executable = executable
        self._state_dir = state_dir
        self._hold_key = (str(executable), str(state_dir))
        self._environment = environment
        self._clients: set[_PersistentNativeClient] = set()
        self._retiring: set[_PersistentNativeClient] = set()
        self._idle: list[_PersistentNativeClient] = []
        self._parked_at: dict[_PersistentNativeClient, float] = {}
        self._trim_timer: threading.Timer | None = None
        self._condition = threading.Condition()
        self._closed = False

    def has_idle_client(self) -> bool:
        """True when a live client is parked and can serve without a spawn."""

        with self._condition:
            if self._closed:
                return False
            return any(client._process is not None and client._process.poll() is None for client in self._idle)

    def _lease(
        self, *, deadline_monotonic: float, idle_only: bool = False, idle_wait_seconds: float = 0.0
    ) -> _PersistentNativeClient | None:
        with self._condition:
            if idle_only:
                return self._lease_idle_locked(
                    min(deadline_monotonic, time.monotonic() + max(0.0, idle_wait_seconds)),
                    # Preserve the immediate nonwaiting borrow path. Waiting callers
                    # must not take a parked lease after their request has expired.
                    request_deadline=deadline_monotonic if idle_wait_seconds > 0 else None,
                )
            while not self._closed:
                # Timed-out requests may have no teardown budget left. Retain
                # ownership until close confirms containment, but reclaim
                # completed retirees instead of permanently exhausting slots.
                for retiring in tuple(self._retiring):
                    if retiring.close(deadline_monotonic=time.monotonic()):
                        self._retiring.discard(retiring)
                        self._clients.discard(retiring)
                # Background work keeps the last parked stream for hooks while
                # the pool can still open one of its own. Not while a restart
                # hold is armed: the resident is crash-looping, and a new
                # stream would only start another client the hold refuses.
                spare_last = (
                    _BACKGROUND_LANE.get()
                    and len(self._idle) == 1
                    and len(self._clients) < _MAX_PERSISTENT_CLIENTS
                    and not restart_hold_active(self._hold_key)
                )
                if self._idle and not spare_last:
                    client = self._idle.pop()
                    self._parked_at.pop(client, None)
                    return client
                if len(self._clients) < _MAX_PERSISTENT_CLIENTS:
                    client = _PersistentNativeClient(
                        executable=self._executable,
                        state_dir=self._state_dir,
                        environment=self._environment,
                        failure_recorder=_LAST_FAILURE_CODE.set,
                    )
                    self._clients.add(client)
                    return client
                remaining = deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(timeout=min(remaining, 0.05) if self._retiring else remaining)
        _LAST_FAILURE_CODE.set("native_client_pool_exhausted")
        return None

    def _lease_idle_locked(
        self, wait_until: float, *, request_deadline: float | None = None
    ) -> _PersistentNativeClient | None:
        """Borrow a live parked stream, waiting until ``wait_until`` for one in use.

        Readiness is advisory: another caller can borrow the last stream before
        dispatch, so a stream is selected and removed atomically. The wait only
        covers streams this pool already has busy; with none, nothing can be
        parked and the caller is answered at once, so asking never starts one.
        """

        while not self._closed:
            # Recheck after every condition wait, before consuming a parked
            # lease: a closing owner must never retire the resident's last stream.
            if native_process_stop_requested() or (
                request_deadline is not None and time.monotonic() >= request_deadline
            ):
                _LAST_FAILURE_CODE.set("native_client_timed_out")
                return None
            for client in reversed(self._idle):
                if _client_alive(client):
                    self._idle.remove(client)
                    self._parked_at.pop(client, None)
                    return client
            idle = set(self._idle)
            busy = any(
                _client_alive(client) for client in self._clients if client not in idle and client not in self._retiring
            )
            remaining = wait_until - time.monotonic()
            if not busy or remaining <= 0:
                return None
            # Stop scopes do not notify this pool's condition. Wake periodically
            # so a closing owner does not wait through the full idle grace.
            self._condition.wait(timeout=min(remaining, 0.05))
        return None

    def request(
        self,
        payload: bytes,
        *,
        deadline_monotonic: float,
        diagnostic: bool = False,
        idle_only: bool = False,
        idle_wait_seconds: float = 0.0,
    ) -> bytes | None:
        """Send one request. ``diagnostic`` asks a question about the resident
        rather than giving it work: the answer must not arm or clear the hold
        that gates hook execution, and the stream it borrows is retired rather
        than parked, so the question leaves no lease of its own behind.

        A caller whose stop scope is already set is refused before it borrows a
        stream. Its response wait would end at once and close the borrowed
        stream, and a parked stream is the client lease that keeps the resident
        up, so a closing owner would otherwise take the resident down with it.
        """
        if native_process_stop_requested():
            _LAST_FAILURE_CODE.set("native_client_timed_out")
            return None
        if not idle_only and restart_hold_active(self._hold_key) and not self.has_idle_client():
            # The Rust client just refused to respawn a crash-looping resident.
            # Answer the same bounded refusal instead of spawning a client per call.
            _LAST_FAILURE_CODE.set(RESTART_BLOCKED_CODE)
            _LAST_HOLD_KEY.set(self._hold_key)
            return restart_blocked_frame()
        client = self._lease(
            deadline_monotonic=deadline_monotonic, idle_only=idle_only, idle_wait_seconds=idle_wait_seconds
        )
        if client is None:
            return None
        response: bytes | None = None
        try:
            _record_resident_request(payload)
            response = (
                client.request(payload, deadline_monotonic=deadline_monotonic, allow_start=False)
                if idle_only
                else client.request(payload, deadline_monotonic=deadline_monotonic)
            )
            if response is not None and not diagnostic:
                if is_restart_blocked_frame(response):
                    arm_restart_hold(self._hold_key)
                    _LAST_FAILURE_CODE.set(RESTART_BLOCKED_CODE)
                    _LAST_HOLD_KEY.set(self._hold_key)
                else:
                    clear_restart_hold(self._hold_key)
            return response
        finally:
            close_client = False
            with self._condition:
                if client not in self._clients:
                    close_client = True
                elif self._closed or diagnostic or response is None or _is_resident_startup_error(response):
                    self._retiring.add(client)
                    close_client = True
                else:
                    self._idle.append(client)
                    self._parked_at[client] = time.monotonic()
                    self._schedule_trim_locked()
                # Idle-only borrowers and capacity waiters share this condition.
                self._condition.notify_all()
            if close_client:
                try:
                    contained = client.close(deadline_monotonic=deadline_monotonic)
                except BaseException:
                    with self._condition:
                        if client in self._clients:
                            self._retiring.add(client)
                    raise
                if contained is not False:
                    with self._condition:
                        self._clients.discard(client)
                        self._retiring.discard(client)
                        self._condition.notify_all()

    def _schedule_trim_locked(self) -> None:
        """Arm one timer for the oldest stream parked behind the newest."""

        if self._closed or self._trim_timer is not None or len(self._idle) < 2:
            return
        # Streams are parked in order, so the first one is the oldest.
        due = self._parked_at.get(self._idle[0], time.monotonic()) + _IDLE_STREAM_TTL_SECONDS
        timer = threading.Timer(max(0.0, due - time.monotonic()), self._trim_idle)
        timer.daemon = True
        self._trim_timer = timer
        timer.start()

    def _trim_idle(self) -> None:
        """Retire streams parked past the idle TTL, keeping the newest parked."""

        with self._condition:
            self._trim_timer = None
            if self._closed:
                return
            now = time.monotonic()
            stale = [
                client
                for client in self._idle[:-1]
                if now - self._parked_at.get(client, now) >= _IDLE_STREAM_TTL_SECONDS
            ]
            for client in stale:
                self._idle.remove(client)
                self._parked_at.pop(client, None)
                self._retiring.add(client)
            self._schedule_trim_locked()
        for client in stale:
            try:
                contained = client.close()
            except Exception:
                # The stream stays retiring; the next lease reclaims it.
                continue
            if contained is not False:
                with self._condition:
                    self._clients.discard(client)
                    self._retiring.discard(client)
                    self._condition.notify_all()

    def close(self, *, deadline_monotonic: float | None = None) -> bool:
        clear_restart_hold(self._hold_key)
        with self._condition:
            self._closed = True
            clients = tuple(self._clients)
            self._idle.clear()
            self._parked_at.clear()
            trim_timer, self._trim_timer = self._trim_timer, None
            self._condition.notify_all()
        if trim_timer is not None:
            trim_timer.cancel()
        for client in clients:
            contained = (
                client.close() if deadline_monotonic is None else client.close(deadline_monotonic=deadline_monotonic)
            )
            if contained is not False:
                with self._condition:
                    self._clients.discard(client)
                    self._retiring.discard(client)
        for client in clients:
            _contain_persistent_resident(client)
        with self._condition:
            return not self._clients


def _client_alive(client: _PersistentNativeClient) -> bool:
    process = client._process
    return process is not None and process.poll() is None


def _contain_persistent_resident(client: _PersistentNativeClient) -> None:
    """Close one local stream without stopping the shared resident.

    Hook processes and the local daemon share one managed resident. A one-shot
    client exit that sends ``resident-stop`` kills in-flight reviews in other
    processes. Explicit shutdown stays on ``close_native_residents``.
    """
    _ = client
