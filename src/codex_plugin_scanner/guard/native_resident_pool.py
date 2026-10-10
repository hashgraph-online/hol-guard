"""Bounded resident stream ownership and concurrency."""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from pathlib import Path

from .native_resident_stream import _PersistentNativeClient


class _PersistentNativeClientPool:
    """Bounded lazy pool of streams for one executable and Guard state root.

    A stream carries one request at a time because its response frames have no
    request identifier. Multiple persistent streams therefore provide bounded
    parallel dispatch without changing the authenticated wire protocol.
    """

    def __init__(self, *, executable: Path, state_dir: Path, environment: Mapping[str, str]) -> None:
        self._executable = executable
        self._state_dir = state_dir
        self._environment = environment
        self._clients: set[_PersistentNativeClient] = set()
        self._retiring: set[_PersistentNativeClient] = set()
        self._idle: list[_PersistentNativeClient] = []
        self._condition = threading.Condition()
        self._closed = False

    def has_idle_client(self) -> bool:
        """True when a live client is parked and can serve without a spawn."""

        with self._condition:
            if self._closed:
                return False
            return any(client._process is not None and client._process.poll() is None for client in self._idle)

    def _lease(self, *, deadline_monotonic: float) -> _PersistentNativeClient | None:
        from . import native_resident_client as owner

        with self._condition:
            while not self._closed:
                # Timed-out requests may have no teardown budget left. Retain
                # ownership until close confirms containment, but reclaim
                # completed retirees instead of permanently exhausting slots.
                for retiring in tuple(self._retiring):
                    if retiring.close(deadline_monotonic=time.monotonic()):
                        self._retiring.discard(retiring)
                        self._clients.discard(retiring)
                if self._idle:
                    return self._idle.pop()
                if len(self._clients) < owner._MAX_PERSISTENT_CLIENTS:
                    client = owner._PersistentNativeClient(
                        executable=self._executable,
                        state_dir=self._state_dir,
                        environment=self._environment,
                        failure_recorder=owner._LAST_FAILURE_CODE.set,
                    )
                    self._clients.add(client)
                    return client
                remaining = deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(timeout=min(remaining, 0.05) if self._retiring else remaining)
        owner._LAST_FAILURE_CODE.set("native_client_pool_exhausted")
        return None

    def request(self, payload: bytes, *, deadline_monotonic: float) -> bytes | None:
        client = self._lease(deadline_monotonic=deadline_monotonic)
        if client is None:
            return None
        response: bytes | None = None
        try:
            response = client.request(payload, deadline_monotonic=deadline_monotonic)
            return response
        finally:
            close_client = False
            with self._condition:
                if client not in self._clients:
                    close_client = True
                elif self._closed or response is None:
                    self._retiring.add(client)
                    close_client = True
                else:
                    self._idle.append(client)
                self._condition.notify()
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

    def close(self, *, deadline_monotonic: float | None = None) -> bool:
        from . import native_resident_client as owner

        with self._condition:
            self._closed = True
            clients = tuple(self._clients)
            self._idle.clear()
            self._condition.notify_all()
        for client in clients:
            contained = (
                client.close() if deadline_monotonic is None else client.close(deadline_monotonic=deadline_monotonic)
            )
            if contained is not False:
                with self._condition:
                    self._clients.discard(client)
                    self._retiring.discard(client)
        for client in clients:
            owner._contain_persistent_resident(client)
        with self._condition:
            return not self._clients
