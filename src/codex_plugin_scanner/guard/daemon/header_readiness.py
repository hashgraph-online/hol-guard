"""Wake the existing bounded header classifier when its owned sockets change.

This is HTTP transport only. The existing classifier still owns admission,
header completeness, reserved capacity and absolute expiry. Readable partial
prefixes retain the original polling bound, so a trickling peer cannot spin
the watcher. No request bytes are consumed by this wait primitive.
"""

from __future__ import annotations

import selectors
import socket
import threading
from contextlib import suppress
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .server import _GuardDaemonHTTPServer


class HeaderWatchdog:
    """Stop flag whose wait also returns for pending-header readiness."""

    def __init__(self, owner: _GuardDaemonHTTPServer) -> None:
        self._owner = owner
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._reader: socket.socket | None = None
        self._writer: socket.socket | None = None

    def is_set(self) -> bool:
        return self._stop.is_set()

    def clear(self) -> None:
        # Allocate only when the watchdog starts, after successful bind/setup.
        # A stopped watchdog may be started again with a fresh owned pair.
        with self._lock:
            if self._reader is None:
                reader, writer = socket.socketpair()
                try:
                    reader.setblocking(False)
                    writer.setblocking(False)
                except BaseException:
                    reader.close()
                    writer.close()
                    raise
                self._reader, self._writer = reader, writer
            self._stop.clear()

    def set(self) -> None:
        self._stop.set()
        self.notify()

    def notify(self) -> None:
        with self._lock:
            if self._writer is not None:
                with suppress(BlockingIOError, OSError):
                    self._writer.send(b"\x00")

    def close(self) -> None:
        self.set()
        with self._lock:
            reader, writer = self._reader, self._writer
            self._reader = self._writer = None
        for endpoint in (reader, writer):
            if endpoint is not None:
                with suppress(OSError):
                    endpoint.close()

    def _pending(self) -> list[socket.socket]:
        owner = self._owner
        with owner.unclassified_connections_lock:
            pending = [
                owner.unclassified_connections[key][0]
                for key in owner.pending_classifications
                if key in owner.unclassified_connections
            ]
            pending.extend(probe[0] for probe in owner.saturation_probes.values())
        return pending

    def wait(self, timeout: float) -> bool:
        if self._stop.is_set():
            return True
        with self._lock:
            reader = self._reader
        if reader is None:
            return self._stop.wait(timeout)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(reader, selectors.EVENT_READ, data="wakeup")
                for request in self._pending():
                    try:
                        selector.register(request, selectors.EVENT_READ, data="pending")
                    except (KeyError, OSError, ValueError):
                        continue  # A concurrent retirement won ownership.
                for key, _mask in selector.select(0):
                    if key.data == "wakeup":
                        with suppress(BlockingIOError, OSError):
                            reader.recv(4096)
                        return self._stop.is_set()
                    request = key.fileobj
                    if isinstance(request, socket.socket) and self._owner._buffered_request_headers_complete(
                        request, pending=True
                    ):
                        return self._stop.is_set()
                    # Level-triggered readiness would repeatedly report this
                    # unchanged partial prefix. Revisit it on the old timer.
                    with suppress(KeyError, OSError, ValueError):
                        selector.unregister(request)
                ready = selector.select(timeout)
                if any(key.data == "wakeup" for key, _mask in ready):
                    with suppress(BlockingIOError, OSError):
                        reader.recv(4096)
        except (OSError, ValueError):
            # Closed descriptors or a platform selector limit cannot remove
            # the existing periodic expiry/classification path.
            return self._stop.wait(timeout)
        return self._stop.is_set()
