"""Bounded request execution for the local Guard daemon."""

from __future__ import annotations

import queue
import socket
import threading
import time
from collections.abc import Callable
from typing import TypeAlias

_TransportWorkItem: TypeAlias = tuple[socket.socket, tuple[str, int]]


class BoundedRequestExecutor:
    def __init__(
        self,
        *,
        name: str,
        workers: int,
        queue_limit: int,
        run: Callable[[socket.socket, tuple[str, int]], None],
        discard: Callable[[socket.socket], None],
    ) -> None:
        self._queue: queue.Queue[_TransportWorkItem | None] = queue.Queue(maxsize=queue_limit)
        self._run = run
        self._discard = discard
        self._stopped = threading.Event()
        self._lifecycle_lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        try:
            for index in range(workers):
                thread = threading.Thread(
                    target=self._worker,
                    daemon=True,
                    name=f"guard-http-{name}-{index + 1}",
                )
                thread.start()
                self._threads.append(thread)
        except BaseException:
            self._stopped.set()
            for _ in self._threads:
                self._queue.put(None, timeout=1.0)
            for thread in self._threads:
                thread.join(timeout=1.0)
            raise

    @property
    def threads(self) -> tuple[threading.Thread, ...]:
        return tuple(self._threads)

    def submit(self, request: socket.socket, client_address: tuple[str, int]) -> bool:
        with self._lifecycle_lock:
            if self._stopped.is_set():
                return False
            try:
                self._queue.put_nowait((request, client_address))
            except queue.Full:
                return False
        return True

    def shutdown(self, *, timeout_seconds: float) -> bool:
        with self._lifecycle_lock:
            if not self._stopped.is_set():
                self._stopped.set()
                while True:
                    try:
                        item = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    if item is not None:
                        self._discard(item[0])
                    self._queue.task_done()
                for _ in self._threads:
                    self._queue.put_nowait(None)
        deadline = time.monotonic() + timeout_seconds
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
        return all(not thread.is_alive() for thread in self._threads)

    def _worker(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                self._run(*item)
            finally:
                self._queue.task_done()
