"""Short-lived reuse of public registry metadata between package reviews.

A package review asks the public registry for the package's metadata document.
Large documents take seconds to download, and the agent hook that waits for the
review has a few seconds in total. Without reuse, a review that ran out of time
started the same download again when the agent retried, and ran out of time
again.

This cache keeps a successful credential-free registry GET for a minute, shares
one download between concurrent reviews of the same document, and lets a
caller that sets a wait deadline stop waiting before its hook deadline while
the download finishes in the background. Nothing here decides anything: the
resident parses every body and owns every verdict, exactly as for a fresh read.
"""

from __future__ import annotations

import contextvars
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Hashable, Iterator
from contextlib import contextmanager

TTL_SECONDS = 60.0
MAX_ENTRIES = 16
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_BACKGROUND_READS = 4
# Time kept back from the hook deadline to render and return the retry answer.
SETTLE_SECONDS = 0.75

RawResponse = tuple[int, tuple[tuple[str, str], ...], bytes]
# URL, request headers, response byte limit, redirect limit.
CacheKey = tuple[str, tuple[tuple[str, str], ...], int, int, Hashable]
ReadResult = RawResponse | dict[str, object]

_WAIT_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "guard_registry_wait_deadline", default=None
)


class RegistryDeadlineError(TimeoutError):
    """The caller's deadline arrived while a registry read was still running."""


@contextmanager
def registry_wait_deadline(deadline_monotonic: float | None) -> Iterator[None]:
    """Stop waiting for registry reads ``SETTLE_SECONDS`` before this deadline.

    Only callers that can answer :class:`RegistryDeadlineError` set it; everyone
    else waits for the read as before.
    """

    token = _WAIT_DEADLINE.set(deadline_monotonic)
    try:
        yield
    finally:
        _WAIT_DEADLINE.reset(token)


class _Read:
    def __init__(self) -> None:
        self.done = threading.Event()
        self.result: ReadResult = {"kind": "error", "message": "read did not finish"}


class RegistryCache:
    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[CacheKey, tuple[float, RawResponse]] = OrderedDict()
        self._bytes = 0
        self._pending: dict[CacheKey, _Read] = {}

    def fetch(self, key: CacheKey, read: Callable[[], ReadResult]) -> ReadResult:
        """A fresh cached response, a shared in-flight read, or a new read."""

        deadline = _WAIT_DEADLINE.get()
        with self._lock:
            cached = self._fresh(key)
            if cached is not None:
                return cached
            pending = self._pending.get(key)
            background = pending is None and deadline is not None and len(self._pending) < MAX_BACKGROUND_READS
            if pending is None:
                pending = _Read()
                self._pending[key] = pending
                owner = True
            else:
                owner = False
        if owner and not background:
            self._complete(key, pending, read)
            return pending.result
        if owner:
            context = contextvars.copy_context()
            thread = threading.Thread(
                target=context.run,
                args=(self._complete, key, pending, read),
                name="hol-guard-registry-read",
                daemon=True,
            )
            thread.start()
        wait = None if deadline is None else max(0.0, deadline - SETTLE_SECONDS - self._clock())
        if not pending.done.wait(wait):
            raise RegistryDeadlineError("registry read still running at the hook deadline")
        return pending.result

    def clear(self) -> None:
        """Forget every stored response; reads already running still finish."""

        with self._lock:
            self._entries.clear()
            self._bytes = 0

    def _complete(self, key: CacheKey, pending: _Read, read: Callable[[], ReadResult]) -> None:
        try:
            pending.result = read()
        finally:
            with self._lock:
                self._pending.pop(key, None)
                result = pending.result
                if isinstance(result, tuple) and result[0] == 200 and len(result[2]) <= key[2]:
                    self._store(key, result)
            pending.done.set()

    def _fresh(self, key: CacheKey) -> RawResponse | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        stored_at, response = entry
        if self._clock() - stored_at >= TTL_SECONDS:
            self._drop(key)
            return None
        return response

    def _store(self, key: CacheKey, response: RawResponse) -> None:
        size = len(response[2])
        if size > MAX_TOTAL_BYTES:
            return
        self._drop(key)
        while self._entries and (len(self._entries) >= MAX_ENTRIES or self._bytes + size > MAX_TOTAL_BYTES):
            self._drop(next(iter(self._entries)))
        self._entries[key] = (self._clock(), response)
        self._bytes += size

    def _drop(self, key: CacheKey) -> None:
        entry = self._entries.pop(key, None)
        if entry is not None:
            self._bytes -= len(entry[1][2])


REGISTRY_CACHE = RegistryCache()

__all__ = [
    "REGISTRY_CACHE",
    "CacheKey",
    "RawResponse",
    "RegistryCache",
    "RegistryDeadlineError",
    "registry_wait_deadline",
]
