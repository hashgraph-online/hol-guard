"""Helpers for exercising the native resident with an authenticated policy."""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from .native_policy_snapshot import get_native_policy_snapshot_publisher
from .native_policy_snapshot_constants import POLICY_SNAPSHOT_UNRECOVERABLE_ERRORS, TRANSIENT_PUBLICATION_ERRORS
from .store import GuardStore

_STARTUP_ERROR_CODES = (
    POLICY_SNAPSHOT_UNRECOVERABLE_ERRORS
    | TRANSIENT_PUBLICATION_ERRORS
    | {
        "native_policy_snapshot_expired",
        "native_policy_snapshot_publish_failed",
    }
)


def _publisher_startup_error(publisher: object) -> str:
    try:
        error = getattr(publisher, "last_error", object())
        if error is None:
            return "none"
        if type(error) is str:
            for code in _STARTUP_ERROR_CODES:
                if error == code:
                    return code
    except Exception:
        pass
    return "unavailable"


def _publisher_startup_diagnostics(publisher: object, elapsed: float) -> str:
    """Describe only the known test publisher worker, without payloads or paths."""

    prefix = f"wait_seconds={elapsed:.3f} last_error={_publisher_startup_error(publisher)}"
    try:
        worker = getattr(publisher, "_thread", None)
        if not isinstance(worker, threading.Thread):
            return f"{prefix} worker_alive=unavailable worker_stack=unavailable"
        alive = worker.is_alive()
        frame = sys._current_frames().get(worker.ident) if alive and worker.ident is not None else None
        if not any(active is worker for active in threading.enumerate()):
            frame = None
        locations: list[str] = []
        for _ in range(6):
            if frame is None:
                break
            code = frame.f_code
            basename = code.co_filename.replace("\\", "/").rsplit("/", 1)[-1]
            # Keep each location ASCII and bounded; never inspect source or locals.
            filename = "".join(c if c.isascii() and (c.isalnum() or c in "._-") else "_" for c in basename[:80])
            function = "".join(c if c.isascii() and (c.isalnum() or c == "_") else "_" for c in code.co_name[:64])
            locations.append(f"{filename}:{function}:{frame.f_lineno}")
            frame = frame.f_back
        stack = " <- ".join(locations) or "unavailable"
        return f"{prefix} worker_alive={str(alive).lower()} worker_stack={stack}"[:1024]
    except Exception:
        # Diagnostics must not mask the readiness failure or expose exception text.
        return f"{prefix} worker_alive=unavailable worker_stack=unavailable"


@contextmanager
def native_policy_snapshot(guard_home: Path) -> Iterator[Mapping[str, object]]:
    """Publish and yield the current ACKed snapshot for a test Guard home."""

    publisher = get_native_policy_snapshot_publisher(GuardStore(guard_home))
    publisher.start()
    try:
        # Hosted macOS Intel runners can take the same cold-start path as
        # Windows before the resident accepts its first authenticated policy.
        ready_wait_seconds = 25.0 if sys.platform in {"darwin", "win32"} else 3.0
        wait_started = time.monotonic()
        if not publisher.wait_until_ready(wait_started + ready_wait_seconds):
            diagnostics = _publisher_startup_diagnostics(publisher, time.monotonic() - wait_started)
            raise AssertionError(f"native policy publisher was not ready: {diagnostics}")
        snapshot = publisher.current_snapshot()
        if snapshot is None:
            raise AssertionError("native policy publisher returned no ACKed snapshot")
        yield snapshot
    finally:
        publisher.close()
