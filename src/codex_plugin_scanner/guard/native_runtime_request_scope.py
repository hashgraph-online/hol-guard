"""Per-request native runtime status reuse for daemon hook handling.

One hook request validates the runtime binary once: review paths probe
``native_runtime_status`` from several call sites, and every probe re-hashes
the whole binary.  The request-scoped store shares that single validation.
Every new hook request still re-validates, and Windows keeps uncached hashing
across requests (``native_binary_identity._CACHE_ENABLED`` is POSIX-only).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from .native_runtime_values import NativeRuntimeStatus

# (native mode, runtime-candidate strings) — the inputs that decide which
# binary a status was computed from.  A mode or candidate-list change inside
# a request therefore always recomputes instead of reusing a stale status.
_RequestKey = tuple[str, tuple[str, ...]]


def _status_binary_unchanged(status: NativeRuntimeStatus) -> bool:
    """True while the on-disk binary still matches the validated identity.

    ``stat()`` is cheap relative to re-hashing the whole binary, so checking
    ``size``/``mtime_ns`` per read keeps a reused status honest against a
    mid-request binary swap without paying the full re-validation cost.
    """

    identity = status.identity
    if identity is None:
        # Nothing was validated (mode=off / unavailable); there is no file to
        # keep fresh.
        return True
    try:
        meta = Path(identity.path).stat()
    except OSError:
        return False
    return meta.st_size == identity.size and meta.st_mtime_ns == identity.mtime_ns


_REQUEST_STATUS: ContextVar[dict[_RequestKey, NativeRuntimeStatus] | None] = ContextVar(
    "guard_native_runtime_status_request",
    default=None,
)


@contextmanager
def native_status_request_scope() -> Iterator[dict[_RequestKey, NativeRuntimeStatus]]:
    """Bind a per-request status store; nested scopes share the active one."""

    existing = _REQUEST_STATUS.get()
    if existing is not None:
        yield existing
        return
    scope: dict[_RequestKey, NativeRuntimeStatus] = {}
    token = _REQUEST_STATUS.set(scope)
    try:
        yield scope
    finally:
        _REQUEST_STATUS.reset(token)


def _resolved_candidate_path(candidate: Path) -> Path | None:
    """Resolve a runtime candidate the way ``validate_native_binary`` does."""

    try:
        return candidate.expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return None


def scoped_status(key: _RequestKey) -> NativeRuntimeStatus | None:
    """Return the stored status for ``key`` while its binary stays unchanged."""

    scope = _REQUEST_STATUS.get()
    if scope is None:
        return None
    status = scope.get(key)
    if status is None or status.identity is None or not _status_binary_unchanged(status):
        return None
    return status


def remember_scoped_status(key: _RequestKey, status: NativeRuntimeStatus) -> None:
    """Keep a validated status for ``key``; unvalidated results never store."""

    scope = _REQUEST_STATUS.get()
    if scope is not None and status.identity is not None:
        scope[key] = status
