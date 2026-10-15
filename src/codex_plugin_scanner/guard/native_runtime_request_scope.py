"""Per-request native runtime status reuse for daemon hook handling.

One hook request validates the runtime binary once: review paths probe
``native_runtime_status`` from several call sites, and every probe re-hashes
the whole binary.  The request-scoped store shares that single validation.
Every new hook request still re-validates, and Windows keeps uncached hashing
across requests (``native_binary_identity._CACHE_ENABLED`` is POSIX-only).
Candidate discovery — which in force mode scans installed distribution
metadata — also runs once per request; nothing is reused across requests.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
from typing import Protocol, TypeVar
from urllib.parse import urlparse

from .native_runtime_values import NativeRuntimeStatus

# (native mode, runtime-candidate strings) — the inputs that decide which
# binary a status was computed from.  A mode or candidate-list change inside
# a request therefore always recomputes instead of reusing a stale status.
_RequestKey = tuple[str, tuple[str, ...]]


class _PostHandler(Protocol):
    path: str


_Handler = TypeVar("_Handler", bound=_PostHandler)


def scoped_hook_post(method: Callable[[_Handler], None]) -> Callable[[_Handler], None]:
    """Share native status for hook POSTs, including route classification."""

    @wraps(method)
    def dispatch(handler: _Handler) -> None:
        parts = [part for part in urlparse(handler.path).path.split("/") if part]
        hook_path = len(parts) == 3 and parts[:2] == ["v1", "hooks"]
        with native_status_request_scope() if hook_path else nullcontext():
            method(handler)

    return dispatch


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

_REQUEST_CANDIDATES: ContextVar[dict[tuple[str, str | None], tuple[Path, ...]] | None] = ContextVar(
    "guard_native_runtime_candidates_request",
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
    candidates: dict[tuple[str, str | None], tuple[Path, ...]] = {}
    token = _REQUEST_STATUS.set(scope)
    candidates_token = _REQUEST_CANDIDATES.set(candidates)
    try:
        yield scope
    finally:
        _REQUEST_CANDIDATES.reset(candidates_token)
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


def scoped_candidates(
    key: tuple[str, str | None],
    discover: Callable[[], tuple[Path, ...]],
) -> tuple[Path, ...]:
    """Return the request-scoped candidates for ``key``, discovering once."""

    scope = _REQUEST_CANDIDATES.get()
    if scope is None:
        return discover()
    if key not in scope:
        scope[key] = discover()
    return scope[key]
