"""Process-wide reuse of a verified native runtime status.

``native_runtime_status`` outside a daemon request scope re-stats the binary,
re-reads the bundled manifest and, for a runtime younger than the identity
cache window or on non-POSIX hosts, re-hashes the whole binary. This cache keeps
one verified ``ready`` status per process and trusts it only while a stat-only
check proves nothing moved: the resolved candidate path, the binary's full stat
identity and owner, and the manifest's full stat identity and owner must all be
unchanged. Any difference, stat error or disappearance drops the entry so the
caller recomputes and fails closed. Files changed within the identity cache age
window, and every non-POSIX host, never enter the cache.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from .file_identity import full_stat_identity
from .native_runtime_request_scope import _RequestKey, _resolved_candidate_path
from .native_runtime_values import NativeRuntimeStatus

_MIN_AGE_NS = 2_000_000_000
_MAX_ENTRIES = 8
_ENABLED = os.name == "posix" and hasattr(os, "O_NOFOLLOW")
_LOCK = threading.Lock()
_Fingerprint = tuple[int, ...]
_STATUSES: dict[_RequestKey, tuple[NativeRuntimeStatus, _Fingerprint, _Fingerprint | None]] = {}


def _fingerprint(path: Path, *, follow: bool) -> _Fingerprint | None:
    """Return a stat-only identity for ``path`` when it is old enough to trust."""

    try:
        metadata = path.stat() if follow else path.lstat()
    except OSError:
        return None
    changed_at = int(getattr(metadata, "st_ctime_ns", 0))
    if changed_at <= 0 or time.time_ns() - changed_at < _MIN_AGE_NS:
        return None
    return (*full_stat_identity(metadata), int(metadata.st_uid), int(metadata.st_gid))


def _manifest_path(binary: Path) -> Path:
    return binary.with_name("runtime-manifest.json")


def process_snapshot(candidates: tuple[Path, ...]) -> tuple[Path, _Fingerprint, _Fingerprint | None] | None:
    """Fingerprint the preferred candidate and its manifest before a status is computed."""

    if not _ENABLED or not candidates:
        return None
    path = _resolved_candidate_path(candidates[0])
    binary = None if path is None else _fingerprint(path, follow=True)
    if path is None or binary is None:
        return None
    return path, binary, _fingerprint(_manifest_path(path), follow=False)


def remember_process_status(
    key: _RequestKey,
    status: NativeRuntimeStatus,
    before: tuple[Path, _Fingerprint, _Fingerprint | None] | None,
) -> None:
    """Keep a ready status only when it describes the preferred candidate and never changed while it was computed.

    ``before`` is the snapshot taken ahead of validation. Requiring the same stat
    identity afterwards means a file swapped during validation, or a lower-priority
    fallback chosen while the preferred runtime was briefly unavailable, is never
    trusted for the life of the process.
    """

    identity = status.identity
    if before is None or identity is None or not status.available or not status.compatible:
        return
    path, binary, manifest = before
    if identity.path != path or _fingerprint(path, follow=True) != binary:
        return
    if status.manifest is not None and (
        manifest is None or _fingerprint(_manifest_path(path), follow=False) != manifest
    ):
        return
    with _LOCK:
        if key not in _STATUSES and len(_STATUSES) >= _MAX_ENTRIES:
            _STATUSES.pop(next(iter(_STATUSES)))
        _STATUSES[key] = (status, binary, manifest if status.manifest is not None else None)


def process_status(key: _RequestKey, candidates: tuple[Path, ...]) -> NativeRuntimeStatus | None:
    """Return the cached status while stat metadata proves the runtime is unchanged."""

    with _LOCK:
        entry = _STATUSES.get(key)
    if entry is None:
        return None
    status, binary, manifest = entry
    identity = status.identity
    if (
        identity is None
        or not candidates
        or identity.path != _resolved_candidate_path(candidates[0])
        or _fingerprint(identity.path, follow=True) != binary
        or (manifest is not None and _fingerprint(_manifest_path(identity.path), follow=False) != manifest)
    ):
        forget_process_status(key)
        return None
    return status


def forget_process_status(key: _RequestKey | None = None) -> None:
    """Drop one entry, or every entry when ``key`` is omitted."""

    with _LOCK:
        if key is None:
            _STATUSES.clear()
        else:
            _STATUSES.pop(key, None)
