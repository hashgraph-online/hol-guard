"""Managed-install gate for hook admission.

A hook that belongs to an app Guard is not protecting is passed through. That
answer is the only one that lowers protection, so it is always read from the
store. The protected answer is remembered briefly: a stale protected answer only
keeps Guard reviewing a hook it would have reviewed a moment earlier, and this
process drops it the moment it changes the managed-install table itself.
"""

from __future__ import annotations

import threading
import time
from functools import lru_cache
from typing import Any

from ..managed_install_revision import current_managed_install_revision

_PROTECTED_ANSWER_TTL_SECONDS = 1.0
_MAX_REMEMBERED_ANSWERS = 256
_lock = threading.Lock()
_protected_until: dict[tuple[str, str], tuple[int, float]] = {}
_refresh_locks: dict[tuple[str, str], threading.Lock] = {}
_REFRESH_WAIT_SECONDS = 0.5


@lru_cache(maxsize=128)
def _canonical_managed_harness_cached(harness: str) -> str:
    try:
        from ..adapters import get_adapter

        return get_adapter(harness).harness
    except (ValueError, ImportError):
        return harness.strip().lower().replace("_", "-")


def _canonical_managed_harness(harness: str) -> str:
    return _canonical_managed_harness_cached(harness)


def _remembered_protected(key: tuple[str, str]) -> bool:
    with _lock:
        remembered = _protected_until.get(key)
    if remembered is None:
        return False
    revision, expires_at = remembered
    return revision == current_managed_install_revision() and time.monotonic() < expires_at


def _remember_protected(key: tuple[str, str], revision: int) -> None:
    with _lock:
        if len(_protected_until) >= _MAX_REMEMBERED_ANSWERS:
            _protected_until.clear()
        _protected_until[key] = (revision, time.monotonic() + _PROTECTED_ANSWER_TTL_SECONDS)


def _refresh_lock_for(key: tuple[str, str]) -> threading.Lock:
    with _lock:
        refresh_lock = _refresh_locks.get(key)
        if refresh_lock is None:
            if len(_refresh_locks) >= _MAX_REMEMBERED_ANSWERS:
                _refresh_locks.clear()
            refresh_lock = _refresh_locks[key] = threading.Lock()
        return refresh_lock


def _hook_harness_is_unmanaged(daemon_server: Any, harness: str) -> bool:
    """True when leftover hooks belong to an app Guard is not currently protecting."""

    store = getattr(daemon_server, "store", None)
    if store is None:
        return False
    getter = getattr(store, "get_managed_install", None)
    if not callable(getter):
        return False
    canonical = _canonical_managed_harness(harness)
    store_path = getattr(store, "path", None)
    key = (str(store_path), canonical) if store_path is not None else None
    if key is None:
        return _read_harness_is_unmanaged(store, getter, canonical, key)
    if _remembered_protected(key):
        return False
    # When the remembered answer expires every concurrent hook misses at once.
    # One of them re-reads the store; the others wait for it and reuse the
    # protected answer it remembers. An unmanaged answer is never remembered, so
    # waiters that do not find one still read the store themselves.
    refresh_lock = _refresh_lock_for(key)
    acquired = refresh_lock.acquire(timeout=_REFRESH_WAIT_SECONDS)
    try:
        if acquired and _remembered_protected(key):
            return False
        return _read_harness_is_unmanaged(store, getter, canonical, key)
    finally:
        if acquired:
            refresh_lock.release()


def _read_harness_is_unmanaged(
    store: Any,
    getter: Any,
    canonical: str,
    key: tuple[str, str] | None,
) -> bool:
    # Read the revision before the store so a concurrent write is never missed.
    revision = current_managed_install_revision()
    try:
        # Reuse setup only for this hook; each read keeps its own transaction.
        with store.connection_scope():
            managed = getter(canonical)
            if isinstance(managed, dict) and managed.get("active") is False:
                return True
            if managed is not None:
                if key is not None:
                    _remember_protected(key, revision)
                return False
            lister = getattr(store, "list_managed_installs", None)
            if not callable(lister):
                return False
            installs = lister()
    except Exception:
        return False
    if not isinstance(installs, list):
        return False
    unmanaged = any(
        isinstance(item, dict)
        and item.get("active") is True
        and _canonical_managed_harness(str(item.get("harness") or "")) != canonical
        for item in installs
    )
    if not unmanaged and key is not None:
        _remember_protected(key, revision)
    return unmanaged
