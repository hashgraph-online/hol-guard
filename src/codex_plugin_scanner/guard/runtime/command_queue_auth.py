"""OAuth identity resolution for the Guard Cloud command worker."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import urllib.error
from collections.abc import Callable, Mapping

from ..store import GuardStore
from .runner import (
    GuardSyncAuthorizationExpiredError,
    GuardSyncNotConfiguredError,
    _resolve_guard_sync_auth_context,
    repair_guard_cloud_connect_storage,
)

_LOGGER = logging.getLogger(__name__)


def _redacted_error(error: BaseException) -> str:
    if isinstance(error, urllib.error.HTTPError):
        return f"HTTP Error {error.code}: {error.reason}"
    return type(error).__name__


def _repair_guard_cloud_authorization(
    store: GuardStore,
    repair_authorization: Callable[[GuardStore], Mapping[str, object]],
) -> dict[str, bool]:
    try:
        result = repair_authorization(store)
    except Exception as error:
        _LOGGER.warning("Guard command authorization repair failed: %s", _redacted_error(error))
        return {"cleared_stale_sign_in": False, "existing_sign_in_valid": False, "repaired_storage": False}
    return {
        "cleared_stale_sign_in": bool(result.get("cleared_stale_sign_in")),
        "existing_sign_in_valid": bool(result.get("existing_sign_in_valid")),
        "repaired_storage": bool(result.get("repaired_storage")),
    }


def resolve_command_queue_auth_context(
    store: GuardStore,
    *,
    force_refresh: bool = False,
    resolve_auth_context: Callable[..., dict[str, object]] = _resolve_guard_sync_auth_context,
    repair_authorization: Callable[[GuardStore], Mapping[str, object]] = repair_guard_cloud_connect_storage,
) -> dict[str, object]:
    try:
        if force_refresh:
            return resolve_auth_context(store, force_refresh=True)
        return resolve_auth_context(store)
    except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError):
        repair = _repair_guard_cloud_authorization(store, repair_authorization)
        if not repair["existing_sign_in_valid"] and not repair["repaired_storage"]:
            raise
        if force_refresh:
            return resolve_auth_context(store, force_refresh=True)
        return resolve_auth_context(store)


__all__ = ["resolve_command_queue_auth_context"]


# Every poll resolves the Cloud sign-in before and after its lease, and each
# resolve takes the OAuth refresh file lock. Drain workers settling a bulk
# Review decision queued behind one another on that lock. A resolved context
# is reused for a few seconds, well inside the margin in which the resolver
# itself keeps reusing an access token, so a reused token is never one the
# resolver would have refreshed. A 401 still forces a fresh resolve.
#
# A context is reused only while the stored sign-in it came from is unchanged.
# Connecting, reconnecting or signing out rewrites that record, from this
# process or another one, so the next poll resolves the new sign-in at once.
_AUTH_CONTEXT_REUSE_SECONDS = 15.0
_auth_context_lock = threading.Lock()
_auth_context_cache: dict[tuple[str, object], tuple[float, str, dict[str, object]]] = {}


def _sign_in_stamp(store: GuardStore) -> str | None:
    """A digest of the stored sign-in record, or None when it cannot be read."""

    state_key = getattr(store, "_oauth_local_credentials_state_key", None)
    if not isinstance(state_key, str):
        return None
    try:
        record = store.get_sync_payload(state_key)
    except Exception:
        return None
    if record is None:
        return None
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def reuse_command_queue_auth_context(
    store: GuardStore,
    *,
    force_refresh: bool = False,
    resolve_auth_context: Callable[..., dict[str, object]] = _resolve_guard_sync_auth_context,
    repair_authorization: Callable[[GuardStore], Mapping[str, object]] = repair_guard_cloud_connect_storage,
) -> dict[str, object]:
    key = (str(getattr(store, "guard_home", id(store))), resolve_auth_context)
    with _auth_context_lock:
        stamp = _sign_in_stamp(store)
        cached = None if force_refresh else _auth_context_cache.get(key)
        if (
            cached is not None
            and stamp is not None
            and cached[1] == stamp
            and time.monotonic() - cached[0] < _AUTH_CONTEXT_REUSE_SECONDS
        ):
            return dict(cached[2])
        _auth_context_cache.pop(key, None)
        resolved_at = time.monotonic()
        auth_context = resolve_command_queue_auth_context(
            store,
            force_refresh=force_refresh,
            resolve_auth_context=resolve_auth_context,
            repair_authorization=repair_authorization,
        )
        # Resolving can refresh and rewrite the record, so the stamp kept is
        # the one the resolved context belongs to.
        stamp = _sign_in_stamp(store)
        if stamp is not None:
            if len(_auth_context_cache) >= 8:
                _auth_context_cache.clear()
            _auth_context_cache[key] = (resolved_at, stamp, auth_context)
        return dict(auth_context)


def clear_command_queue_auth_context_cache() -> None:
    with _auth_context_lock:
        _auth_context_cache.clear()
