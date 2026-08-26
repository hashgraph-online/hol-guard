"""OAuth identity resolution for the Guard Cloud command worker."""

from __future__ import annotations

import logging
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
