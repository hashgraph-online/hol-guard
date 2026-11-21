"""Which exact Cloud Review operations the command queue advertises."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

from ..native_guard_store import NativeGuardStoreUnavailable

if TYPE_CHECKING:
    from types import ModuleType

    from ..store import GuardStore


def _exact() -> ModuleType:
    # exact_cloud_review re-exports this module's entry point, so import it late.
    from . import exact_cloud_review

    return exact_cloud_review


def exact_cloud_review_operations(store: GuardStore, *, now: str | None = None) -> tuple[str, ...]:
    """The exact operations to advertise; none while the consent rows cannot be read."""

    try:
        return _advertised_operations(store, now=now)
    except NativeGuardStoreUnavailable:
        return ()


def _revoked_or_unreadable(store: GuardStore) -> bool:
    """Whether consent is revoked or its rows cannot be read; either way nothing is advertised."""

    _ecr = _exact()
    try:
        return _ecr._consent_row(store, "revocation") is not None
    except sqlite3.Error:
        return True


def _advertised_operations(store: GuardStore, *, now: str | None) -> tuple[str, ...]:
    _ecr = _exact()
    if _revoked_or_unreadable(store):
        return ()
    try:
        _ecr._verified_capability(store, now=now)
        return (_ecr.EXACT_CLOUD_REVIEW_OPERATION,)
    except sqlite3.Error:
        # NativeGuardStoreUnavailable is a sqlite3.Error too; never advertise
        # without a readable consent pair.
        return ()
    except (AttributeError, _ecr.ExactCloudReviewError):
        pass
    if _revoked_or_unreadable(store):
        return ()
    try:
        _ = _ecr._oauth_metadata(store)
    except (AttributeError, _ecr.ExactCloudReviewError):
        return ()
    return (_ecr.EXACT_CLOUD_REVIEW_OPERATION,)
