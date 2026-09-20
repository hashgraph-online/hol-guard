"""Classify policy-activation failures without claiming application."""

from __future__ import annotations

import errno
import json
import sqlite3
from collections.abc import Mapping
from typing import Final

STORAGE_FAILURE: Final = "storage"
TRANSPORT_FAILURE: Final = "transport"
PRECOMMIT_FAILURE: Final = "precommit"
POSTCOMMIT_FAILURE: Final = "postcommit"

_STORAGE_REASONS: Final = frozenset(
    {
        "policy_activation_disk_full",
        "policy_activation_sqlite_locked",
        "policy_activation_sqlite_failed",
        "policy_activation_storage_failed",
        "policy_activation_payload_unencodable",
        "policy_bundle_activation_payload_unencodable",
    }
)
_TRANSPORT_REASON: Final = "policy_activation_transport_failed"


def classify_policy_activation_failure(
    error: BaseException,
    *,
    boundary: str = PRECOMMIT_FAILURE,
) -> dict[str, object]:
    """Return fixed support codes; exception text never becomes display data."""

    kind = STORAGE_FAILURE
    reason = "policy_activation_storage_failed"
    if isinstance(error, (json.JSONDecodeError, TypeError, ValueError)) and not isinstance(error, sqlite3.Error):
        reason = "policy_activation_payload_unencodable"
    elif isinstance(error, sqlite3.OperationalError):
        message = str(error).lower()
        code = getattr(error, "sqlite_errorcode", None)
        base_code = code & 0xFF if isinstance(code, int) else None
        if base_code == getattr(sqlite3, "SQLITE_FULL", 13) or any(
            value in message for value in ("disk is full", "database or disk is full", "no space left")
        ):
            reason = "policy_activation_disk_full"
        elif base_code in {getattr(sqlite3, "SQLITE_BUSY", 5), getattr(sqlite3, "SQLITE_LOCKED", 6)} or any(
            value in message
            for value in ("database is locked", "database table is locked", "database schema is locked")
        ):
            reason = "policy_activation_sqlite_locked"
        else:
            reason = "policy_activation_sqlite_failed"
    elif isinstance(error, sqlite3.Error):
        reason = "policy_activation_sqlite_failed"
    elif isinstance(error, (TimeoutError, ConnectionError)):
        kind = TRANSPORT_FAILURE
        reason = _TRANSPORT_REASON
    elif isinstance(error, OSError):
        if error.errno in {errno.ENOSPC, errno.EDQUOT}:
            reason = "policy_activation_disk_full"
    elif not isinstance(error, MemoryError):
        kind = "activation"
        reason = "policy_activation_failed"
    return {
        "applied": False,
        "boundary": boundary if boundary in {PRECOMMIT_FAILURE, POSTCOMMIT_FAILURE} else PRECOMMIT_FAILURE,
        "failure_kind": kind,
        "reason": reason,
        "retryable": kind in {STORAGE_FAILURE, TRANSPORT_FAILURE} and reason != "policy_activation_payload_unencodable",
    }


class PolicyActivationPersistenceError(RuntimeError):
    """A failure record could not be persisted; retain its safe classification."""

    def __init__(self, error: BaseException) -> None:
        self.status = classify_policy_activation_failure(error)
        super().__init__(str(self.status["reason"]))


def activation_status_from_store(store: object) -> dict[str, object]:
    """Report durable recovery evidence without asserting native application."""

    get_sync = getattr(store, "get_sync_payload", None)
    try:
        last_error = get_sync("policy_bundle_last_error") if callable(get_sync) else None
        last_good = get_sync("policy_bundle_last_good") if callable(get_sync) else None
    except (sqlite3.Error, OSError, MemoryError) as error:
        status = classify_policy_activation_failure(error)
        return {
            "applied": False,
            "last_good_present": False,
            "storage_failure": status["failure_kind"] == STORAGE_FAILURE,
            "transport_failure": status["failure_kind"] == TRANSPORT_FAILURE,
            "reason": status["reason"],
        }
    error_payload = last_error if isinstance(last_error, Mapping) else {}
    raw_reason = error_payload.get("reason")
    reason = raw_reason if isinstance(raw_reason, str) and raw_reason else None
    if reason is not None and reason not in _STORAGE_REASONS | {_TRANSPORT_REASON}:
        reason = "policy_activation_rejected"
    return {
        "applied": False,
        "last_good_present": isinstance(last_good, Mapping) and bool(last_good),
        "storage_failure": reason in _STORAGE_REASONS,
        "transport_failure": reason == _TRANSPORT_REASON,
        "reason": reason,
    }


__all__ = [
    "POSTCOMMIT_FAILURE",
    "PRECOMMIT_FAILURE",
    "STORAGE_FAILURE",
    "TRANSPORT_FAILURE",
    "PolicyActivationPersistenceError",
    "activation_status_from_store",
    "classify_policy_activation_failure",
]
