"""Daemon handler request validation answered by the native runtime.

The daemon's HTTP framing and store access stay in Python. Which request
bodies and query strings a handler accepts, the status and body of every
rejection, and the normalized values a handler may act on are decided by the
resident (``daemon_handler``). There is no Python evaluator: a reply that is
not a bound, strictly decoded ``ok`` raises ``NativeDaemonHandlerError`` and
callers fail closed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .native_daemon_route import _decide
from .native_resident_decision import ResidentOperation

DAEMON_HANDLER_FEATURE = "daemon-handler-v1"
_TIMEOUT_SECONDS = 2.0
_OUTCOMES = frozenset({"reject", "proceed"})
# Envelope cap for this operation: the daemon accepts bodies up to 1,000,000
# bytes and ``json.dumps`` escapes non-ASCII text to as much as three times its
# UTF-8 size. It matches the resident's canonical-request bound plus the envelope.
_MAX_REQUEST_BYTES = 4 * 1024 * 1024 + 64 * 1024

_MAX_LIST_ITEMS = 4_096
_TEXT = (str,)
_OPT_TEXT = (str, type(None))
# Exact fields a ``proceed`` answer must carry per query kind, with the types
# each may hold. A bound answer that deviates is unusable and fails closed.
_PROCEED_FIELDS: dict[str, dict[str, tuple[type, ...]]] = {
    "policy_upsert": {
        "harness": _TEXT,
        "scope": _TEXT,
        "action": _TEXT,
        "artifact_id": _OPT_TEXT,
        "workspace": _OPT_TEXT,
        "publisher": _OPT_TEXT,
        "reason": _OPT_TEXT,
    },
    "policy_clear": {
        "harness": _OPT_TEXT,
        "source": _OPT_TEXT,
        "scope": _OPT_TEXT,
        "artifact_id": _OPT_TEXT,
        "artifact_hash": _OPT_TEXT,
        "artifact_id_is_null": (bool,),
        "artifact_hash_is_null": (bool,),
        "workspace": _OPT_TEXT,
        "publisher": _OPT_TEXT,
    },
    "requests_clear": {"status": _TEXT, "harness": _OPT_TEXT},
    "bulk_allow": {"request_ids": (list,)},
    "requests_list": {
        "limit": (int,),
        "status": _OPT_TEXT,
        "include_totals": (bool,),
        "cursor": _OPT_TEXT,
        "harness": _OPT_TEXT,
        "search": _OPT_TEXT,
    },
    "harness_action": {"dry_run": (bool, type(None))},
    "events_cursor": {"cursor": (int,)},
    "headless_state": {
        "app_status": _TEXT,
        "message": _TEXT,
        "outcome": _TEXT,
        "proof_status": _TEXT,
        "retryable": (bool,),
    },
    "detection_statuses": {"app_statuses": (list,)},
}
# Failure-response kinds always answer ``reject``; computed-value kinds never do.
_ALWAYS_REJECT = frozenset({"headless_error", "headless_cursor_surface", "supply_chain_sync_error"})
_NEVER_REJECT = frozenset({"headless_state", "detection_statuses"})

# Request-body keys each body handler reads, in contract order.
_BODY_KEYS: dict[str, tuple[str, ...]] = {
    "policy_upsert": ("harness", "scope", "action", "artifact_id", "workspace", "publisher", "reason"),
    "policy_clear": (
        "harness",
        "source",
        "scope",
        "artifact_id",
        "artifact_hash",
        "workspace",
        "publisher",
        "all",
        "artifact_id_is_null",
        "artifact_hash_is_null",
    ),
    "requests_clear": ("status", "harness"),
    "bulk_allow": ("request_ids",),
}


class NativeDaemonHandlerError(RuntimeError):
    """No authoritative answer; ``code`` says why, for diagnostics only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_OPERATION = ResidentOperation(
    operation="daemon_handler",
    feature=DAEMON_HANDLER_FEATURE,
    prefix="native_daemon_handler",
    request_schema="guard-daemon-handler-request.v1",
    request_id_prefix="daemon-handler",
    result_schema="guard-daemon-handler-result.v1",
    timeout_seconds=_TIMEOUT_SECONDS,
    error=NativeDaemonHandlerError,
)


@dataclass(frozen=True, slots=True)
class HandlerDecision:
    """``reject``: send ``status`` and ``body``. ``proceed``: act on ``fields``."""

    outcome: str
    status: int
    body: dict[str, Any]
    fields: dict[str, Any]

    @property
    def rejected(self) -> bool:
        return self.outcome == "reject"


def _field(value: object) -> dict[str, object]:
    if value is None:
        return {"state": "absent"}
    if isinstance(value, bool):
        return {"state": "bool", "value": value}
    if isinstance(value, str):
        return {"state": "text", "value": value}
    if isinstance(value, list):
        # The resident bounds list size; a longer list is sent by length only and rejected there.
        strings = [item for item in value if isinstance(item, str)] if len(value) <= _MAX_LIST_ITEMS else []
        return {"state": "list", "len": len(value), "strings": strings}
    return {"state": "other"}


def _typed(value: object, allowed: tuple[type, ...]) -> bool:
    if isinstance(value, bool):
        return bool in allowed
    return isinstance(value, allowed)


def _proceed_fields_valid(kind: object, fields: dict[str, Any]) -> bool:
    spec = _PROCEED_FIELDS.get(kind) if isinstance(kind, str) else None
    if spec is None or set(fields) != set(spec):
        return False
    if not all(_typed(fields[key], allowed) for key, allowed in spec.items()):
        return False
    return all(isinstance(item, str) for key in ("request_ids", "app_statuses") for item in fields.get(key, ()))


def _ask(query: dict[str, object], guard_home: Path | None) -> HandlerDecision:
    def validate(payload: dict[str, Any]) -> None:
        status = payload["status"]
        if payload["outcome"] not in _OUTCOMES or not 100 <= status <= 599:
            raise NativeDaemonHandlerError(_OPERATION.invalid)
        kind, outcome = payload["kind"], payload["outcome"]
        if (outcome == "reject" and kind in _NEVER_REJECT) or (outcome == "proceed" and kind in _ALWAYS_REJECT):
            raise NativeDaemonHandlerError(_OPERATION.invalid)
        if outcome == "proceed" and not _proceed_fields_valid(kind, payload["fields"]):
            raise NativeDaemonHandlerError(_OPERATION.invalid)

    answer = _decide(
        query,
        guard_home,
        {"outcome": str, "status": int, "body": dict, "fields": dict},
        validate,
        operation=_OPERATION,
        max_request_bytes=_MAX_REQUEST_BYTES,
    )
    return HandlerDecision(answer["outcome"], answer["status"], answer["body"], answer["fields"])


def native_body_handler(kind: str, payload: Mapping[str, object], *, guard_home: Path | None = None) -> HandlerDecision:
    """Validate a request body for one of the body handlers."""

    query: dict[str, object] = {"kind": kind}
    for key in _BODY_KEYS[kind]:
        query[key] = _field(payload.get(key))
    return _ask(query, guard_home)


def native_requests_list(query_string: str, *, guard_home: Path | None = None) -> HandlerDecision:
    return _ask({"kind": "requests_list", "query": query_string}, guard_home)


def native_events_cursor(query_string: str, *, guard_home: Path | None = None) -> HandlerDecision:
    return _ask({"kind": "events_cursor", "query": query_string}, guard_home)


def native_harness_action(
    action: str,
    payload: Mapping[str, object],
    *,
    guard_home: Path | None = None,
) -> HandlerDecision:
    return _ask(
        {"kind": "harness_action", "action": action, "dry_run": _field(payload.get("dry_run"))},
        guard_home,
    )


def _fact(mapping: object, key: str) -> object:
    return mapping.get(key) if isinstance(mapping, dict) else None


def native_headless_action_error(
    operation: str, error_code: str, *, guard_home: Path | None = None
) -> tuple[int, dict[str, Any]]:
    """The status and body of a failed headless app action."""

    decision = _ask({"kind": "headless_error", "operation": operation, "error_code": error_code}, guard_home)
    return decision.status, decision.body


def native_headless_cursor_surface_error(*, guard_home: Path | None = None) -> tuple[int, dict[str, Any]]:
    decision = _ask({"kind": "headless_cursor_surface"}, guard_home)
    return decision.status, decision.body


def native_headless_action_state(
    harness: str,
    operation: str,
    result: Mapping[str, object],
    *,
    guard_home: Path | None = None,
) -> dict[str, Any]:
    """The app status, message, outcome and proof status of a completed headless app action."""

    managed = result.get("managed_install")
    verification = result.get("verification")
    query: dict[str, object] = {
        "kind": "headless_state",
        "harness": harness,
        "operation": operation,
        "managed_install": {
            "present": isinstance(managed, dict),
            "active_truthy": bool(_fact(managed, "active")),
            "active_is_false": isinstance(managed, dict) and managed.get("active") is False,
        },
        "verification": (
            {
                "installed": bool(verification.get("installed")),
                "command_or_config": bool(verification.get("command_available"))
                or bool(verification.get("config_paths")),
            }
            if isinstance(verification, dict)
            else None
        ),
    }
    return _ask(query, guard_home).fields


def native_detection_app_statuses(values: list[object], *, guard_home: Path | None = None) -> list[str]:
    """The app status for each detected harness status."""

    statuses = _ask({"kind": "detection_statuses", "values": [str(value) for value in values]}, guard_home).fields[
        "app_statuses"
    ]
    if len(statuses) != len(values):
        raise NativeDaemonHandlerError(_OPERATION.invalid)
    return list(statuses)


def native_supply_chain_error(
    operation: str, error: Exception, *, guard_home: Path | None = None
) -> tuple[int, dict[str, Any]]:
    """The status and body of a failed supply-chain package action."""

    from .runtime.runner import (
        GuardSyncAuthorizationExpiredError,
        GuardSyncNotAvailableError,
        GuardSyncNotConfiguredError,
    )

    if isinstance(error, GuardSyncAuthorizationExpiredError):
        kind = "authorization_expired"
    elif isinstance(error, GuardSyncNotConfiguredError):
        kind = "not_configured"
    elif isinstance(error, GuardSyncNotAvailableError):
        kind = "not_available"
    else:
        kind = "other"
    query = {
        "kind": "supply_chain_sync_error",
        "operation": operation,
        "error": kind,
        "message": str(error),
        "retryable": bool(getattr(error, "retryable", False)) if kind == "not_available" else False,
    }
    decision = _ask(query, guard_home)
    return decision.status, decision.body


__all__ = [
    "DAEMON_HANDLER_FEATURE",
    "HandlerDecision",
    "NativeDaemonHandlerError",
    "native_body_handler",
    "native_detection_app_statuses",
    "native_events_cursor",
    "native_harness_action",
    "native_headless_action_error",
    "native_headless_action_state",
    "native_headless_cursor_surface_error",
    "native_requests_list",
    "native_supply_chain_error",
]
