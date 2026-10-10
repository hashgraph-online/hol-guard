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
        return {"state": "list", "len": len(value), "strings": [item for item in value if isinstance(item, str)]}
    return {"state": "other"}


def _ask(query: dict[str, object], guard_home: Path | None) -> HandlerDecision:
    def validate(payload: dict[str, Any]) -> None:
        status = payload["status"]
        if payload["outcome"] not in _OUTCOMES or not 100 <= status <= 599:
            raise NativeDaemonHandlerError(_OPERATION.invalid)

    answer = _decide(
        query,
        guard_home,
        {"outcome": str, "status": int, "body": dict, "fields": dict},
        validate,
        operation=_OPERATION,
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


__all__ = [
    "DAEMON_HANDLER_FEATURE",
    "HandlerDecision",
    "NativeDaemonHandlerError",
    "native_body_handler",
    "native_events_cursor",
    "native_harness_action",
    "native_requests_list",
]
