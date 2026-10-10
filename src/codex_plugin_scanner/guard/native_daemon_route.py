"""Daemon route, origin and session policy answered by the native runtime.

The daemon's HTTP framing, token verification and response rendering stay in
Python. Which routes need a header token, which a dashboard session may reach,
whether an ``Origin`` may call a path, whether verified session claims
authorize a request, and how an approval-resolution body is validated are
decided by the resident (``daemon_route``). There is no Python evaluator: a
reply that is not a bound, strictly decoded ``ok`` raises
``NativeDaemonRouteError`` and callers fail closed.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

DAEMON_ROUTE_FEATURE = "daemon-route-v1"
_REQUEST_SCHEMA = "guard-daemon-route-request.v1"
_RESULT_SCHEMA = "guard-daemon-route-result.v1"
_RESIDENT_CODE = re.compile(r"^native_daemon_route_[a-z_]{1,64}$")
_UNAVAILABLE = "native_daemon_route_unavailable"
_INVALID = "native_daemon_route_payload_invalid"
_TIMEOUT_SECONDS = 2.0
_CACHE_SIZE = 1024
_ROUTE_CLASSES = frozenset({"extension_control", "local_cli", "none"})
_RESOLVE_OUTCOMES = frozenset(
    {
        "not_matched",
        "missing_required_fields",
        "invalid_scope_contract_version",
        "invalid_scope_contract_digest",
        "resolved",
    }
)
_OPT_STR = (str, type(None))

_CLAIM_KEYS: dict[str, str] = {
    "surface": "surface",
    "action_path": "action_path",
    "harness": "harness",
    "nonce": "nonce",
    "workspace_id": "workspace_id",
    "workspace_id_camel": "workspaceId",
    "location_id": "location_id",
    "location_id_camel": "locationId",
    "daemon_origin": "daemon_origin",
    "daemon_origin_camel": "daemonOrigin",
}
_PAYLOAD_KEYS: dict[str, str] = {
    "harness": "harness",
    "workspace_id": "workspace_id",
    "workspace_id_camel": "workspaceId",
    "location_id": "location_id",
    "location_id_camel": "locationId",
    "daemon_origin": "daemon_origin",
    "daemon_origin_camel": "daemonOrigin",
    "dashboard_session_nonce": "dashboard_session_nonce",
}


class NativeDaemonRouteError(RuntimeError):
    """No authoritative answer; ``code`` says why, for diagnostics only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class RouteFacts:
    requires_header_token: bool
    session_path: bool
    route_class: str


@dataclass(frozen=True, slots=True)
class OriginDecision:
    allowed: bool
    hosted_origin: bool


@dataclass(frozen=True, slots=True)
class SessionVerdict:
    allowed: bool
    consume_nonce: str | None


@dataclass(frozen=True, slots=True)
class ResolveOutcome:
    outcome: str
    request_id: str | None
    action: str | None
    scope: str | None
    scope_contract_version: str | None
    scope_contract_digest: str | None


def _text(value: object) -> str | None:
    return value.strip() or None if isinstance(value, str) else None


def _text_field(value: object) -> dict[str, str]:
    if value is None:
        return {"state": "absent"}
    if isinstance(value, str):
        return {"state": "text", "value": value.strip()}
    return {"state": "invalid"}


def _list_field(value: object) -> dict[str, object]:
    if value is None:
        return {"state": "absent"}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return {"state": "strings", "values": list(value)}
    return {"state": "invalid"}


def _strings(value: object) -> list[str] | None:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else None


def _shape(value: object, fields: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise NativeDaemonRouteError(_INVALID)
    for key, kinds in fields.items():
        item = value[key]
        allowed = kinds if isinstance(kinds, tuple) else (kinds,)
        if isinstance(item, bool) and bool not in allowed:
            raise NativeDaemonRouteError(_INVALID)
        if not isinstance(item, allowed):
            raise NativeDaemonRouteError(_INVALID)
    return value


def _record_resident(guard_home: Path, *, success: bool, reason: str = "") -> None:
    status = native_runtime_status()
    if status.identity is None:
        return
    if success:
        native_record_resident_success(status.identity.sha256, guard_home)
    else:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=reason)


def _decide(
    query: Mapping[str, object],
    guard_home: Path | None,
    fields: Mapping[str, Any],
    validate: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Ask the resident and return its payload once it is bound and strictly shaped.

    Resident health is recorded only after binding and validation, so a
    resident that keeps sending well-bound but malformed payloads opens the
    circuit instead of resetting the failure streak on every reply.
    """

    try:
        home = _resolve_digest_home(guard_home)
    except (OSError, RuntimeError, ValueError):
        raise NativeDaemonRouteError("native_daemon_route_home_unbound") from None
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"daemon-route-{uuid4().hex}",
        "query": dict(query),
    }
    try:
        if not ensure_resident_prerequisite(home):
            raise NativeDaemonRouteError(_UNAVAILABLE)
        digest = "sha256:" + _canonical_request_sha256(request)
    except (OSError, TypeError, ValueError):
        raise NativeDaemonRouteError("native_daemon_route_request_invalid") from None
    response = _resident_request(
        operation="daemon_route",
        request=request,
        guard_home=home,
        timeout_seconds=_TIMEOUT_SECONDS,
        required_feature=DAEMON_ROUTE_FEATURE,
        response_schema=_RESULT_SCHEMA,
        record_success=False,
    )
    if response is None:
        raise NativeDaemonRouteError(_UNAVAILABLE)
    if (
        response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        _record_resident(home, success=False, reason="native_daemon_route_unbound")
        raise NativeDaemonRouteError(_UNAVAILABLE)
    status, code = response.get("status"), response.get("code")
    if status == "error":
        _record_resident(home, success=True)
        raise NativeDaemonRouteError(code if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code) else _UNAVAILABLE)
    payload = response.get("payload")
    if status != "ok" or code != "ok" or not isinstance(payload, dict) or payload.get("kind") != query.get("kind"):
        _record_resident(home, success=False, reason="native_daemon_route_bad_status")
        raise NativeDaemonRouteError(_UNAVAILABLE)
    try:
        _shape(payload, {"kind": str, **fields})
        if validate is not None:
            validate(payload)
    except NativeDaemonRouteError:
        _record_resident(home, success=False, reason="native_daemon_route_invalid")
        raise
    _record_resident(home, success=True)
    return payload


@lru_cache(maxsize=_CACHE_SIZE)
def _route_facts(method: str, path: str, home: Path | None) -> RouteFacts:
    def validate(payload: dict[str, Any]) -> None:
        if payload["route_class"] not in _ROUTE_CLASSES:
            raise NativeDaemonRouteError(_INVALID)

    payload = _decide(
        {"kind": "route", "method": method, "path": path},
        home,
        {"requires_header_token": bool, "session_path": bool, "route_class": str},
        validate,
    )
    return RouteFacts(payload["requires_header_token"], payload["session_path"], payload["route_class"])


def native_route_facts(method: str, path: str, *, guard_home: Path | None = None) -> RouteFacts:
    """Route facts for one method and URL path; identical answers are memoized."""

    return _route_facts(method, path, guard_home)


@lru_cache(maxsize=_CACHE_SIZE)
def _origin_decision(origin: str, path: str, home: Path | None) -> OriginDecision:
    payload = _decide(
        {"kind": "origin", "origin": origin, "path": path},
        home,
        {"allowed": bool, "hosted_origin": bool},
    )
    return OriginDecision(payload["allowed"], payload["hosted_origin"])


def native_origin_decision(origin: str, path: str, *, guard_home: Path | None = None) -> OriginDecision:
    """Whether a normalized ``Origin`` may call ``path``, and whether it is a hosted origin."""

    return _origin_decision(origin, path, guard_home)


def native_strict_loopback_origin(
    raw: str,
    normalized: str | None,
    *,
    guard_home: Path | None = None,
) -> str | None:
    payload = _decide(
        {"kind": "strict_loopback", "raw": raw, "normalized": normalized},
        guard_home,
        {"origin": _OPT_STR},
    )
    return payload["origin"]


def native_session_authorize(
    *,
    method: str,
    path: str,
    claims: Mapping[str, object],
    payload: Mapping[str, object] | None,
    header_nonce: object,
    request_origin: str | None,
    guard_home: Path | None = None,
) -> SessionVerdict:
    """Whether verified session claims authorize a request.

    The claims are the signature-checked token payload; ``payload`` is the
    parsed request body (``None`` for a bodyless request).
    """

    claim_fields: dict[str, object] = {name: _text(claims.get(key)) for name, key in _CLAIM_KEYS.items()}
    claim_fields["allowed_read_paths"] = _strings(claims.get("allowed_read_paths"))
    claim_fields["allowed_action_paths"] = _strings(claims.get("allowed_action_paths"))
    claim_fields["managers"] = _strings(claims.get("managers"))
    body: dict[str, object] | None = None
    if payload is not None:
        body = {name: _text(payload.get(key)) for name, key in _PAYLOAD_KEYS.items()}
        body["managers"] = _list_field(payload.get("managers"))
    answer = _decide(
        {
            "kind": "session_authorize",
            "method": method,
            "path": path,
            "claims": claim_fields,
            "payload": body,
            "header_nonce": _text(header_nonce),
            "request_origin": request_origin,
        },
        guard_home,
        {"allowed": bool, "consume_nonce": _OPT_STR},
    )
    return SessionVerdict(answer["allowed"], answer["consume_nonce"])


def native_resolve_request(
    path: str,
    payload: Mapping[str, object],
    *,
    guard_home: Path | None = None,
) -> ResolveOutcome:
    """Match an approval-resolution route and validate its scope fields."""

    def validate(answer: dict[str, Any]) -> None:
        if answer["outcome"] not in _RESOLVE_OUTCOMES:
            raise NativeDaemonRouteError(_INVALID)

    answer = _decide(
        {
            "kind": "resolve_request",
            "path": path,
            "action": _text_field(payload.get("action")),
            "scope": _text_field(payload.get("scope")),
            "scope_contract_version": _text_field(payload.get("scope_contract_version")),
            "scope_contract_digest": _text_field(payload.get("scope_contract_digest")),
        },
        guard_home,
        {
            "outcome": str,
            "request_id": _OPT_STR,
            "action": _OPT_STR,
            "scope": _OPT_STR,
            "scope_contract_version": _OPT_STR,
            "scope_contract_digest": _OPT_STR,
        },
        validate,
    )
    return ResolveOutcome(
        answer["outcome"],
        answer["request_id"],
        answer["action"],
        answer["scope"],
        answer["scope_contract_version"],
        answer["scope_contract_digest"],
    )


__all__ = [
    "DAEMON_ROUTE_FEATURE",
    "NativeDaemonRouteError",
    "OriginDecision",
    "ResolveOutcome",
    "RouteFacts",
    "SessionVerdict",
    "native_origin_decision",
    "native_resolve_request",
    "native_route_facts",
    "native_session_authorize",
    "native_strict_loopback_origin",
]
