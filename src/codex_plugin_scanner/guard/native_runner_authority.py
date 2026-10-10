"""Typed client for the native ``guard run`` authority owner; no Python verdicts.

Rust owns the authority transforms of the guard-run flow: composing runtime
detector authority, binding it into per-artifact decisions, recording terminal
approval-claim failures, classifying saved claims, trusted request overrides,
the pre/post-claim launch-authority signature, the final authority gate and the
policy-shadow comparison. Python ships typed inputs, binds each answer to its
request by ``request_id`` and canonical ``request_sha256``, and merges the
returned patch. Any transport, scope or binding failure raises
``NativeRunnerAuthorityError`` (a ``ValueError``); callers treat it as a refusal
to launch. Nothing here ever computes an action, reason or signature locally.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .native_context import (
    _COLD_START_ALLOWANCE_SECONDS,
    _canonical_request_sha256,
    _native_error,
    _native_runtime_status_memo,
    _resolve_digest_home,
    ensure_resident_prerequisite,
)
from .native_resident_client import native_resident_client_ready, native_resident_client_request
from .native_runtime import _isolated_environment
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)

_FEATURE = "runner-authority-v1"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_REQUEST_SCHEMA = "guard-runner-authority-request.v1"
_RESULT_SCHEMA = "guard-runner-authority-result.v1"
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
# The authority answer gates a launch, so a slow resident fails closed rather
# than degrading; the budget is generous but bounded below the resident cap.
_TIMEOUT_SECONDS = 5.0
_MAX_DEADLINE_BUDGET_MS = 9_000
_INVALID_RESULT = "native_runner_authority_result_invalid"


class NativeRunnerAuthorityError(ValueError):
    """The native owner could not supply a bound, typed runner-authority answer."""


def _fail(status: Any, guard_home: Path, code: str) -> NativeRunnerAuthorityError:
    native_record_resident_failure(status.identity.sha256, guard_home, reason=code)
    return NativeRunnerAuthorityError(code)


def native_runner_authority(kind: str, args: Mapping[str, Any], guard_home: Path | None = None) -> dict[str, Any]:
    """Run one authority ``kind`` in the resident and return its bound payload."""

    guard_home = _resolve_digest_home(guard_home)
    request: dict[str, Any] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": uuid.uuid4().hex,
        "guard_home": str(guard_home),
        "kind": kind,
        "args": dict(args),
    }
    status = _native_runtime_status_memo()
    if (
        status.mode == "off"
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _FEATURE not in status.capabilities.features
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
    ):
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")
    try:
        prerequisite = ensure_resident_prerequisite(guard_home)
    except Exception as error:
        raise NativeRunnerAuthorityError("native_runner_authority_prerequisite_unavailable") from error
    if not prerequisite:
        raise NativeRunnerAuthorityError("native_runner_authority_prerequisite_unavailable")
    try:
        request_sha256 = _canonical_request_sha256(request)
        budget_seconds = _TIMEOUT_SECONDS
        if not native_resident_client_ready(status.identity.path, guard_home):
            budget_seconds += _COLD_START_ALLOWANCE_SECONDS
        deadline_budget_ms = max(1, min(_MAX_DEADLINE_BUDGET_MS, int(budget_seconds * 1_000)))
        envelope = json.dumps(
            {"operation": "runner_authority", "deadline_budget_ms": deadline_budget_ms, "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeRunnerAuthorityError("native_runner_authority_component_unencodable") from error
    if len(envelope) > _MAX_REQUEST_BYTES:
        raise NativeRunnerAuthorityError("native_runner_authority_request_too_large")
    try:
        output = native_resident_client_request(
            executable=status.identity.path,
            guard_home=guard_home,
            environment=_isolated_environment(),
            payload=envelope,
            deadline_monotonic=time.monotonic() + deadline_budget_ms / 1_000,
        )
    except Exception:
        output = None
    if output is None:
        raise _fail(status, guard_home, "native_runner_authority_resident_unavailable")
    try:
        payload = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _fail(status, guard_home, _INVALID_RESULT) from error
    error_code = _native_error(payload)
    if error_code is not None:
        if error_code == "native_overloaded":
            native_record_overload(status.identity.sha256, guard_home)
            raise NativeRunnerAuthorityError(error_code)
        raise _fail(status, guard_home, error_code)
    bound = (
        isinstance(payload, dict)
        and payload.get("schema") == _RESULT_SCHEMA
        and payload.get("request_id") == request["request_id"]
        and payload.get("request_sha256") == request_sha256
    )
    if not bound or not isinstance(payload, dict):
        raise _fail(status, guard_home, _INVALID_RESULT)
    code = payload.get("code")
    if payload.get("status") == "error" and isinstance(code, str) and code.startswith("native_runner_authority_"):
        # A bound refusal is the resident answering, not an outage: the request
        # is refused (callers fail closed) but the resident stays healthy, so a
        # bad request can never open the shared availability circuit.
        native_record_resident_success(status.identity.sha256, guard_home)
        raise NativeRunnerAuthorityError(code)
    if payload.get("status") != "ok" or code != "ok" or not isinstance(payload.get("payload"), dict):
        raise _fail(status, guard_home, _INVALID_RESULT)
    native_record_resident_success(status.identity.sha256, guard_home)
    return payload["payload"]
