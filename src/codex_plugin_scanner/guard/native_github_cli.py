"""Resident bridge for the ``github_cli_classify`` op (RTM-032).

The Rust command model owns GitHub CLI capability classification. This module
only frames one request, binds the response by ``request_id`` plus
``request_sha256``, and decodes the assessment. Any transport failure
(resident unavailable, capability absent, timeout, overload, malformed or
mismatched result) yields ``None``; callers must treat ``None`` as an
``unknown`` capability and never recompute a classification in Python.
"""

from __future__ import annotations

import itertools
import json
import time
from dataclasses import dataclass

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, _native_error, native_runtime_status
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
    native_runtime_health_snapshot,
)

_MAX_REQUEST_BYTES = 256 * 1024
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_FEATURE = "github-cli-classify-v1"
_REQUEST_SCHEMA = "guard-github-cli-classify-request.v1"
_RESULT_SCHEMA = "guard-github-cli-classify-result.v1"
_REQUEST_IDS = itertools.count()


@dataclass(frozen=True, slots=True)
class NativeGitHubCliClassification:
    capability: str
    reason_code: str
    detail: str
    capabilities: tuple[str, ...]
    pr_body_file_operand: str | None


def github_cli_classify_native(
    args: tuple[str, ...] | list[str],
    *,
    timeout_seconds: float = 2.0,
    deadline_monotonic: float | None = None,
) -> NativeGitHubCliClassification | None:
    """Classify GitHub CLI arguments in the resident, or return ``None``."""
    effective_deadline = time.monotonic() + timeout_seconds
    if deadline_monotonic is not None:
        effective_deadline = min(effective_deadline, deadline_monotonic)
    if effective_deadline <= time.monotonic():
        return None
    status = native_runtime_status(deadline_monotonic=effective_deadline)
    if (
        status.mode == "off"
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
        or _FEATURE not in status.capabilities.features
    ):
        return None
    guard_home = _resolve_digest_home(None)
    if not ensure_resident_prerequisite(guard_home):
        return None
    if native_runtime_health_snapshot(status.identity.sha256, guard_home).circuit_open:
        return None

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"gh-{next(_REQUEST_IDS)}",
        "args": [str(item) for item in args],
    }
    remaining_seconds = effective_deadline - time.monotonic()
    if remaining_seconds <= 0:
        return None
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
        resident = json.dumps(
            {
                "operation": "github_cli_classify",
                "deadline_budget_ms": max(1, min(9_000, int(remaining_seconds * 1_000))),
                "request": request,
            },
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return None
    if len(resident) > _MAX_REQUEST_BYTES:
        return None

    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=resident,
        deadline_monotonic=effective_deadline,
    )
    identity = status.identity.sha256
    if output is None:
        native_record_resident_failure(identity, guard_home, reason="native_github_cli_classify_unavailable")
        return None
    try:
        envelope = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError):
        native_record_resident_failure(identity, guard_home, reason="native_github_cli_classify_decode_failed")
        return None
    if _native_error(envelope) == "native_overloaded":
        native_record_overload(identity, guard_home)
        return None
    if (
        not isinstance(envelope, dict)
        or envelope.get("schema") != _RESULT_SCHEMA
        or envelope.get("request_id") != request["request_id"]
        or envelope.get("request_sha256") != request_sha256
    ):
        native_record_resident_failure(identity, guard_home, reason="native_github_cli_classify_schema_mismatch")
        return None
    assessment = envelope.get("assessment")
    capabilities = assessment.get("capabilities") if isinstance(assessment, dict) else None
    operand = envelope.get("pr_body_file_operand")
    if (
        envelope.get("status") != "ok"
        or envelope.get("code") != "ok"
        or not isinstance(assessment, dict)
        or not isinstance(assessment.get("capability"), str)
        or not isinstance(assessment.get("reason_code"), str)
        or not isinstance(assessment.get("detail"), str)
        or not isinstance(capabilities, list)
        or not capabilities
        or not all(isinstance(item, str) for item in capabilities)
        or not (operand is None or isinstance(operand, str))
    ):
        native_record_resident_failure(identity, guard_home, reason="native_github_cli_classify_bad_result")
        return None
    native_record_resident_success(identity, guard_home)
    return NativeGitHubCliClassification(
        capability=assessment["capability"],
        reason_code=assessment["reason_code"],
        detail=assessment["detail"],
        capabilities=tuple(capabilities),
        pr_body_file_operand=operand,
    )
