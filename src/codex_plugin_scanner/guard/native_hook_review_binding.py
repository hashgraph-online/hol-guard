"""Resident projection of the committed hook review binding."""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from pathlib import Path

from .native_execution import _resident_request
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

_FEATURE = "hook-review-binding-v1"
_REQUEST_SCHEMA = "guard-hook-review-binding-request.v1"
_RESULT_SCHEMA = "guard-hook-review-binding-result.v1"
_POLICY_BINDING_SCHEMA = "guard.native-review-policy-binding.v2"


def native_hook_review_binding(
    marker: Mapping[str, object],
    business_identity: bytes,
    cli_revision: object,
    guard_home: Path,
    *,
    deadline: float | None = None,
) -> tuple[object, ...] | None:
    """Validate and project one committed binding through the resident."""

    revision = cli_revision if isinstance(cli_revision, int) and not isinstance(cli_revision, bool) else None
    status = native_runtime_status(deadline_monotonic=deadline)
    if status.identity is None:
        return None
    timeout_seconds = 0.25 if deadline is None else min(0.25, deadline - time.monotonic())
    if timeout_seconds <= 0:
        return None
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"hook-review-binding-{uuid.uuid4().hex}",
        "marker": dict(marker),
        "business_identity_hex": business_identity.hex(),
        "cli_revision": revision,
    }
    try:
        response = _resident_request(
            operation="hook_review_binding",
            request=request,
            guard_home=guard_home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            record_success=False,
            status=status,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    if response is None:
        return None
    result = response.get("result") if isinstance(response, Mapping) else None
    token = result.get("token") if isinstance(result, Mapping) else None
    if (
        not isinstance(result, Mapping)
        or set(result) != {"request_id", "token"}
        or result.get("request_id") != request["request_id"]
        or not isinstance(token, list)
        or len(token) != 8
        or token[6] != business_identity.hex()
        or token[7] != revision
    ):
        native_record_resident_failure(status.identity.sha256, guard_home, reason="native_hook_review_binding_result")
        return None
    try:
        identity = bytes.fromhex(token[6])
    except (TypeError, ValueError):
        native_record_resident_failure(status.identity.sha256, guard_home, reason="native_hook_review_binding_result")
        return None
    native_record_resident_success(status.identity.sha256, guard_home)
    return (*token[:6], identity, token[7])


__all__ = ["native_hook_review_binding"]


def native_hook_review_policy_binding(
    *,
    harness: str,
    native_result: Mapping[str, object],
    verified_receipt: Mapping[str, object] | None,
    guard_home: Path,
    deadline: float | None = None,
) -> dict[str, object] | None:
    """Validate and project a review policy binding through the resident."""

    receipt_bound = isinstance(verified_receipt, Mapping) and "command_extensions" in verified_receipt
    result_bound = "command_extensions" in native_result
    if not result_bound and not receipt_bound:
        return None
    status = native_runtime_status(deadline_monotonic=deadline)
    if status.identity is None:
        return None
    timeout_seconds = 0.25 if deadline is None else min(0.25, deadline - time.monotonic())
    if timeout_seconds <= 0:
        return None
    request_id = f"hook-review-policy-binding-{uuid.uuid4().hex}"
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": request_id,
        "marker": {},
        "business_identity_hex": "",
        "policy_binding": {
            "harness": harness,
            "native_result": dict(native_result),
            "verified_receipt": dict(verified_receipt) if isinstance(verified_receipt, Mapping) else {},
        },
    }
    try:
        response = _resident_request(
            operation="hook_review_binding",
            request=request,
            guard_home=guard_home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            record_success=False,
            status=status,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    if response is None:
        return None
    result = response.get("result") if isinstance(response, Mapping) else None
    binding = result.get("binding") if isinstance(result, Mapping) else None
    if (
        not isinstance(result, Mapping)
        or set(result) != {"request_id", "binding"}
        or result.get("request_id") != request_id
    ):
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_hook_review_policy_binding_result"
        )
        return None
    if binding is None:
        native_record_resident_success(status.identity.sha256, guard_home)
        return None
    if (
        not isinstance(binding, Mapping)
        or set(binding) != {"schema", "rule_digest", "runtime_identity", "command_extensions"}
        or binding.get("schema") != _POLICY_BINDING_SCHEMA
        or not isinstance(binding.get("rule_digest"), str)
        or not isinstance(binding.get("runtime_identity"), str)
        or not isinstance(binding.get("command_extensions"), Mapping)
    ):
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_hook_review_policy_binding_result"
        )
        return None
    native_record_resident_success(status.identity.sha256, guard_home)
    return dict(binding)


__all__.append("native_hook_review_policy_binding")
