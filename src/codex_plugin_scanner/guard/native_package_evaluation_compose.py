"""Resident bridge for the ``package_evaluation_compose`` op.

The resident owns every package-verdict rewrite (current-policy rewrite,
rejected saved-approval reuse, saved allow/block overrides, external-archive
binding blocks). The caller sends the evaluation fields a rewrite reads plus
kind-specific facts and gets back a patch it applies mechanically. A missing,
mismatched, or malformed native answer raises
:class:`NativePackageEvaluationComposeError`; there is no Python fallback and
no preserved-evaluation fallback, so an unavailable resident can never leave a
weaker verdict in place.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_package_authority import _REQUEST_SCHEMA, _RESULT_SCHEMA, _request_id, _resident_request

_COMPOSE_FEATURE = "package-evaluation-compose-v1"
_PATCH_KEYS = frozenset(
    {"decision", "policy_action", "reasons", "packages", "risk_summary", "user_copy", "record_monitor_evidence"}
)
_USER_COPY_KEYS = frozenset({"title", "summary", "next_step", "dashboard_url", "harness_message"})


class NativePackageEvaluationComposeError(RuntimeError):
    """No authoritative native composition result was available."""


def _dict_list(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise NativePackageEvaluationComposeError("Native package composition patch invalid")
    return [dict(item) for item in value]


def compose_package_evaluation_patch(
    kind: str,
    evaluation: Any,
    **facts: object,
) -> dict[str, Any]:
    """Return the native patch for ``kind`` applied to ``evaluation``'s verdict."""

    guard_home = _resolve_digest_home(None)
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": _request_id(),
        "guard_home": str(guard_home),
        "kind": kind,
        "evaluation": {
            "policy_action": evaluation.policy_action,
            "reasons": [dict(item) for item in evaluation.reasons],
            "packages": [dict(item) for item in evaluation.packages],
        },
        **{key: value for key, value in facts.items() if value is not None},
    }
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError) as error:
        raise NativePackageEvaluationComposeError("Native package composition request invalid") from error
    if not ensure_resident_prerequisite(guard_home):
        raise NativePackageEvaluationComposeError("Native package composition unavailable")
    response = _resident_request(
        operation="package_evaluation_compose",
        request=request,
        guard_home=guard_home,
        timeout_seconds=2.0,
        required_features=(_COMPOSE_FEATURE,),
    )
    if (
        not isinstance(response, dict)
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != request_sha256
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        raise NativePackageEvaluationComposeError("Native package composition unavailable or invalid")
    payload = response.get("payload")
    patch = payload.get("patch") if isinstance(payload, dict) else None
    if not isinstance(patch, dict) or not set(patch) <= _PATCH_KEYS:
        raise NativePackageEvaluationComposeError("Native package composition patch invalid")
    return patch


def compose_package_evaluation(kind: str, evaluation: Any, **facts: object) -> Any:
    """Apply the native verdict patch to ``evaluation`` without recomputing it."""

    patch = compose_package_evaluation_patch(kind, evaluation, **facts)
    changes: dict[str, Any] = {}
    for key in ("decision", "policy_action", "risk_summary"):
        if key in patch:
            if not isinstance(patch[key], str):
                raise NativePackageEvaluationComposeError("Native package composition patch invalid")
            changes[key] = patch[key]
    if "record_monitor_evidence" in patch:
        if not isinstance(patch["record_monitor_evidence"], bool):
            raise NativePackageEvaluationComposeError("Native package composition patch invalid")
        changes["record_monitor_evidence"] = patch["record_monitor_evidence"]
    for key in ("reasons", "packages"):
        if key in patch:
            changes[key] = tuple(_dict_list(patch[key]))
    if "user_copy" in patch:
        copy = patch["user_copy"]
        if not isinstance(copy, Mapping) or set(copy) != _USER_COPY_KEYS:
            raise NativePackageEvaluationComposeError("Native package composition patch invalid")
        user_copy_type = type(evaluation.user_copy)
        changes["user_copy"] = user_copy_type(**{key: copy[key] for key in _USER_COPY_KEYS})
    return replace(evaluation, **changes)
