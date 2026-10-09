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
_GUARD_ACTIONS = frozenset({"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"})
_PACKAGE_DECISIONS = frozenset({"allow", "warn", "ask", "block"})
_VERDICT_KEYS = frozenset({"decision", "risk_summary", "user_copy", "record_monitor_evidence"})
_BLOCK_VARIANTS = frozenset({"launch_unbound", "mcp_unbound", "binding_unavailable"})


class NativePackageEvaluationComposeError(RuntimeError):
    """No authoritative native composition result was available."""


def _dict_list(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise NativePackageEvaluationComposeError("Native package composition patch invalid")
    return [dict(item) for item in value]


def _expected_policy_action(kind: str, facts: Mapping[str, object]) -> str | None:
    """The action the reply must leave in force; echoes the request, never computes a verdict."""

    if kind == "current_policy_action":
        action = facts.get("current_action")
        return action if isinstance(action, str) else None
    if kind == "rejected_reuse":
        reuse = facts.get("approval_reuse")
        action = reuse.get("action") if isinstance(reuse, Mapping) else None
        return action if isinstance(action, str) else None
    if kind == "saved_allow":
        return "allow"
    if kind == "saved_block":
        return "block"
    if kind == "external_archive_override":
        variant = facts.get("variant")
        if variant in _BLOCK_VARIANTS:
            return "block"
        return "allow" if variant == "shim_delegated" else None
    return None


def _invalid() -> NativePackageEvaluationComposeError:
    return NativePackageEvaluationComposeError("Native package composition patch invalid")


def _validate_patch(kind: str, evaluation: Any, patch: Mapping[str, Any], facts: Mapping[str, object]) -> None:
    """Reject empty, partial, or out-of-vocabulary replies for ``kind``."""

    if not set(patch) <= _PATCH_KEYS:
        raise _invalid()
    expected = _expected_policy_action(kind, facts)
    if expected is None or expected not in _GUARD_ACTIONS:
        raise _invalid()
    effective = patch.get("policy_action", evaluation.policy_action)
    if effective not in _GUARD_ACTIONS or effective != expected:
        raise _invalid()
    if "decision" in patch and patch["decision"] not in _PACKAGE_DECISIONS:
        raise _invalid()
    if kind == "rejected_reuse" and evaluation.policy_action == expected:
        # Same action: only the reason list is rewritten.
        if not set(patch) <= {"reasons"}:
            raise _invalid()
        return
    if kind == "current_policy_action" and evaluation.policy_action == expected:
        raise _invalid()  # callers skip identity rewrites; an empty reply cannot be trusted
    if not set(patch) >= _VERDICT_KEYS:
        raise _invalid()
    copy = patch["user_copy"]
    if not isinstance(copy, Mapping) or set(copy) != _USER_COPY_KEYS:
        raise _invalid()
    for key, value in copy.items():
        if not (isinstance(value, str) or (value is None and key in {"next_step", "dashboard_url"})):
            raise _invalid()
    if not isinstance(copy["title"], str) or not isinstance(copy["summary"], str):
        raise _invalid()


def native_unavailable_block_evaluation(evaluation: Any) -> Any:
    """Terminal fail-closed block used when the resident cannot answer.

    This is a constant block, not a verdict computation: it can only tighten
    an evaluation and never allows anything.
    """

    message = "HOL Guard blocked this package request because its native policy engine was unavailable."
    reason = {
        "code": "native_package_evaluation_unavailable",
        "message": message,
        "severity": "high",
        "source": "guard-local",
    }
    copy_type = type(evaluation.user_copy)
    return replace(
        evaluation,
        decision="block",
        policy_action="block",
        reasons=(reason, *(dict(item) for item in evaluation.reasons)),
        packages=tuple({**dict(item), "decision": "block"} for item in evaluation.packages),
        risk_summary=message,
        user_copy=copy_type(
            title="Package request blocked",
            summary=message,
            next_step="Restart HOL Guard or run `hol-guard doctor`, then retry.",
            dashboard_url=None,
            harness_message=message,
        ),
        record_monitor_evidence=False,
    )


def compose_blocking_package_evaluation(kind: str, evaluation: Any, **facts: object) -> Any:
    """Compose on a path whose outcome blocks; a resident failure still blocks."""

    try:
        return compose_package_evaluation(kind, evaluation, **facts)
    except NativePackageEvaluationComposeError:
        return native_unavailable_block_evaluation(evaluation)


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
    if not isinstance(patch, dict):
        raise _invalid()
    _validate_patch(kind, evaluation, patch, facts)
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
