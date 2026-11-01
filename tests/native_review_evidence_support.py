"""Ask the resident's ``hook_review`` kind directly, as the edge does.

The daemon no longer sends this ask: the edge answers a review's evidence in
the same round trip as the review. Regressions still ask the resident for one
review's evidence to pin the identity, token and once-only reasons it proves.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.daemon.hook_native_exact_action import (
    _ONCE_ONLY_REASONS,
    UNPROVEN_LAUNCH,
)
from codex_plugin_scanner.guard.daemon.hook_native_review_binding import native_review_policy_binding
from codex_plugin_scanner.guard.native_daemon_route import _decide
from codex_plugin_scanner.guard.native_resident_decision import ResidentOperation
from codex_plugin_scanner.guard.runtime.extension_control_runtime import current_extension_control_binding_digest

NATIVE_EXACT_ACTION_FEATURE = "native-exact-action-v6"
_BUDGET_MS = 4000
_MAX_REQUEST_BYTES = 4 * 1024 * 1024


class NativeExactActionError(RuntimeError):
    """No authoritative answer; ``code`` says why."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_OPERATION = ResidentOperation(
    operation="native_exact_action",
    feature=NATIVE_EXACT_ACTION_FEATURE,
    prefix="native_exact_action",
    request_schema="guard-native-exact-action-request.v1",
    request_id_prefix="native-exact-action",
    result_schema="guard-native-exact-action-result.v1",
    timeout_seconds=6.0,
    error=NativeExactActionError,
)


def _hook_review_query(
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
) -> dict[str, object]:
    return {
        "kind": "hook_review",
        "harness": harness,
        "payload": dict(payload),
        "result": dict(native_result),
        "receipt": dict(native_receipt) if isinstance(native_receipt, Mapping) else None,
        "workspace": None if workspace is None else str(workspace),
        "home_dir": None if home_dir is None else str(home_dir),
        "environment": {key: value for key, value in os.environ.items() if isinstance(value, str)},
        "extension_control_digest": current_extension_control_binding_digest(),
        "budget_ms": _BUDGET_MS,
    }


def _validate_exact_action(payload: dict[str, Any]) -> None:
    reason = payload["once_only_reason"]
    if reason is not None and reason not in _ONCE_ONLY_REASONS:
        raise NativeExactActionError(_OPERATION.invalid)


def _policy_binding_valid(
    harness: str, native_result: Mapping[str, object], native_receipt: Mapping[str, object] | None
) -> bool:
    try:
        native_review_policy_binding(harness=harness, native_result=native_result, verified_receipt=native_receipt)
    except ValueError:
        return False
    return True


def resident_review_evidence(
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """The resident's answer to one review, shaped as the edge's ``review_evidence``."""

    try:
        reply = _decide(
            _hook_review_query(
                harness=harness,
                payload=payload,
                native_result=native_result,
                native_receipt=native_receipt,
                workspace=workspace,
                home_dir=home_dir,
            ),
            guard_home,
            {
                "policy_binding_valid": bool,
                "binding": (str, type(None)),
                "token": (str, type(None)),
                "once_only_reason": (str, type(None)),
            },
            _validate_exact_action,
            operation=_OPERATION,
            max_request_bytes=_MAX_REQUEST_BYTES,
        )
    except (NativeExactActionError, OSError, RuntimeError, TypeError, ValueError):
        return {
            "policy_binding_valid": _policy_binding_valid(harness, native_result, native_receipt),
            "binding": None,
            "token": None,
            "once_only_reason": UNPROVEN_LAUNCH,
        }
    return {key: reply[key] for key in ("policy_binding_valid", "binding", "token", "once_only_reason")}


def native_review_evidence(**kwargs: Any) -> tuple[bool, str | None, str | None, str | None]:
    """The decoded evidence the daemon's pause reads from the edge."""

    from codex_plugin_scanner.guard.daemon.hook_native_exact_action import review_evidence_parts

    parts = review_evidence_parts(resident_review_evidence(**kwargs))
    assert parts is not None
    return parts


def with_review_evidence(edge: Any, **kwargs: Any) -> Any:
    """A faked edge answer as the real edge sends it: a review carries its evidence.

    ``kwargs`` are the arguments the daemon passed to ``review_raw_hook_native``.
    The resident answers the same question the edge asks beside the review.
    """

    if not isinstance(edge, dict) or "review_evidence" in edge or kwargs.get("observe_mode"):
        return edge
    result = edge.get("result")
    if (
        edge.get("event_name") != "PreToolUse"
        or not isinstance(result, dict)
        or result.get("minimum_action") not in {"review", "require-reapproval"}
    ):
        return edge
    receipt = edge.get("receipt")
    evidence = resident_review_evidence(
        harness=str(edge.get("harness")),
        payload=kwargs.get("payload") or {},
        native_result=result,
        native_receipt=receipt if isinstance(receipt, dict) else None,
        workspace=kwargs.get("cwd"),
        home_dir=kwargs.get("home_dir"),
        guard_home=kwargs.get("guard_home"),
    )
    return {**edge, "review_evidence": evidence}
