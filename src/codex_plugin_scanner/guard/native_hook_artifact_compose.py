"""Hook artifact decision composition answered by the native runtime.

Python gathers evidence (policy config, store rows, scanner results); the
resident composes the action lattice, settles local grants, evaluates saved and
claimed approval reuse, decides the trusted-request override, and selects the
decision copy. There is no Python evaluator: ``native_hook_compose`` raises
``NativeHookComposeError`` for anything but a bound, strictly decoded ``ok``
answer, and the hook pipeline's fail-closed worker exception handling turns
that into an availability response.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request

HOOK_ARTIFACT_COMPOSE_FEATURE = "hook-artifact-compose-v1"
_REQUEST_SCHEMA = "guard-hook-artifact-compose-request.v1"
_RESULT_SCHEMA = "guard-hook-artifact-compose-result.v1"
_RESIDENT_CODE = re.compile(r"^native_hook_artifact_compose_[a-z_]{1,64}$")
_UNAVAILABLE = "native_hook_artifact_compose_unavailable"
_TIMEOUT_SECONDS = 5.0
# Every field is sent explicitly (nulls included) so the digest bound here
# equals the resident's digest of its decoded request.
_FIELDS: dict[str, frozenset[str]] = {
    "policy_stack": frozenset(
        {
            "config_action",
            "approval_context_config_action",
            "cli_action",
            "payload_action_present",
            "payload_action",
            "native_floor",
            "edge_floor",
            "current_action_override_present",
            "has_package",
            "package_policy_action",
            "has_data_flow",
            "data_flow_configured_action",
            "has_scanner",
            "scanner_action",
            "has_compound_findings",
            "artifact_risk_signals",
            "data_flow_reasons",
            "artifact_risk_summary",
            "data_flow_summary",
            "package_risk_signals",
            "package_risk_summary",
            "scanner_risk_signals",
        }
    ),
    "tool_grant_apply": frozenset(),
    "grant_settle": frozenset(
        {"current_action", "policy_action", "approval_context_action", "granted_action", "native_floor"}
    ),
    "saved_reuse": frozenset(
        {
            "current_action",
            "stored_present",
            "stored_action",
            "stored_artifact_hash",
            "integrity_failure",
            "stored_validation_reason",
            "cursor_native_present",
            "cursor_validation_reason",
            "diagnostic_reason",
            "diagnostic_stored_hash",
        }
    ),
    "saved_block_reuse": frozenset({"current_action", "policy_action", "stored_artifact_hash"}),
    "trusted_override": frozenset(
        {
            "token_validation_reason",
            "policy_action",
            "remembered_rule_rejected",
            "prior_reuse_reason_code",
            "stored_present",
            "stored_action",
            "stored_source",
            "stored_validation_reason",
            "claim_succeeded",
        }
    ),
    "claimed_reuse": frozenset(
        {
            "claimed_hash",
            "token_validation_reason",
            "post_claim_refresh_failed",
            "remembered_rule_rejected",
            "prior_reuse",
            "package_reuse_saved_action",
            "workflow_capability_required",
            "workflow_authorization_claimed",
            "policy_action",
            "current_policy_action",
            "claimed_trusted_request_override",
            "claimed_package_approval_consumed",
        }
    ),
    "decision_copy": frozenset(
        {
            "policy_action",
            "package",
            "package_policy_action",
            "has_compound_findings",
            "compound_finding_count",
            "risk_summary",
            "scanner_raised_to_block",
            "has_scanner_evidence",
            "scanner_primary_signal",
            "base_user_body",
            "base_harness_message",
            "base_dashboard_primary_detail",
            "remembered_rule_reason",
        }
    ),
}


class NativeHookComposeError(RuntimeError):
    """No authoritative composition answer; ``code`` says why, for diagnostics."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def native_hook_compose(kind: str, fields: Mapping[str, object], *, guard_home: Path | None) -> dict[str, object]:
    """Return the resident's answer to one composition query, or raise."""

    expected = _FIELDS.get(kind)
    if expected is None or set(fields) != expected:
        raise NativeHookComposeError("native_hook_artifact_compose_request_invalid")
    try:
        home = _resolve_digest_home(guard_home)
    except (OSError, RuntimeError, ValueError):
        raise NativeHookComposeError("native_hook_artifact_compose_home_unbound") from None
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"hook-artifact-compose-{uuid4().hex}",
        "query": {"kind": kind, **fields},
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        raise NativeHookComposeError("native_hook_artifact_compose_request_invalid") from None
    if not ensure_resident_prerequisite(home):
        raise NativeHookComposeError(_UNAVAILABLE)
    response = _resident_request(
        operation="hook_artifact_compose",
        request=request,
        guard_home=home,
        timeout_seconds=_TIMEOUT_SECONDS,
        required_feature=HOOK_ARTIFACT_COMPOSE_FEATURE,
        response_schema=_RESULT_SCHEMA,
    )
    if (
        response is None
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        raise NativeHookComposeError(_UNAVAILABLE)
    status, code = response.get("status"), response.get("code")
    if status == "error":
        reason = code if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code) else _UNAVAILABLE
        raise NativeHookComposeError(reason)
    payload = response.get("payload")
    if status != "ok" or code != "ok" or not isinstance(payload, dict):
        raise NativeHookComposeError("native_hook_artifact_compose_payload_invalid")
    return payload


__all__ = ["HOOK_ARTIFACT_COMPOSE_FEATURE", "NativeHookComposeError", "native_hook_compose"]
