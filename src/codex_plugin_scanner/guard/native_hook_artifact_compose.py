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

from .models import GUARD_ACTION_VALUES
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request

HOOK_ARTIFACT_COMPOSE_FEATURE = "hook-artifact-compose-v1"
# A query kind an older resident does not know is rejected as an unknown
# kind, so each kind added after the op requires its own feature and only
# for its own call.
HOOK_ARTIFACT_COMPOSE_PACKAGE_FIREWALL_ENTITLEMENT_FEATURE = "hook-artifact-compose-package-firewall-entitlement-v1"
HOOK_ARTIFACT_COMPOSE_PACKAGE_REUSE_FEATURE = "hook-artifact-compose-package-reuse-v1"
HOOK_ARTIFACT_COMPOSE_PACKAGE_FIREWALL_ACCESS_FEATURE = "hook-artifact-compose-package-firewall-access-v1"
HOOK_ARTIFACT_COMPOSE_POLICY_LOOKUP_FEATURE = "hook-artifact-compose-policy-lookup-v1"
HOOK_ARTIFACT_COMPOSE_PROMPT_REASON_FEATURE = "hook-artifact-compose-prompt-reason-v1"
HOOK_ARTIFACT_COMPOSE_REMEMBERED_RULE_FEATURE = "hook-artifact-compose-remembered-rule-v1"
HOOK_ARTIFACT_COMPOSE_SIGNAL_COMPOSITION_FEATURE = "hook-artifact-compose-signal-composition-v1"
# The policy stack answers whether local tool-grant evidence is required, the
# artifact facts answer whether the native floor is skipped, and the settled
# verdict's composition and approval source are a query kind of their own.
# A runtime that predates any of them cannot answer the others, so every caller
# of the three requires this one feature.
HOOK_ARTIFACT_COMPOSE_POLICY_TAIL_FEATURE = "hook-artifact-compose-policy-tail-v1"
_REQUEST_SCHEMA = "guard-hook-artifact-compose-request.v1"
_RESULT_SCHEMA = "guard-hook-artifact-compose-result.v1"
_RESIDENT_CODE = re.compile(r"^native_hook_artifact_compose_[a-z_]{1,64}$")
_UNAVAILABLE = "native_hook_artifact_compose_unavailable"
_TIMEOUT_SECONDS = 5.0
# Every field is sent explicitly (nulls included) so the digest bound here
# equals the resident's digest of its decoded request.
_FIELDS: dict[str, frozenset[str]] = {
    "package_firewall_entitlement": frozenset(
        {
            "bundle_payload",
            "connect_state",
            "has_cloud_sync_profile",
            "now",
            "oauth_health",
            "oauth_payload",
        }
    ),
    "policy_stack": frozenset(
        {
            "event_name",
            "artifact_type",
            "has_raw_command",
            "policy_config",
            "runtime",
            "approval_context",
            "data_flow_strong",
            "cli_action",
            "payload_action_present",
            "payload_action",
            "native_floor",
            "native_edge",
            "current_action_override_present",
            "has_package",
            "package_policy_action",
            "has_data_flow",
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
    "config_action": frozenset({"policy_config", "artifact"}),
    "tool_grant_apply": frozenset(),
    "grant_settle": frozenset(
        {"current_action", "policy_action", "approval_context_action", "granted_action", "native_floor"}
    ),
    "observe_executable_action": frozenset(
        {
            "current_config_action",
            "current_action_override",
            "trusted_cli_override",
            "untrusted_hook_payload_hint",
            "package_action",
            "data_flow_action",
            "scanner_action",
            "package_evaluation_action",
        }
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
    "decision_build_copy": frozenset({"copy", "reason", "signals"}),
    "policy_lookup_select": frozenset({"lookups"}),
    "package_reuse_settle": frozenset(
        {
            "reasons",
            "claim_saved_approval",
            "current_action",
            "evaluation_policy_action",
            "stored_policy_action",
            "stored_artifact_hash",
            "approval_reuse_source",
        }
    ),
    "package_firewall_access": frozenset({"entitlement", "operation", "has_installed_managers"}),
    "prompt_request_reason": frozenset({"harness", "prompt_classes", "prompt_summary", "policy_action"}),
    "remembered_rule_reason": frozenset({"remembered_rules", "integrity_message", "artifact_summary"}),
    "signal_composition": frozenset({"signals", "base_action"}),
    "policy_composition": frozenset(
        {
            "current_config_action",
            "current_action_override",
            "trusted_cli_action",
            "untrusted_payload_action",
            "package_policy_action",
            "data_flow_action",
            "scanner_action",
            "current_composed_action",
            "saved_policy_action",
            "approval_reuse_source",
            "trusted_request_override",
            "trusted_request_override_reason",
            "authoritative_action",
            "claude_native_approval_observed",
            "user_override_present",
        }
    ),
}

# The feature a kind needs beyond the op itself. A runtime that predates the
# kind rejects it as an unknown kind, so the gate is per kind, not per op.
_KIND_FEATURES: dict[str, str] = {
    "package_firewall_access": HOOK_ARTIFACT_COMPOSE_PACKAGE_FIREWALL_ACCESS_FEATURE,
    "package_firewall_entitlement": HOOK_ARTIFACT_COMPOSE_PACKAGE_FIREWALL_ENTITLEMENT_FEATURE,
    "package_reuse_settle": HOOK_ARTIFACT_COMPOSE_PACKAGE_REUSE_FEATURE,
    "policy_composition": HOOK_ARTIFACT_COMPOSE_POLICY_TAIL_FEATURE,
    "policy_lookup_select": HOOK_ARTIFACT_COMPOSE_POLICY_LOOKUP_FEATURE,
    "policy_stack": HOOK_ARTIFACT_COMPOSE_POLICY_TAIL_FEATURE,
    "prompt_request_reason": HOOK_ARTIFACT_COMPOSE_PROMPT_REASON_FEATURE,
    "remembered_rule_reason": HOOK_ARTIFACT_COMPOSE_REMEMBERED_RULE_FEATURE,
    "signal_composition": HOOK_ARTIFACT_COMPOSE_SIGNAL_COMPOSITION_FEATURE,
}

# The exact answer shape of each query kind. Spec letters: a action,
# A action or null, b bool, i integer, s string, S string or null, d dict,
# D dict or null, l list.
_ANSWERS: dict[str, dict[str, str]] = {
    "package_firewall_entitlement": {
        "allowed": "b",
        "reason": "s",
        "tier": "s",
        "upgrade_cta": "S",
    },
    "policy_stack": {
        "approval_context_config_action": "a",
        "auto_stop_events": "l",
        "approval_context_data_flow_action": "A",
        "approval_context_policy_action": "a",
        "current_config_action": "a",
        "data_flow_action": "A",
        "local_eligibility_required": "b",
        "local_grants_allowed": "b",
        "native_floor": "A",
        "normalizer_evidence": "l",
        "package_policy_action": "A",
        "policy_action": "a",
        "requested_policy_action": "S",
        "risk_signals": "l",
        "risk_summary": "s",
        "scanner_action": "A",
        "scanner_raised_to_block": "b",
        "trusted_cli_action": "A",
        "untrusted_payload_action": "A",
    },
    "config_action": {"action": "a", "auto_stop_events": "l"},
    "tool_grant_apply": {"approval_context_policy_action": "a", "current_policy_action": "a", "policy_action": "a"},
    "grant_settle": {"approval_context_policy_action": "a", "current_policy_action": "a", "policy_action": "a"},
    "observe_executable_action": {"executable_action": "a"},
    "saved_reuse": {"approval_reuse": "d", "approval_reuse_source": "S", "policy_action": "a"},
    "saved_block_reuse": {"approval_reuse": "d", "policy_action": "a"},
    "trusted_override": {"claim_required": "b", "evidence": "D", "reason_code": "S"},
    "claimed_reuse": {
        "approval_reuse": "d",
        "approval_reuse_source": "s",
        "evidence": "d",
        "policy_action": "a",
        "trusted_request_override_applied": "b",
        "trusted_request_override_reason": "S",
    },
    "decision_copy": {"decision_overrides": "d", "risk_headline": "S"},
    "decision_build_copy": {"decision_v2": "d", "risk_headline": "S"},
    "policy_lookup_select": {
        "authority_revision": "i",
        "decision": "D",
        "ignored_local_integrity": "D",
        "trust_status": "d",
    },
    "package_reuse_settle": {
        "approval_reuse": "D",
        "approval_reuse_source": "S",
        "claim_disposition": "S",
        "evidence_appends": "l",
        "policy_action": "a",
        "reuse_applied": "b",
        "reuse_evidence": "D",
        "revalidate_required": "b",
        "saved_allow_applied": "b",
        "settled_evidence_appends": "l",
    },
    "package_firewall_access": {
        "action_states": "d",
        "available_actions": "l",
        "block": "d",
        "operation_allowed": "B",
    },
    "prompt_request_reason": {"reason": "s"},
    "remembered_rule_reason": {"reason": "S"},
    "signal_composition": {
        "action": "a",
        "reason": "s",
        "downgraded": "b",
        "upgraded": "b",
        "normalization_reason_code": "S",
        "original_action": "S",
    },
    "policy_composition": {"approval_source": "s", "evidence": "d", "policy_composition": "d"},
}


def _field_valid(spec: str, value: object) -> bool:
    if spec.isupper() and value is None:
        return True
    match spec.lower():
        case "a":
            return isinstance(value, str) and value in GUARD_ACTION_VALUES
        case "b":
            return isinstance(value, bool)
        case "i":
            return isinstance(value, int) and not isinstance(value, bool)
        case "s":
            return isinstance(value, str)
        case "d":
            return isinstance(value, dict)
        case "l":
            return isinstance(value, list)
    return False


def _answer_valid(kind: str, payload: dict[str, object]) -> bool:
    shape = _ANSWERS[kind]
    return set(payload) == set(shape) and all(_field_valid(spec, payload[name]) for name, spec in shape.items())


class NativeHookComposeError(RuntimeError):
    """No authoritative composition answer; ``code`` says why, for diagnostics."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class NativeHookComposeValidationError(ValueError):
    """The bound healthy owner refused invalid decision-copy facts."""


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
        required_feature=_KIND_FEATURES.get(kind, HOOK_ARTIFACT_COMPOSE_FEATURE),
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
        payload = response.get("payload")
        if (
            code == "native_hook_artifact_compose_validation_refused"
            and isinstance(payload, dict)
            and payload.get("error_type") == "ValueError"
            and isinstance(payload.get("message"), str)
            and len(payload["message"].encode("utf-8")) <= 4096
        ):
            raise NativeHookComposeValidationError(payload["message"])
        reason = code if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code) else _UNAVAILABLE
        raise NativeHookComposeError(reason)
    payload = response.get("payload")
    if status != "ok" or code != "ok" or not isinstance(payload, dict):
        raise NativeHookComposeError("native_hook_artifact_compose_payload_invalid")
    if not _answer_valid(kind, payload):
        raise NativeHookComposeError("native_hook_artifact_compose_payload_invalid")
    return payload


__all__ = [
    "HOOK_ARTIFACT_COMPOSE_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_PACKAGE_FIREWALL_ACCESS_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_PACKAGE_FIREWALL_ENTITLEMENT_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_PACKAGE_REUSE_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_POLICY_LOOKUP_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_POLICY_TAIL_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_PROMPT_REASON_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_REMEMBERED_RULE_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_SIGNAL_COMPOSITION_FEATURE",
    "NativeHookComposeError",
    "NativeHookComposeValidationError",
    "native_hook_compose",
]
