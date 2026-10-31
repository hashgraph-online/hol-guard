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
HOOK_ARTIFACT_COMPOSE_SIGNAL_COMPOSITION_FEATURE = "hook-artifact-compose-signal-composition-v1"
# The precheck and the settle are two halves of one live-allow decision, with
# the fresh review running between them, so a runtime that serves one serves
# both and they share a feature.
HOOK_ARTIFACT_COMPOSE_CODEX_LIVE_ALLOW_FEATURE = "hook-artifact-compose-codex-live-allow-v1"
# Shipped with the policy-tail query kinds; the native artifact facts op is
# gated on the same feature, since a runtime with one has the other.
HOOK_ARTIFACT_COMPOSE_POLICY_TAIL_FEATURE = "hook-artifact-compose-policy-tail-v1"
_REQUEST_SCHEMA = "guard-hook-artifact-compose-request.v1"
_RESULT_SCHEMA = "guard-hook-artifact-compose-result.v1"
_RESIDENT_CODE = re.compile(r"^native_hook_artifact_compose_[a-z_]{1,64}$")
_MAX_REQUEST_BYTES = 256 * 1024
# The live-allow precheck carries the stored and the freshly built action
# envelopes, which the hook adapter accepts at its own bound. Sending them
# under the smaller default would refuse a large command here and deny an
# action the user had already approved, so this kind is bounded where the
# envelopes themselves are.
_LIVE_ALLOW_PRECHECK_MAX_REQUEST_BYTES = 4 * 1024 * 1024
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
    "config_action": frozenset({"policy_config", "artifact"}),
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
    "policy_lookup_select": frozenset({"lookups"}),
    "codex_live_allow_precheck": frozenset(
        {
            "resolution_action",
            "artifact_hash",
            "row_request_id",
            "stored_envelope",
            "previous_resolution_action",
            "previous_status",
            "request_id",
            "authority_resolved",
            "hook_event_name",
            "fresh_envelope",
        }
    ),
    "codex_live_allow_settle": frozenset({"fresh_review"}),
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
    "signal_composition": frozenset({"signals", "base_action"}),
}

# The feature a kind needs beyond the op itself. A runtime that predates the
# kind rejects it as an unknown kind, so the gate is per kind, not per op.
_KIND_FEATURES: dict[str, str] = {
    "codex_live_allow_precheck": HOOK_ARTIFACT_COMPOSE_CODEX_LIVE_ALLOW_FEATURE,
    "codex_live_allow_settle": HOOK_ARTIFACT_COMPOSE_CODEX_LIVE_ALLOW_FEATURE,
    "package_firewall_access": HOOK_ARTIFACT_COMPOSE_PACKAGE_FIREWALL_ACCESS_FEATURE,
    "package_firewall_entitlement": HOOK_ARTIFACT_COMPOSE_PACKAGE_FIREWALL_ENTITLEMENT_FEATURE,
    "package_reuse_settle": HOOK_ARTIFACT_COMPOSE_PACKAGE_REUSE_FEATURE,
    "policy_lookup_select": HOOK_ARTIFACT_COMPOSE_POLICY_LOOKUP_FEATURE,
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
    "config_action": {"action": "a", "auto_stop_events": "l"},
    "saved_reuse": {"approval_reuse": "d", "approval_reuse_source": "S", "policy_action": "a"},
    "trusted_override": {"claim_required": "b", "evidence": "D", "reason_code": "S"},
    "claimed_reuse": {
        "approval_reuse": "d",
        "approval_reuse_source": "s",
        "evidence": "d",
        "policy_action": "a",
        "trusted_request_override_applied": "b",
        "trusted_request_override_reason": "S",
    },
    "codex_live_allow_precheck": {
        "review_required": "b",
        "claimed_saved_allow_hash": "S",
        "claimed_approval_request_id": "S",
    },
    "codex_live_allow_settle": {"fresh_allow_authorized": "b"},
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
    "signal_composition": {
        "action": "a",
        "reason": "s",
        "downgraded": "b",
        "upgraded": "b",
        "normalization_reason_code": "S",
        "original_action": "S",
    },
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
    """The bound healthy owner refused the facts sent with a query."""


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
        max_request_bytes=(
            _LIVE_ALLOW_PRECHECK_MAX_REQUEST_BYTES if kind == "codex_live_allow_precheck" else _MAX_REQUEST_BYTES
        ),
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
    "HOOK_ARTIFACT_COMPOSE_CODEX_LIVE_ALLOW_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_PACKAGE_FIREWALL_ACCESS_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_PACKAGE_FIREWALL_ENTITLEMENT_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_PACKAGE_REUSE_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_POLICY_LOOKUP_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_POLICY_TAIL_FEATURE",
    "HOOK_ARTIFACT_COMPOSE_SIGNAL_COMPOSITION_FEATURE",
    "NativeHookComposeError",
    "NativeHookComposeValidationError",
    "native_hook_compose",
]
