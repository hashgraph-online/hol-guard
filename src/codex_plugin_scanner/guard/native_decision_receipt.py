"""Strict privacy and idempotency checks for Rust hook decision receipts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Final, cast

NATIVE_HOOK_DECISION_RECEIPT_SCHEMA: Final = "guard-native-hook-decision-receipt.v1"
NATIVE_HOOK_DECISION_RECEIPT_MAX_BYTES: Final = 16 * 1024
NATIVE_HOOK_DECISION_RECEIPT_MAX_STRING_BYTES: Final = 512
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_REQUEST_ID = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,255}$")
_HARNESS = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_ACTIONS = frozenset({"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"})
_MODEL_ACTIONS = frozenset({"allow_original", "replace_with_reviewed_excerpt", "block", "not_applicable"})
_PAYLOAD_KINDS = frozenset({"inline", "source_file_ref", "encrypted_payload_ref"})
_REQUIRED_FIELDS = frozenset(
    {
        "schema",
        "version",
        "authority",
        "decision_id",
        "request_id",
        "request_digest",
        "harness",
        "event_name",
        "payload_kind",
        "policy_generation",
        "policy_digest",
        "rule_digest",
        "runtime_identity",
        "decision",
        "model_output_action",
        "policy_action",
        "observed_policy_action",
        "reason_code",
        "workspace_bound",
        "source_ref_external_allowed",
        "reviewed_output_sha256",
        "observe_mode",
        "deadline_budget_ms",
    }
)


def _bounded_identifier(value: object, *, pattern: re.Pattern[str], maximum: int) -> str | None:
    if not isinstance(value, str) or not value or len(value) > maximum or pattern.fullmatch(value) is None:
        return None
    return value


def _optional_digest(value: object) -> str | None | object:
    if value is None:
        return None
    if isinstance(value, str) and _HEX64.fullmatch(value):
        return value
    return _INVALID


_INVALID = object()


def _identity_payload(receipt: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema": "guard-native-hook-decision-identity.v1",
        "version": 1,
        "request_id": receipt["request_id"],
        "request_digest": receipt["request_digest"],
        "harness": receipt["harness"],
        "event_name": receipt["event_name"],
        "payload_kind": receipt["payload_kind"],
        "policy_generation": receipt["policy_generation"],
        "policy_digest": receipt["policy_digest"],
        "rule_digest": receipt["rule_digest"],
        "runtime_identity": receipt["runtime_identity"],
        "decision": receipt["decision"],
        "model_output_action": receipt["model_output_action"],
        "policy_action": receipt["policy_action"],
        "observed_policy_action": receipt["observed_policy_action"],
        "reason_code": receipt["reason_code"],
        "workspace_bound": receipt["workspace_bound"],
        "source_ref_external_allowed": receipt["source_ref_external_allowed"],
        "reviewed_output_sha256": receipt["reviewed_output_sha256"],
        "observe_mode": receipt["observe_mode"],
        "deadline_budget_ms": receipt["deadline_budget_ms"],
    }


def canonical_receipt_bytes(receipt: Mapping[str, object]) -> bytes:
    """Return the deterministic identity encoding shared with the Rust edge."""

    return json.dumps(
        _identity_payload(receipt),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _validate_receipt_identity(receipt: dict[str, object]) -> str | None:
    if receipt["schema"] != NATIVE_HOOK_DECISION_RECEIPT_SCHEMA or receipt["version"] != 1:
        return None
    if receipt["authority"] != "rust":
        return None
    decision_id = _bounded_identifier(receipt["decision_id"], pattern=_HEX64, maximum=64)
    request_id = _bounded_identifier(receipt["request_id"], pattern=_REQUEST_ID, maximum=256)
    request_digest = _bounded_identifier(receipt["request_digest"], pattern=_HEX64, maximum=64)
    harness = _bounded_identifier(receipt["harness"], pattern=_HARNESS, maximum=64)
    if decision_id is None or request_id is None or request_digest is None or harness is None:
        return None
    event_name = receipt["event_name"]
    payload_kind = receipt["payload_kind"]
    if not isinstance(event_name, str) or event_name not in {"PreToolUse", "PostToolUse"}:
        return None
    if not isinstance(payload_kind, str) or payload_kind not in _PAYLOAD_KINDS:
        return None
    generation = receipt["policy_generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or not 0 < generation <= 2**63 - 1:
        return None
    return decision_id


def _validate_receipt_policy(receipt: dict[str, object]) -> bool:
    for field in ("policy_digest", "rule_digest", "runtime_identity", "reviewed_output_sha256"):
        if _optional_digest(receipt[field]) is _INVALID:
            return False
    decision = receipt["decision"]
    model_output_action = receipt["model_output_action"]
    if not isinstance(decision, str) or decision not in {"allow", "deny"}:
        return False
    if not isinstance(model_output_action, str) or model_output_action not in _MODEL_ACTIONS:
        return False
    for field in ("policy_action", "observed_policy_action"):
        action = receipt[field]
        if action is not None and (not isinstance(action, str) or action not in _ACTIONS):
            return False
    reason_code = _bounded_identifier(
        receipt["reason_code"],
        pattern=_IDENTIFIER,
        maximum=NATIVE_HOOK_DECISION_RECEIPT_MAX_STRING_BYTES,
    )
    return reason_code is not None


def _validate_receipt_limits(receipt: dict[str, object]) -> bool:
    for field in ("workspace_bound", "source_ref_external_allowed", "observe_mode"):
        if not isinstance(receipt[field], bool):
            return False
    budget = receipt["deadline_budget_ms"]
    if budget is not None and (isinstance(budget, bool) or not isinstance(budget, int) or not 1 <= budget <= 9_000):
        return False
    try:
        encoded = json.dumps(receipt, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        return False
    return len(encoded) <= NATIVE_HOOK_DECISION_RECEIPT_MAX_BYTES


def validate_native_decision_receipt(value: object) -> dict[str, object] | None:
    """Validate and copy one Rust receipt without retaining request material."""

    if not isinstance(value, Mapping):
        return None
    receipt = dict(cast(Mapping[str, object], value))
    if set(receipt) != _REQUIRED_FIELDS:
        return None
    decision_id = _validate_receipt_identity(receipt)
    if decision_id is None or not _validate_receipt_policy(receipt) or not _validate_receipt_limits(receipt):
        return None
    expected_decision_id = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    if decision_id != expected_decision_id:
        return None
    return receipt


def receipt_matches_edge(payload: Mapping[str, object], receipt: object) -> bool:
    """Require receipt identity fields to agree with the typed edge result."""

    validated = validate_native_decision_receipt(receipt)
    event_name = payload.get("event_name")
    harness = payload.get("harness")
    payload_kind = payload.get("payload_kind")
    result = payload.get("result")
    if (
        validated is None
        or not isinstance(event_name, str)
        or not isinstance(harness, str)
        or not isinstance(payload_kind, str)
        or not isinstance(result, Mapping)
        or validated["event_name"] != event_name
        or validated["harness"] != harness
        or validated["payload_kind"] != payload_kind
    ):
        return False
    request_id = payload.get("request_id")
    if request_id is not None and validated["request_id"] != request_id:
        return False
    expected = {
        "decision": result.get("decision"),
        "model_output_action": ("not_applicable" if event_name == "PreToolUse" else result.get("model_output_action")),
        "policy_action": result.get("policy_action"),
        "observed_policy_action": result.get("observed_policy_action"),
        "reason_code": result.get("reason_code"),
        "reviewed_output_sha256": result.get("reviewed_output_sha256"),
        "observe_mode": result.get("observe_mode") is True,
    }
    return all(validated[key] == value for key, value in expected.items())


__all__ = [
    "NATIVE_HOOK_DECISION_RECEIPT_MAX_BYTES",
    "NATIVE_HOOK_DECISION_RECEIPT_SCHEMA",
    "canonical_receipt_bytes",
    "receipt_matches_edge",
    "validate_native_decision_receipt",
]
