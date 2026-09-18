"""Bind ordinary local review reuse to its verified native policy domain."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from ..native_decision_receipt import receipt_matches_edge, validate_native_decision_receipt

NATIVE_REVIEW_BINDING_FIELD = "native_review_policy_binding"
NATIVE_REVIEW_REQUEST_DIGEST_FIELD = "native_review_request_digest"
_SCHEMA = "guard.native-review-policy-binding.v1"


def native_codex_request_digest(native_result: Mapping[str, object], verified_receipt: object) -> str | None:
    """Retain the Rust commitment to exact Codex input, source, and generation.

    This is distinct from ordinary reusable-review policy binding. A renewed
    policy generation conservatively requires a new browser approval.
    """
    receipt = validate_native_decision_receipt(verified_receipt)
    if receipt is None or not receipt_matches_edge(
        {
            "harness": "codex",
            "event_name": "PreToolUse",
            "payload_kind": receipt["payload_kind"],
            "result": native_result,
        },
        receipt,
    ):
        return None
    digest = receipt.get("request_digest")
    return digest if isinstance(digest, str) else None


def native_review_policy_binding(
    *, harness: str, native_result: Mapping[str, object], verified_receipt: object
) -> dict[str, object] | None:
    """Capture only a typed native receipt; request payload metadata is not authority.

    Absence on both native surfaces retains the legacy contract. A partially
    present or inconsistent command domain cannot create an unbound approval.
    Receipt persistence is asynchronous and does not participate in this check.
    """

    receipt_bound = isinstance(verified_receipt, Mapping) and "command_extensions" in verified_receipt
    if "command_extensions" not in native_result and not receipt_bound:
        return None
    receipt = validate_native_decision_receipt(verified_receipt)
    if receipt is None or not receipt_matches_edge(
        {
            "harness": harness,
            "event_name": "PreToolUse",
            "payload_kind": receipt["payload_kind"],
            "result": native_result,
        },
        receipt,
    ):
        raise ValueError("native_review_policy_binding_invalid")
    if any(not isinstance(receipt.get(field), str) for field in ("policy_digest", "rule_digest", "runtime_identity")):
        raise ValueError("native_review_policy_binding_invalid")
    command_binding = receipt.get("command_extensions")
    if not isinstance(command_binding, dict) or command_binding.get("uncertainty_count") != 0:
        raise ValueError("native_review_policy_binding_invalid")
    return {
        "schema": _SCHEMA,
        "policy_digest": receipt["policy_digest"],
        "rule_digest": receipt["rule_digest"],
        "runtime_identity": receipt["runtime_identity"],
        "command_extensions": dict(command_binding),
    }


def native_review_binding_matches(row: Mapping[str, object], current: Mapping[str, object] | None) -> bool:
    envelope = row.get("action_envelope_json")
    if not isinstance(envelope, Mapping):
        return current is None
    if current is None:
        # A J-bound approval cannot become a legacy approval by stripping the
        # current request's binding. Preserve absence-only legacy behavior.
        return NATIVE_REVIEW_BINDING_FIELD not in envelope
    recorded = envelope.get(NATIVE_REVIEW_BINDING_FIELD)
    return isinstance(recorded, Mapping) and recorded == current


def native_review_action_identity(
    *, tool_name: str, launch_target: str, binding: Mapping[str, object] | None
) -> str | None:
    if binding is None:
        return None
    # Pending queue deduplication must not overwrite an earlier policy domain
    # while a user is deciding that earlier request.
    encoded = json.dumps(
        {"tool_name": tool_name, "launch_target": launch_target, "binding": binding},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(b"hol-guard.native-review-action.v1\0" + encoded).hexdigest()
