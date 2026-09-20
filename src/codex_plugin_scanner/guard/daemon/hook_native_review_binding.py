"""Bind ordinary local review reuse to its verified native policy domain."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from ..native_decision_receipt import receipt_matches_edge, validate_native_decision_receipt

NATIVE_REVIEW_BINDING_FIELD = "native_review_policy_binding"
NATIVE_REVIEW_REQUEST_DIGEST_FIELD = "native_review_request_digest"
_SCHEMA = "guard.native-review-policy-binding.v1"
_NONCOMMAND_SCHEMA = "guard.native-review-policy-binding.v2"


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
    *,
    harness: str,
    native_result: Mapping[str, object],
    verified_receipt: object,
    policy_snapshot: Mapping[str, object] | None = None,
    workspace_bound: bool | None = None,
) -> dict[str, object]:
    """Capture the verified current native review domain.

    Commands require their exact extension binding. A noncommand review needs
    the current Rust extraction marker and matching ACKed snapshot; absence of
    command evidence alone is insufficient. Persistence remains asynchronous.
    """

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
    if receipt.get("review_scope") == "noncommand":
        return _noncommand_binding(receipt, native_result, policy_snapshot, workspace_bound)
    if not isinstance(command_binding, dict) or command_binding.get("uncertainty_count") != 0:
        raise ValueError("native_review_policy_binding_invalid")
    return {
        "schema": _SCHEMA,
        "policy_digest": receipt["policy_digest"],
        "rule_digest": receipt["rule_digest"],
        "runtime_identity": receipt["runtime_identity"],
        "command_extensions": dict(command_binding),
    }


def _noncommand_binding(
    receipt: Mapping[str, object],
    native_result: Mapping[str, object],
    snapshot: Mapping[str, object] | None,
    workspace_bound: bool | None,
) -> dict[str, object]:
    from ..native_hook_edge import _decode_pre_tool_result

    # The marker is emitted only after native extraction proved no command.
    # Validate current authority independently; legacy receipts or removing a
    # command binding cannot create this separate approval domain.
    if (
        snapshot is None
        or snapshot.get("mode") != "enforce"
        or type(snapshot.get("generation")) is not int
        or snapshot.get("generation") != receipt["policy_generation"]
        or any(snapshot.get(field) != receipt[field] for field in ("policy_digest", "runtime_identity"))
        or ("rule_digest" in snapshot and snapshot["rule_digest"] != receipt["rule_digest"])
        or type(workspace_bound) is not bool
        or receipt["workspace_bound"] is not workspace_bound
        or "command_extensions" in receipt
        or "command_extensions" in native_result
        or not _decode_pre_tool_result(dict(native_result), harness=str(receipt["harness"]))
    ):
        raise ValueError("native_review_policy_binding_invalid")
    action = native_result["action"]
    assert isinstance(action, Mapping)
    return {
        "schema": _NONCOMMAND_SCHEMA,
        "review_scope": "noncommand",
        **{
            field: receipt[field]
            for field in (
                "policy_generation",
                "policy_digest",
                "rule_digest",
                "runtime_identity",
                "request_digest",
                "harness",
                "event_name",
                "payload_kind",
                "workspace_bound",
                "source_ref_external_allowed",
            )
        },
        "action_type": action["action_type"],
        "operation": action["operation"],
    }


def native_review_binding_matches(row: Mapping[str, object], current: Mapping[str, object] | None) -> bool:
    if current is None:
        return False
    envelope = row.get("action_envelope_json")
    if not isinstance(envelope, Mapping):
        return False
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
