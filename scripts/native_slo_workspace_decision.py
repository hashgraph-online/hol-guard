"""Join observed request boundaries to validated and committed native receipts.

These are observer endpoints in one owned Python process, not Rust decision
timestamps. A request offered before acceptance remains distinguishable from
one offered afterward even when both finish after the accepted mutation.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from itertools import pairwise
from typing import Any, TypeGuard, cast

from scripts.native_slo_workspace_observer import public_binding

MAX_REQUESTS = 32
_DIGEST = re.compile(r"[0-9a-f]{64}")
_COMMAND_FIELDS = {
    "program_digest": "program_digest",
    "catalog_digest": "catalog_digest",
    "trust_digest": "trust_digest",
    "control_revision": "revision",
    "managed_control_revision": "managed_revision",
    "control_effective_digest": "effective_digest",
}


def finite_time(value: object) -> TypeGuard[int | float]:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(cast(float, value))
    except OverflowError:
        return False


def authority_projection(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only bounded public identity, lifetime and command-control fields."""
    binding = public_binding(snapshot)
    command = snapshot.get("command_extensions")
    issued, expires = snapshot.get("issued_at_ms"), snapshot.get("expires_at_ms")
    rule = snapshot.get("rule_digest")
    if (
        binding is None
        or snapshot.get("mode") != "enforce"
        or type(issued) is not int
        or type(expires) is not int
        or not 0 <= issued < expires < 2**63
        or not isinstance(rule, str)
        or _DIGEST.fullmatch(rule) is None
        or not isinstance(command, Mapping)
    ):
        raise ValueError("workspace request authority projection invalid")
    controls = {receipt_key: command.get(source_key) for receipt_key, source_key in _COMMAND_FIELDS.items()}
    for key, value in controls.items():
        valid = (
            type(value) is int and 0 <= value < 2**64
            if key in {"control_revision", "managed_control_revision"}
            else isinstance(value, str) and _DIGEST.fullmatch(value) is not None
        )
        if not valid:
            raise ValueError("workspace request command identity invalid")
    return {
        **binding,
        "rule_digest": rule,
        "mode": "enforce",
        "issued_at_ms": issued,
        "expires_at_ms": expires,
        "command_controls": controls,
    }


def receipt_projection(receipt: object) -> dict[str, Any] | None:
    from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt

    valid = validate_native_decision_receipt(receipt)
    if valid is None:
        return None
    # The product validator admits an exact privacy-bounded schema (at most
    # 16 KiB). Retain all of it so an independent reader can recheck identity.
    return json.loads(json.dumps(valid, allow_nan=False))


def _checks(row: Mapping[str, Any], authority: Mapping[str, Any], action: str) -> dict[str, bool]:
    receipt = row.get("native_receipt")
    committed = row.get("committed_receipt")
    validated = receipt_projection(receipt)
    validated_committed = receipt_projection(committed)
    identity = receipt.get("decision_id") if isinstance(receipt, Mapping) else None
    command = receipt.get("command_extensions") if isinstance(receipt, Mapping) else None
    stamps = [
        row.get(key)
        for key in (
            "offered_ms",
            "review_entered_ms",
            "native_finished_ms",
            "review_returned_ms",
            "delivered_ms",
            "commit_observed_ms",
        )
    ]
    ordered = all(finite_time(stamp) and 0 <= stamp < 2**63 for stamp in stamps) and all(
        left <= right for left, right in pairwise(cast(list[int | float], stamps))
    )
    wall_entered, wall_returned = row.get("review_entered_wall_ms"), row.get("review_returned_wall_ms")
    expected_decision = "allow" if action == "allow" else "deny"
    return {
        "one_completed_review": (
            type(row.get("review_calls")) is int and row["review_calls"] == 1 and row.get("review_returned") is True
        ),
        "one_completed_request": row.get("request_returned") is True,
        "bounded_monotonic_order": ordered,
        "observed_wall_lifetime": (
            finite_time(wall_entered)
            and finite_time(wall_returned)
            and authority["issued_at_ms"] <= wall_entered <= wall_returned < authority["expires_at_ms"]
        ),
        "request_scope_matches": (
            type(row.get("workspace_index")) is int
            and 0 <= row["workspace_index"] < 100
            and row.get("request_scope_matches") is True
        ),
        "request_binding_matches": row.get("request_binding_matches") is True,
        "authenticated_readbacks_match": (
            row.get("authority_readback_before") is True and row.get("authority_readback_after") is True
        ),
        "validated_native_receipt": validated is not None and row.get("native_receipt_validated") is True,
        "receipt_authority_matches": isinstance(receipt, Mapping)
        and all(
            receipt.get(receipt_key) == authority[source_key]
            for receipt_key, source_key in (
                ("policy_generation", "generation"),
                ("policy_digest", "policy_digest"),
                ("runtime_identity", "runtime_identity"),
                ("rule_digest", "rule_digest"),
            )
        ),
        "receipt_command_controls_match": isinstance(command, Mapping)
        and all(command.get(key) == value for key, value in authority["command_controls"].items()),
        "receipt_semantics_match": (
            isinstance(receipt, Mapping)
            and receipt.get("event_name") == "PreToolUse"
            and receipt.get("harness") == "claude-code"
            and receipt.get("workspace_bound") is True
            and receipt.get("observe_mode") is False
            and receipt.get("policy_action") == action
            and receipt.get("decision") == expected_decision
            and receipt.get("model_output_action") == "not_applicable"
        ),
        "delivery_matches": row.get("delivered_decision") == expected_decision,
        "original_witness_matches": (
            isinstance(identity, str)
            and row.get("witness_decision_id") == identity
            and row.get("writer_admitted") is True
            and row.get("witness_committed") is True
            and row.get("witness_commit_binding_valid") is True
        ),
        "unique_committed_readback": (
            type(row.get("committed_row_count")) is int
            and row["committed_row_count"] == 1
            and row.get("committed_receipt_validated") is True
            and validated_committed is not None
            and validated_committed == validated
        ),
        "capture_faults_absent": type(row.get("capture_faults")) is int and row["capture_faults"] == 0,
    }


def _first(rows: list[dict[str, Any]]) -> dict[str, object] | None:
    if not rows:
        return None
    stamp = min(row["native_finished_ms"] for row in rows)
    first = [row for row in rows if row["native_finished_ms"] == stamp]
    return {
        "native_finished_ms": stamp,
        "attempts": [row["attempt"] for row in first],
        "decision_ids": [row["decision_id"] for row in first],
        "unique_observed_first": len(first) == 1,
    }


def join_decisions(
    rows: Sequence[Mapping[str, Any]],
    *,
    authority: Mapping[str, Any],
    action: str,
    accepted_ms: float,
    declared_attempts: Sequence[str],
    observation_complete: bool,
) -> dict[str, object]:
    """Require every declared request; never discard a failed earlier sample."""
    if (
        not finite_time(accepted_ms)
        or not 0 <= accepted_ms < 2**63
        or action not in {"allow", "block"}
        or not 1 <= len(declared_attempts) <= MAX_REQUESTS
        or any(
            not isinstance(value, str) or re.fullmatch(r"mixed-policy-(?:[0-9]|[12][0-9]|3[01])", value) is None
            for value in declared_attempts
        )
        or len(set(declared_attempts)) != len(declared_attempts)
        or len(rows) > MAX_REQUESTS
        or any(not isinstance(row, Mapping) for row in rows)
    ):
        raise ValueError("workspace request join outside declared bounds")
    controls = authority.get("command_controls")
    if not isinstance(controls, Mapping):
        raise ValueError("workspace request join authority invalid")
    reconstructed = authority_projection(
        {
            **authority,
            "command_extensions": {source: controls.get(target) for target, source in _COMMAND_FIELDS.items()},
        }
    )
    if reconstructed != authority:
        raise ValueError("workspace request join authority invalid")
    actual_attempts = [row.get("attempt") for row in rows]
    exact_attempts = (
        len(actual_attempts) == len(declared_attempts)
        and all(isinstance(value, str) for value in actual_attempts)
        and sorted(cast(list[str], actual_attempts)) == sorted(declared_attempts)
    )
    assessed = []
    for row in rows:
        checks = _checks(row, authority, action)
        receipt = row.get("native_receipt")
        native_finished = row.get("native_finished_ms")
        after_acceptance = (
            finite_time(row.get("offered_ms"))
            and finite_time(row.get("review_entered_ms"))
            and row["offered_ms"] >= accepted_ms
            and row["review_entered_ms"] >= accepted_ms
        )
        assessed.append(
            {
                "attempt": row.get("attempt"),
                "workspace_index": row.get("workspace_index"),
                "decision_id": receipt.get("decision_id") if isinstance(receipt, Mapping) else None,
                "request_id": receipt.get("request_id") if isinstance(receipt, Mapping) else None,
                "native_finished_ms": native_finished,
                "request_offered_after_acceptance": after_acceptance,
                "accepted_to_offer_ms": row["offered_ms"] - accepted_ms if finite_time(row.get("offered_ms")) else None,
                "accepted_to_native_finish_ms": native_finished - accepted_ms if finite_time(native_finished) else None,
                "checks": checks,
                "passed": all(checks.values()),
            }
        )
    identities = [row["decision_id"] for row in assessed]
    unique_identities = all(
        isinstance(value, str) and _DIGEST.fullmatch(value) is not None for value in identities
    ) and len(set(identities)) == len(identities)
    request_ids = [row["request_id"] for row in assessed]
    unique_request_ids = all(
        isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,255}", value) for value in request_ids
    ) and len(set(request_ids)) == len(request_ids)
    eligible = [row for row in assessed if row["passed"] and row["native_finished_ms"] >= accepted_ms]
    first_native = _first(eligible)
    first_post_acceptance = _first([row for row in eligible if row["request_offered_after_acceptance"]])
    complete = (
        observation_complete is True
        and exact_attempts
        and unique_identities
        and unique_request_ids
        and all(row["passed"] for row in assessed)
        and first_post_acceptance is not None
        and first_post_acceptance["unique_observed_first"] is True
    )
    return {
        "passed": complete,
        "observation_complete": observation_complete is True,
        "declared_requests": len(declared_attempts),
        "observed_requests": len(rows),
        "exact_attempts": exact_attempts,
        "unique_receipt_identities": unique_identities,
        "unique_native_request_ids": unique_request_ids,
        "rows": assessed,
        "first_native_completion_after_acceptance": first_native,
        "first_completion_of_post_acceptance_request": first_post_acceptance,
        "accepted_ms": accepted_ms,
        "authority": json.loads(json.dumps(authority, allow_nan=False)),
        "timing_scope": "owned Python wrapper endpoints including diagnostic overhead",
        "first_scope": "only the complete declared request set, not all daemon traffic",
        "commit_scope": "validated SQLite readback time, not transaction commit time",
        "lifetime_scope": "same-host wall-clock observations at wrapper boundaries",
        "internal_rust_decision_time_observed": False,
        "qualification_complete": False,
    }
