"""Frozen installed Ollama lifecycle outcomes, independent of Python matchers."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from codex_plugin_scanner.guard.native_command_observations import validate_native_command_observations
from codex_plugin_scanner.guard.native_decision_receipt import receipt_matches_edge, validate_native_decision_receipt

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.store import GuardStore

LEGACY_RETRY_SCOPE = "resolved_legacy_approval_does_not_authorize_unknown_executable"
READINESS_PHASES = frozenset(
    {"initial", "enabled", "disabled", "updated", "settings_rollback", "approved_retry", "stale_write_rejected"}
)


@dataclass(frozen=True, slots=True)
class OllamaCase:
    name: str
    command: str
    rule: str | None
    action: str = "review"
    reason: str = "native_command_review_required"
    safe_variant: bool = False
    uncertainty_rule: str | None = None


INACTIVE_CASES = (
    OllamaCase("push_inactive", "ollama push guard-fixture-model", None),
    OllamaCase("rm_inactive", "ollama rm guard-fixture-model", None),
)
ACTIVE_CASES = (
    OllamaCase("push", "ollama push guard-fixture-model", "command.ollama.push"),
    OllamaCase("rm", "ollama rm guard-fixture-model", "command.ollama.rm"),
    OllamaCase("windows_exe", "ollama.exe push guard-fixture-model", "command.ollama.push"),
    OllamaCase("windows_cmd", "ollama.cmd rm guard-fixture-model", "command.ollama.rm"),
    OllamaCase("push_help", "ollama push --help", "command.ollama.push", safe_variant=True),
    OllamaCase("rm_help", "ollama rm --help", "command.ollama.rm", safe_variant=True),
    OllamaCase(
        "independent_floor",
        "ollama push guard-fixture-model && rm -rf /",
        "command.ollama.push",
        action="block",
        reason="native_destructive_command",
        uncertainty_rule="command.shell-mutations.destructive-shell",
    ),
)
RESTRICTED_CASES = (
    OllamaCase(
        "push_permission_disabled",
        "ollama push guard-fixture-model",
        "command.ollama.push",
        action="block",
        reason="native_command_permission_disabled",
    ),
    ACTIVE_CASES[1],
)


def require(condition: object, reason: str) -> None:
    if not condition:
        raise AssertionError("installed_ollama_" + reason)


def validated_build_sha(value: object) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None, "build_sha_invalid")
    return cast(str, value)


def review_payload(workspace: Path, case: OllamaCase) -> dict[str, object]:
    """Keep a strong native correlation separate from the report's phase label."""
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": case.command},
        "tool_use_id": "ollama-fixture-" + secrets.token_hex(16),
        "cwd": str(workspace),
    }


def payload_digest(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def require_same_ack(before: Mapping[str, object], current: Mapping[str, object]) -> None:
    require(
        all(
            field in before and field in current and before[field] == current[field]
            for field in ("generation", "policy_digest", "runtime_identity", "command_extensions")
        ),
        "legacy_retry_ack_changed",
    )


def validate_legacy_retry(
    store: GuardStore,
    prior_id: str,
    next_id: str | None,
    first: Mapping[str, object],
    retry: Mapping[str, object],
) -> dict[str, object]:
    """Require a new durable review for the identical request and native binding."""
    require(next_id is not None and next_id != prior_id, "legacy_retry_did_not_queue_distinct_review")
    prior = store.get_approval_request(prior_id)
    pending = store.get_approval_request(cast(str, next_id))
    require(
        prior is not None and prior.get("status") == "resolved" and prior.get("resolution_action") == "allow",
        "legacy_resolution_not_preserved",
    )
    require(
        pending is not None and pending.get("status") == "pending" and pending.get("harness") == "claude-code",
        "legacy_retry_review_not_durable",
    )
    require(
        all(
            field in first and field in retry and first[field] is not None and first[field] == retry[field]
            for field in (
                "hook_envelope_digest",
                "request_digest",
                "policy_generation",
                "policy_digest",
                "control_revision",
                "observations_digest",
            )
        ),
        "legacy_retry_request_or_authority_changed",
    )
    require(
        retry.get("legacy_approval_reused") is False
        and retry.get("approval_durable") is True
        and retry.get("action") == "review",
        "legacy_retry_did_not_remain_review",
    )
    return {
        "approval_retry_scope": LEGACY_RETRY_SCOPE,
        "prior_resolution_preserved": True,
        "distinct_pending_review": True,
        "same_hook_envelope": True,
        "same_native_request_and_policy": True,
    }


def validate_review(
    case: OllamaCase,
    edge: Mapping[str, object],
    response: Mapping[str, object],
    *,
    expected_binding: Mapping[str, object],
) -> dict[str, object]:
    """Require exact native attribution, binding, floor and delivered decision."""
    require(edge.get("authority") == "rust", "authority_mismatch")
    receipt = validate_native_decision_receipt(edge.get("receipt"))
    require(receipt is not None and receipt_matches_edge(edge, receipt), "receipt_mismatch")
    result = edge.get("result")
    require(isinstance(result, Mapping), "result_missing")
    result = cast(Mapping[str, object], result)
    observations = validate_native_command_observations(result.get("command_extensions"))
    require(observations is not None, "observations_missing")
    observations = cast(dict[str, object], observations)
    binding = cast(Mapping[str, object], observations["binding"])
    require(all(binding.get(key) == value for key, value in expected_binding.items()), "binding_mismatch")
    require(observations["evaluation_error"] is None, "evaluation_failed")
    uncertain = [
        item for item in cast(list[dict[str, object]], observations["observations"]) if item["uncertainty_reasons"]
    ]
    if case.uncertainty_rule is None:
        require(binding.get("uncertainty_count") == 0, "evaluation_uncertain")
    else:
        require(binding.get("uncertainty_count") == 1 and len(uncertain) == 1, "uncertainty_count_mismatch")
        require(
            uncertain[0]["extension_id"] == "command.shell-mutations"
            and uncertain[0]["rule_id"] == case.uncertainty_rule
            and uncertain[0]["uncertainty_reasons"] == ["matcher-failure"]
            and uncertain[0]["effective_segment_indexes"] == [1]
            and uncertain[0]["matcher_evidence"]
            == [{"segment_index": 1, "executable": "rm", "detail": "Matched bounded structured command constraints."}],
            "uncertainty_owner_mismatch",
        )
    owned = [
        item
        for item in cast(list[dict[str, object]], observations["observations"])
        if item["extension_id"] == "command.ollama"
    ]
    if case.rule is None:
        require(not owned, "inactive_extension_executed")
    else:
        require(len(owned) == 1 and owned[0]["rule_id"] == case.rule, "rule_mismatch")
        require(owned[0]["extension_version"] == "1.0.0" and owned[0]["rule_version"] == "1.0.0", "version_mismatch")
        require(owned[0]["effective_segment_indexes"] == ([] if case.safe_variant else [0]), "evidence_mismatch")
        if case.safe_variant:
            require(
                any(
                    variant["variant_id"] == "help"
                    for variant in cast(list[dict[str, object]], owned[0]["safe_variants"])
                ),
                "safe_variant_missing",
            )
    require(
        result.get("decision") == "deny"
        and result.get("minimum_action") == case.action
        and result.get("policy_action") == case.action
        and result.get("reason_code") == case.reason,
        "native_floor_mismatch",
    )
    specific = response.get("hookSpecificOutput")
    delivered_permission = "ask" if case.action == "review" else "deny"
    require(
        isinstance(specific, Mapping)
        and specific.get("hookEventName") == "PreToolUse"
        and specific.get("permissionDecision") == delivered_permission
        and response.get("policy_action") == case.action
        and response.get("reason_code") == case.reason,
        "delivered_decision_mismatch",
    )
    require("approval_reuse_status" not in response, "legacy_approval_reused")
    if case.action == "review":
        require(
            isinstance(response.get("approval_request_id"), str) and response["approval_request_id"], "approval_missing"
        )
    else:
        require("approval_request_id" not in response, "block_became_review")
    return cast(dict[str, object], receipt)
