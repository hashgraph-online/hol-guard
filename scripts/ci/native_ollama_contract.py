"""Frozen installed Ollama lifecycle outcomes, independent of Python matchers."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from codex_plugin_scanner.guard.native_command_observations import validate_native_command_observations
from codex_plugin_scanner.guard.native_decision_receipt import receipt_matches_edge, validate_native_decision_receipt


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


def validate_review(
    case: OllamaCase,
    edge: Mapping[str, object],
    response: Mapping[str, object],
    *,
    expected_binding: Mapping[str, object],
    approval_reused: bool = False,
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
    require(not approval_reused or case.action == "review", "approval_bypassed_native_block")
    delivered_action = "allow" if approval_reused else case.action
    delivered_permission = "allow" if approval_reused else "ask" if case.action == "review" else "deny"
    require(
        isinstance(specific, Mapping)
        and specific.get("hookEventName") == "PreToolUse"
        and specific.get("permissionDecision") == delivered_permission
        and response.get("policy_action") == delivered_action
        and response.get("reason_code") == case.reason,
        "delivered_decision_mismatch",
    )
    if case.action == "review" and not approval_reused:
        require(
            isinstance(response.get("approval_request_id"), str) and response["approval_request_id"], "approval_missing"
        )
        require("approval_reuse_status" not in response, "stale_approval_reused")
    else:
        require("approval_request_id" not in response, "block_became_review")
    if approval_reused:
        require(response.get("approval_reuse_status") == "accepted", "legacy_approval_not_reused")
    return cast(dict[str, object], receipt)
