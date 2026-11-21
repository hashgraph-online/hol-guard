"""Prove a Watch-mode case recorded a correlated native would-have-stopped decision."""

from __future__ import annotations

import re
from typing import Any

from .catalog import WATCH_OUTPUT


def watch_evidence_error(
    case: dict[str, Any], calls: list[dict[str, Any]], by_id: dict[str, list[dict[str, Any]]]
) -> str | None:
    """A plain allow is not proof that Watch recorded a would-have-stopped action."""
    bindings = []
    for key in ("watch_binding_before", "watch_binding_after"):
        binding = case.get(key)
        if (
            not isinstance(binding, dict)
            or binding.get("mode") != "observe"
            or type(binding.get("generation")) is not int
            or binding["generation"] <= 0
            or not isinstance(binding.get("policy_digest"), str)
            or re.fullmatch(r"[0-9a-f]{64}", binding["policy_digest"]) is None
            or not isinstance(binding.get("runtime_identity"), str)
            or re.fullmatch(r"[0-9a-f]{64}", binding["runtime_identity"]) is None
        ):
            return "Watch fixture lacks an authenticated resident policy binding"
        bindings.append(binding)
    before, after = bindings
    if any(before[field] != after[field] for field in ("mode", "generation", "policy_digest", "runtime_identity")):
        return "Watch resident policy binding changed during the command"
    if len(calls) != 1:
        return "Watch requires one actual harmless command"
    result = calls[0].get("result")
    content = result.get("content") if isinstance(result, dict) else None
    if not isinstance(content, list) or not any(
        isinstance(item, dict)
        and item.get("type") == "text"
        and isinstance(item.get("text"), str)
        and WATCH_OUTPUT in item["text"]
        for item in content
    ):
        return "Watch command result lacks the expected fixture output"
    pre = [row for row in by_id[calls[0]["id"]] if row.get("event") == "PreToolUse"]
    observation = pre[0].get("native_observation") if len(pre) == 1 else None
    receipt = observation.get("native_receipt") if isinstance(observation, dict) else None
    if (
        not isinstance(observation, dict)
        or not isinstance(receipt, dict)
        or observation.get("schema") != "hol-guard.transition-hook-observation.v1"
        or observation.get("operation_id") != pre[0].get("probe_operation_id")
        or observation.get("request_id") != pre[0].get("probe_request_id")
        or not isinstance(observation.get("operation_id"), str)
        or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", observation["operation_id"]) is None
        or not isinstance(observation.get("request_id"), str)
        or re.fullmatch(r"transition-hook-[0-9a-f]{32}", observation["request_id"]) is None
        or receipt.get("schema") != "guard-native-hook-decision-receipt.v1"
        or receipt.get("authority") != "rust"
        or type(receipt.get("version")) is not int
        or receipt.get("version") != 1
        or receipt.get("harness") != "omp"
        or receipt.get("event_name") != "PreToolUse"
        or receipt.get("request_id") != observation["request_id"]
        or not isinstance(receipt.get("request_digest"), str)
        or re.fullmatch(r"[0-9a-f]{64}", receipt["request_digest"]) is None
        or type(receipt.get("policy_generation")) is not int
        or receipt.get("policy_generation") != before["generation"]
        or receipt.get("policy_digest") != before["policy_digest"]
        or receipt.get("runtime_identity") != before["runtime_identity"]
        # PreToolUse receipts describe the native hypothetical deny; the resident
        # binding above proves that Watch rendered the deny as a warning/allow.
        or receipt.get("observe_mode") is not False
        or not isinstance(receipt.get("decision_id"), str)
        or re.fullmatch(r"[0-9a-f]{64}", receipt["decision_id"]) is None
        or receipt.get("decision") != "deny"
        or receipt.get("policy_action") not in {"review", "require-reapproval", "sandbox-required", "block"}
        or receipt.get("reason_code") != pre[0].get("reason_code")
        or pre[0].get("decision") != "allow"
        or pre[0].get("policy_action") != "warn"
    ):
        return "Watch lacks a correlated native would-have-stopped receipt and nonblocking response"
    return None
