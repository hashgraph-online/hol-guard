"""Record the evidence of MCP tool calls the native relay decided.

The native MCP relay asks the resident to decide each ``tools/call`` it can
answer. For a forward or a block the resident queues what the Python proxy
records for that call: the tool-call identity it built, the policy decision,
the route's decision source and policy action, and the call params with the
arguments in host order. The direct-evidence drain hands each such record to
the same receipt writers the proxy calls, so a relayed call leaves the
receipt and runtime evidence the proxy would have left.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MCP_TOOL_CALL_EVIDENCE_KIND = "mcp_tool_call"
# The harnesses whose MCP proxy the relay replaces.
_RELAY_HARNESSES = frozenset({"codex", "copilot", "cursor", "opencode"})
_RECORD_KEYS = frozenset(
    {
        "kind",
        "harness",
        "outcome",
        "decision_source",
        "policy_action",
        "tool_name",
        "params",
        "arguments",
        "identity",
        "decision",
    }
)
_FORWARD_ACTIONS = frozenset({"allow", "warn"})
_BLOCK_SOURCE = "policy-block"


def is_mcp_relay_evidence(record: object) -> bool:
    return isinstance(record, Mapping) and record.get("kind") == MCP_TOOL_CALL_EVIDENCE_KIND


def record_mcp_relay_evidence(store: object, guard_home: Path, record: object) -> bool:
    """Record one relayed call as the proxy records it; ``False`` drops it."""

    from ..mcp_tool_calls import allow_tool_call, block_tool_call
    from ..native_mcp_tool_call_identity import _decode  # pyright: ignore[reportPrivateUsage]
    from ..proxy.runtime_mcp_projection import McpCallProjector
    from ..tool_decision_evidence import tool_decision_scanner_evidence

    if not isinstance(record, Mapping) or set(record) != _RECORD_KEYS:
        return False
    harness, outcome = record["harness"], record["outcome"]
    source, policy_action = record["decision_source"], record["policy_action"]
    tool_name, params = record["tool_name"], record["params"]
    if (
        record["kind"] != MCP_TOOL_CALL_EVIDENCE_KIND
        or harness not in _RELAY_HARNESSES
        or not isinstance(source, str)
        or not isinstance(tool_name, str)
        or not isinstance(params, dict)
        or params.get("name") != tool_name
    ):
        return False
    if outcome == "forward":
        if policy_action not in _FORWARD_ACTIONS:
            return False
    elif outcome != "block" or source != _BLOCK_SOURCE or policy_action in _FORWARD_ACTIONS:
        return False
    try:
        identity = _decode(record["identity"], expect_hash=True, token=True)
        decision = _decision(record["decision"])
        ordered = _ordered_params(params, record["arguments"])
        artifact = identity.artifact
        if artifact.harness != harness or not isinstance(identity.artifact_hash, str):
            return False
        arguments = McpCallProjector(guard_home).project(tool_name, ordered).safe_arguments
        recorded: dict[str, Any] = {
            "store": store,
            "artifact": artifact,
            "artifact_hash": identity.artifact_hash,
            "decision_source": source,
            "now": datetime.now(timezone.utc).isoformat(),
            "signals": decision.signals,
            "risk_categories": decision.risk_categories,
            "arguments": arguments,
            "additional_scanner_evidence": tool_decision_scanner_evidence(decision),
            "policy_action": policy_action,
        }
        if outcome == "forward":
            allow_tool_call(remember=False, **recorded)
        else:
            block_tool_call(**recorded)
    except Exception:
        # A record the proxy could not have written is dropped, never guessed.
        return False
    return True


def _decision(value: object) -> Any:
    """The ``ToolCallDecision`` of a native decision without a fresh authority."""

    from ..mcp_tool_calls import ToolCallDecision
    from ..native_mcp_tool_policy import _validated_decision  # pyright: ignore[reportPrivateUsage]

    payload = _validated_decision(value)
    if payload["post_claim_authority"] is not None:
        raise ValueError("mcp_relay_evidence_fresh_authority")
    return ToolCallDecision(
        action=payload["action"],
        source=payload["source"],
        signals=tuple(payload["signals"]),
        summary=payload["summary"],
        risk_categories=tuple(payload["risk_categories"]),
        normalization_reason_code=payload["normalization_reason_code"],
        original_action=payload["original_action"],
        approval_reuse_status=payload["approval_reuse_status"],
        approval_reuse_reason_code=payload["approval_reuse_reason_code"],
        current_action=payload["current_action"],
        saved_action=payload["saved_action"],
        pending_approval_reuse_decision=payload["pending_approval_reuse_decision"],
        approval_reuse_claim_disposition=payload["approval_reuse_claim_disposition"],
        post_claim_revalidated=payload["post_claim_revalidated"],
    )


def _ordered_params(params: dict[str, object], arguments: object) -> dict[str, object]:
    """The params with a mapping's arguments back in host key order."""

    if not isinstance(arguments, dict) or arguments.get("format") != "mapping":
        return params
    entries = arguments.get("entries")
    current = params.get("arguments")
    if not isinstance(entries, list) or not isinstance(current, dict):
        raise ValueError("mcp_relay_evidence_arguments_invalid")
    pairs = [entry for entry in entries if isinstance(entry, list) and len(entry) == 2 and isinstance(entry[0], str)]
    ordered = {key: value for key, value in pairs}
    if len(pairs) != len(entries) or ordered != current:
        raise ValueError("mcp_relay_evidence_arguments_invalid")
    return {**params, "arguments": ordered}
