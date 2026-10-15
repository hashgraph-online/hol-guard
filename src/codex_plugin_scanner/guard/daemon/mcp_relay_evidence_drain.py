"""Record the evidence of MCP tool calls the native relay decided.

The native MCP relay asks the resident to decide each ``tools/call`` it can
answer. For a forward or a block the resident queues what the Python proxy
records for that call: the tool-call identity it built, the policy decision,
the route's decision source and policy action, and the call params with the
arguments in host order. The direct-evidence drain hands each such record to
the same receipt writers the proxy calls, so a relayed call leaves the
receipt and runtime evidence the proxy would have left. A call the proxy
decides only after claiming its saved approval carries the evidence the
post-claim check appended, which follows the decision's own evidence as in
``_allow_and_forward``.

A call the proxy would queue for approval under the ``safe-alternative``
blocked-request mode is blocked by the resident, and its record carries the
receipt redaction level the proxy's config binds. It is recorded as
``_queue_approval_center_response`` records it: the ``policy-safe-alternative``
block receipt with the risk categories of the call projected with its
artifact, then the silent inbox row ``record_unprompted_review`` writes.
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
# The post-claim check's evidence, present only on a claimed call's record.
_APPEND_KEY = "evidence_append"
# The silent inbox row, present only on a safe-alternative block's record.
_REVIEW_KEY = "review"
_OPTIONAL_KEYS = frozenset({_APPEND_KEY, _REVIEW_KEY})
_FORWARD_ACTIONS = frozenset({"allow", "warn"})
_BLOCK_SOURCE = "policy-block"
_SAFE_ALTERNATIVE_SOURCE = "policy-safe-alternative"
_REDACTION_LEVELS = frozenset({"full", "partial", "none"})


def is_mcp_relay_evidence(record: object) -> bool:
    return isinstance(record, Mapping) and record.get("kind") == MCP_TOOL_CALL_EVIDENCE_KIND


def record_mcp_relay_evidence(store: object, guard_home: Path, record: object) -> bool:
    """Record one relayed call as the proxy records it; ``False`` drops it."""

    from ..mcp_tool_calls import allow_tool_call, block_tool_call
    from ..native_mcp_tool_call_identity import _decode  # pyright: ignore[reportPrivateUsage]
    from ..proxy.runtime_mcp_projection import McpCallProjector
    from ..tool_decision_evidence import tool_decision_scanner_evidence

    if not isinstance(record, Mapping) or set(record) - _OPTIONAL_KEYS != _RECORD_KEYS:
        return False
    append = record.get(_APPEND_KEY, [])
    if not isinstance(append, list) or not all(isinstance(item, dict) for item in append):
        return False
    harness, outcome = record["harness"], record["outcome"]
    source, policy_action = record["decision_source"], record["policy_action"]
    tool_name, params = record["tool_name"], record["params"]
    if (
        record["kind"] != MCP_TOOL_CALL_EVIDENCE_KIND
        or harness not in _RELAY_HARNESSES
        or not isinstance(source, str)
        or not isinstance(policy_action, str)
        or not isinstance(tool_name, str)
        or not isinstance(params, dict)
        or params.get("name") != tool_name
    ):
        return False
    # Only a safe-alternative block carries its inbox row, and it must.
    reviewed = _REVIEW_KEY in record
    redaction_level = _redaction_level(record[_REVIEW_KEY]) if reviewed else None
    if reviewed and redaction_level is None:
        return False
    if outcome == "forward":
        if policy_action not in _FORWARD_ACTIONS or reviewed:
            return False
    elif (
        outcome != "block"
        or policy_action in _FORWARD_ACTIONS
        or source != (_SAFE_ALTERNATIVE_SOURCE if reviewed else _BLOCK_SOURCE)
    ):
        return False
    try:
        identity = _decode(record["identity"], expect_hash=True, token=True)
        decision = _decision(record["decision"])
        ordered = _ordered_params(params, record["arguments"])
        artifact = identity.artifact
        if artifact.harness != harness or not isinstance(identity.artifact_hash, str):
            return False
        scanner_evidence = (*tool_decision_scanner_evidence(decision), *append)
        if redaction_level is not None:
            # The proxy projects a queued call with its artifact.
            projection = McpCallProjector(guard_home).project(tool_name, ordered, artifact)
            risk_categories, arguments = projection.risk_categories, projection.safe_arguments
        else:
            projection = None
            risk_categories = decision.risk_categories
            arguments = McpCallProjector(guard_home).project(tool_name, ordered).safe_arguments
        recorded: dict[str, Any] = {
            "store": store,
            "artifact": artifact,
            "artifact_hash": identity.artifact_hash,
            "decision_source": source,
            "now": datetime.now(timezone.utc).isoformat(),
            "signals": decision.signals,
            "risk_categories": risk_categories,
            "arguments": arguments,
            "additional_scanner_evidence": scanner_evidence,
            "policy_action": policy_action,
        }
        if outcome == "forward":
            allow_tool_call(remember=False, **recorded)
        else:
            block_tool_call(**recorded)
        if projection is not None and redaction_level is not None:
            # After the receipt, as the proxy writes them.
            _record_unprompted_review(
                store,
                artifact,
                identity.artifact_hash,
                projection,
                decision.signals,
                policy_action=policy_action,
                scanner_evidence=scanner_evidence,
                redaction_level=redaction_level,
            )
    except Exception:
        # A record the proxy could not have written is dropped, never guessed.
        return False
    return True


def _redaction_level(review: object) -> str | None:
    """The redaction level a safe-alternative block's inbox row is written with."""

    if not isinstance(review, Mapping) or set(review) != {"redaction_level"}:
        return None
    level = review["redaction_level"]
    return level if isinstance(level, str) and level in _REDACTION_LEVELS else None


def _record_unprompted_review(
    store: object,
    artifact: Any,
    artifact_hash: str,
    projection: Any,
    signals: tuple[str, ...],
    *,
    policy_action: str,
    scanner_evidence: tuple[dict[str, object], ...],
    redaction_level: str,
) -> None:
    """The silent inbox row ``_queue_approval_center_response`` leaves.

    ``record_unprompted_review`` keeps the block when the row cannot be
    written, as the proxy does.
    """

    from ..approvals import record_unprompted_review
    from ..models import HarnessDetection
    from ..proxy.runtime_mcp_projection import review_artifact_payload

    record_unprompted_review(
        detection=HarnessDetection(
            harness=artifact.harness,
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        ),
        evaluation={
            "artifacts": [
                review_artifact_payload(
                    projection,
                    artifact,
                    artifact_hash,
                    signals,
                    policy_action=policy_action,
                    scanner_evidence=scanner_evidence,
                )
            ]
        },
        store=store,  # pyright: ignore[reportArgumentType]
        redaction_level=redaction_level,
    )


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
