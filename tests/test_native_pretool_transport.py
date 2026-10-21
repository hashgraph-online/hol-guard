"""Decoder contracts for bounded native pre-tool results."""

import pytest

from codex_plugin_scanner.guard.native_hook_edge import _decode_edge
from codex_plugin_scanner.guard.native_pretool import _decode_pre_tool
from tests.native_pretool_edge_fixtures import _edge, _sync_receipt


@pytest.mark.parametrize("harness", ("claude-code", "codex", "cline", "cursor", "copilot", "grok", "zcode", "devin"))
def test_generic_result_decoder_accepts_supported_harnesses(harness: str) -> None:
    edge = _edge(harness, "PreToolUse", "unknown")
    assert _decode_edge(edge) == edge
    result = edge["result"]
    assert isinstance(result, dict)
    assert _decode_pre_tool(result, command="ignored") == result


@pytest.mark.parametrize("operation", ["set", "read"])
def test_bounded_host_task_metadata_decodes_at_the_transport_edge(operation: str) -> None:
    edge = _edge("claude-code", "PreToolUse", "harness")
    result = edge["result"]
    assert isinstance(result, dict)
    action = result["action"]
    assert isinstance(action, dict)
    action["operation"] = operation
    result.update(
        decision="allow",
        policy_action="allow",
        minimum_action="allow",
        explicitly_benign=True,
        reason_code="native_agent_task_metadata",
    )
    _sync_receipt(edge)
    assert _decode_edge(edge) == edge
    assert _decode_pre_tool(result, command="ignored") == result


def test_generic_result_decoder_rejects_raw_or_conflicting_content() -> None:
    edge = _edge("codex", "PreToolUse", "file_read")
    result = edge["result"]
    assert isinstance(result, dict)
    result["command"] = "must-not-cross-result-boundary"
    assert _decode_edge(edge) is None

    conflicting = _edge("codex", "PreToolUse", "file_read")
    conflicting_result = conflicting["result"]
    assert isinstance(conflicting_result, dict)
    conflicting_result["decision"] = "allow"
    assert _decode_edge(conflicting) is None

    operation_conflict = _edge("codex", "PreToolUse", "file_read")
    operation_result = operation_conflict["result"]
    assert isinstance(operation_result, dict)
    operation_action = operation_result["action"]
    assert isinstance(operation_action, dict)
    operation_action["operation"] = "write"
    assert _decode_edge(operation_conflict) is None

    malformed_type = _edge("codex", "PreToolUse", "unknown")
    malformed_result = malformed_type["result"]
    assert isinstance(malformed_result, dict)
    malformed_result["decision"] = []
    assert _decode_edge(malformed_type) is None


@pytest.mark.parametrize(
    ("action", "decision"),
    (
        ("allow", "allow"),
        ("warn", "allow"),
        ("review", "deny"),
        ("require-reapproval", "deny"),
        ("sandbox-required", "deny"),
        ("block", "deny"),
    ),
)
def test_generic_result_decoder_accepts_complete_policy_action_lattice(
    action: str,
    decision: str,
) -> None:
    edge = _edge("codex", "PreToolUse")
    result = edge["result"]
    assert isinstance(result, dict)
    result.update(
        {
            "decision": decision,
            "policy_action": action,
            "minimum_action": action,
            "reason_code": f"native_policy_{action.replace('-', '_')}",
            "reason": "HOL Guard returned a typed native policy result.",
            "explicitly_benign": action == "allow",
        }
    )
    assert _decode_pre_tool(result, command="ignored") == result
