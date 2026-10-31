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
