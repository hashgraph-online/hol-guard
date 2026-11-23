"""An MCP review held only because Guard never saw the server names it for setup.

The native decision carries ``connector_setup`` only for a non-recognition
review; the proxy groups the queued row under the server's ``connector:``
marker, answers the agent with the shared connector-setup copy and marks the
response with its own reason code. Receipt events keep the review taxonomy.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls, native_approval_errors
from codex_plugin_scanner.guard.mcp_tool_calls import RUNTIME_TOOL_CALL_CONNECTOR_SETUP_REQUIRED
from codex_plugin_scanner.guard.native_mcp_tool_policy import (
    NativeMcpToolPolicyError,
    _validated_decision,  # pyright: ignore[reportPrivateUsage]
)

IDENTITY = "5d0a8f3b9c2e47a1b6d4c8e2f0a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7"
CONNECTOR = {
    "reason_code": "connector_setup_required",
    "identity_hash": IDENTITY,
    "surface": "mcp",
    "name": "echo-mcp",
    "queue_group_id": f"connector:{IDENTITY}",
}
ARTIFACT = SimpleNamespace(
    harness="codex",
    artifact_id="codex:project:echo-mcp:lookup",
    name="echo-mcp:lookup",
    artifact_type="mcp_tool_call",
    source_scope="project",
    config_path="config.toml",
)


def _wire(**fields: object) -> dict[str, object]:
    return {
        "action": "review",
        "policy_action": "review",
        "source": "policy",
        "signals": [],
        "summary": "summary",
        "risk_categories": [],
        "normalization_reason_code": None,
        "original_action": None,
        "approval_reuse_status": None,
        "approval_reuse_reason_code": None,
        "current_action": None,
        "saved_action": None,
        "pending_approval_reuse_decision": None,
        "approval_reuse_claim_disposition": None,
        "post_claim_revalidated": False,
        "post_claim_authority": None,
        **fields,
    }


def test_reason_code_is_agent_facing_not_an_event_or_refusal() -> None:
    assert RUNTIME_TOOL_CALL_CONNECTOR_SETUP_REQUIRED == "runtime_tool_call_connector_setup_required"
    events = {event for event, _ in mcp_tool_calls._NON_EXECUTED_TOOL_CALL_TAXONOMY.values()}  # pyright: ignore[reportPrivateUsage]
    assert RUNTIME_TOOL_CALL_CONNECTOR_SETUP_REQUIRED not in events
    assert RUNTIME_TOOL_CALL_CONNECTOR_SETUP_REQUIRED not in native_approval_errors.FINITE_FAILURE_CODES
    frame = {"error": RUNTIME_TOOL_CALL_CONNECTOR_SETUP_REQUIRED, "retryable": False}
    assert native_approval_errors.resident_refusal_code(frame) is None


def test_a_decision_may_name_a_connector() -> None:
    assert _validated_decision(_wire())["action"] == "review"
    assert _validated_decision(_wire(connector_setup=dict(CONNECTOR)))["connector_setup"] == CONNECTOR
    assert _validated_decision(_wire(connector_setup={**CONNECTOR, "name": None}))["connector_setup"]["name"] is None


@pytest.mark.parametrize(
    "connector",
    [
        None,
        {**CONNECTOR, "reason_code": "other"},
        {**CONNECTOR, "identity_hash": IDENTITY.upper()},
        {**CONNECTOR, "surface": "cli"},
        {**CONNECTOR, "name": 7},
        {**CONNECTOR, "queue_group_id": f"connector:{'0' * 64}"},
        {**CONNECTOR, "url": "https://mcp.example.test/mcp"},
        {key: value for key, value in CONNECTOR.items() if key != "name"},
    ],
)
def test_a_malformed_connector_fails_the_decision_closed(connector: object) -> None:
    with pytest.raises(NativeMcpToolPolicyError, match="payload_invalid"):
        _validated_decision(_wire(connector_setup=connector))


@pytest.mark.parametrize(
    "fields",
    [
        {"action": "block", "policy_action": "block"},
        {"policy_action": "require-reapproval"},
        {"signals": ["network"]},
        {"risk_categories": ["destructive_operation"]},
        {"source": "local-mcp-extension"},
        {"source": "temporary-mcp-grant"},
        {"approval_reuse_claim_disposition": "consumed"},
        {"pending_approval_reuse_decision": {"state": "pending"}},
        {"post_claim_revalidated": True, "post_claim_authority": "fresh"},
    ],
)
def test_connector_setup_does_not_recompute_the_native_decision(fields: dict[str, object]) -> None:
    decision = _validated_decision(_wire(connector_setup=dict(CONNECTOR), **fields))
    assert decision["connector_setup"] == CONNECTOR


def test_a_heuristic_review_may_name_a_connector() -> None:
    decision = _validated_decision(_wire(source="heuristic", connector_setup=dict(CONNECTOR)))
    assert decision["connector_setup"] == CONNECTOR
