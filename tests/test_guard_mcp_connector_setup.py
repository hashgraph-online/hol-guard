"""An MCP review held only because Guard never saw the server names it for setup.

The native decision carries ``connector_setup`` only for a non-recognition
review; the proxy groups the queued row under the server's ``connector:``
marker, answers the agent with the shared connector-setup copy and marks the
response with its own reason code. Receipt events keep the review taxonomy.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import approvals, mcp_tool_calls, native_approval_errors
from codex_plugin_scanner.guard.mcp_tool_calls import RUNTIME_TOOL_CALL_CONNECTOR_SETUP_REQUIRED
from codex_plugin_scanner.guard.native_mcp_tool_policy import (
    NativeMcpToolPolicyError,
    _validated_decision,  # pyright: ignore[reportPrivateUsage]
)
from codex_plugin_scanner.guard.proxy import runtime_mcp
from codex_plugin_scanner.guard.proxy.runtime_mcp_projection import connector_agent_text, review_artifact_payload

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
def test_a_connector_on_a_decision_nothing_but_non_recognition_caused_is_rejected(fields: dict[str, object]) -> None:
    with pytest.raises(NativeMcpToolPolicyError, match="payload_invalid"):
        _validated_decision(_wire(connector_setup=dict(CONNECTOR), **fields))


def test_a_heuristic_review_may_name_a_connector() -> None:
    decision = _validated_decision(_wire(source="heuristic", connector_setup=dict(CONNECTOR)))
    assert decision["connector_setup"] == CONNECTOR


def _projection() -> SimpleNamespace:
    return SimpleNamespace(
        display_launch_target="echo-mcp:lookup",
        risk_summary="",
        browser_intent=None,
        risk_categories=(),
        safe_arguments={},
        safe_params={"name": "lookup"},
    )


def test_the_review_row_joins_the_connector_group_only_when_named() -> None:
    plain = review_artifact_payload(_projection(), ARTIFACT, "sha256:h", (), policy_action="review")
    grouped = review_artifact_payload(
        _projection(), ARTIFACT, "sha256:h", (), policy_action="review", connector_setup=CONNECTOR
    )
    assert "queue_group_id" not in plain
    assert grouped == {**plain, "queue_group_id": f"connector:{IDENTITY}"}


def test_agent_text_names_a_plain_server_and_never_asks_in_default_mode() -> None:
    default = connector_agent_text(CONNECTOR, ask=False)
    assert "`echo-mcp` (MCP server)" in default
    assert "http" not in default and "ask the user" not in default.lower()
    assert "`this MCP server`" in connector_agent_text({**CONNECTOR, "name": "evil`\nname"}, ask=False)
    assert "`this MCP server`" in connector_agent_text({**CONNECTOR, "name": None}, ask=True)


class _Projector:
    def project(self, tool_name: str, params: object, artifact: object = None) -> SimpleNamespace:
        return _projection()


def _proxy(mode: str) -> Any:
    proxy = object.__new__(runtime_mcp.RuntimeMcpGuardProxy)
    proxy.config = SimpleNamespace(blocked_request_mode=mode, receipt_redaction_level="partial")
    proxy.store = object()
    proxy.harness = "codex"
    proxy.server_name = "echo-mcp"
    proxy.config_path = ARTIFACT.config_path
    proxy._call_projector = _Projector()
    return proxy


def _answer(proxy: Any, connector: dict[str, object] | None) -> dict[str, Any]:
    response, _event = proxy._queue_approval_center_response(
        message_id=3,
        artifact=ARTIFACT,
        artifact_hash="sha256:h",
        tool_name="lookup",
        signals=(),
        params={"name": "lookup", "arguments": {}},
        policy_action="review",
        connector_setup=connector,
    )
    return response["error"]


def test_default_mode_answers_with_setup_copy_and_a_grouped_silent_row(monkeypatch: pytest.MonkeyPatch) -> None:
    rows: list[dict[str, Any]] = []
    monkeypatch.setattr(runtime_mcp, "block_tool_call", lambda **_kwargs: None)
    monkeypatch.setattr(approvals, "record_unprompted_review", lambda **kwargs: rows.append(kwargs))

    error = _answer(_proxy("safe-alternative"), CONNECTOR)

    assert error["message"] == connector_agent_text(CONNECTOR, ask=False)
    assert error["data"]["guardReasonCode"] == RUNTIME_TOOL_CALL_CONNECTOR_SETUP_REQUIRED
    assert "reviewUrl" not in error["data"]
    [item] = rows[0]["evaluation"]["artifacts"]
    assert item["queue_group_id"] == f"connector:{IDENTITY}"

    generic = _answer(_proxy("safe-alternative"), None)
    assert "guardReasonCode" not in generic["data"]
    assert "queue_group_id" not in rows[1]["evaluation"]["artifacts"][0]


def test_ask_mode_queues_the_grouped_row_and_links_it(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    queued: list[dict[str, Any]] = []

    def queue(**kwargs: Any) -> list[dict[str, object]]:
        queued.append(kwargs)
        return [{"request_id": "req-1", "approval_url": "http://127.0.0.1:1/approvals/req-1"}]

    monkeypatch.setattr(runtime_mcp, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:1")
    monkeypatch.setattr(runtime_mcp, "queue_blocked_approvals", queue)
    monkeypatch.setattr(runtime_mcp, "block_tool_call", lambda **_kwargs: None)
    proxy = _proxy("ask")
    proxy.context = SimpleNamespace(guard_home=tmp_path)
    proxy._maybe_open_approval_center = lambda **_kwargs: None

    error = _answer(proxy, CONNECTOR)

    assert error["message"].startswith(connector_agent_text(CONNECTOR, ask=True))
    assert error["data"]["guardReasonCode"] == RUNTIME_TOOL_CALL_CONNECTOR_SETUP_REQUIRED
    [item] = queued[0]["evaluation"]["artifacts"]
    assert item["queue_group_id"] == f"connector:{IDENTITY}"
