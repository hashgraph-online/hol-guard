"""The inline approval prompt the relay raises, and the replies it classifies.

Under ``blocked_request_mode = "ask"`` the MCP proxy asks an elicitation-capable
client to approve the exact call before it queues an approval request. The relay
owns the transport, so it raises the same prompt and classifies the same reply,
and its resident routes the result. The shared fixture holds the proxy's request,
the kind each reply classifies into and the block a denial or an invalid answer
produces; the Rust side asserts the same vectors.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.proxy import runtime_mcp

FIXTURE = Path(__file__).parent / "fixtures" / "mcp_relay" / "inline_approval_vectors.json"


def _vectors() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _proxy() -> Any:
    proxy = object.__new__(runtime_mcp.ElicitationMcpGuardProxy)
    proxy.server_name = _vectors()["prompt"]["server"]
    proxy._inline_prompt_counter = 0
    return proxy


@pytest.mark.parametrize("vector", _vectors()["vectors"], ids=lambda vector: str(vector["name"]))
def test_the_fixture_holds_the_kind_the_proxy_classifies(vector: dict[str, Any]) -> None:
    payload = runtime_mcp._approval_payload(vector["response"])

    assert runtime_mcp._inline_approval_kind(payload) == vector["kind"]


def test_the_fixture_holds_the_prompt_the_proxy_raises() -> None:
    prompt = _vectors()["prompt"]

    assert _proxy()._inline_approval_request(prompt["tool"], prompt["summary"]) == prompt["request"]


def test_the_prompt_counter_belongs_to_the_session() -> None:
    prompt = _vectors()["prompt"]
    proxy = _proxy()

    raised = [proxy._inline_approval_request(prompt["tool"], prompt["summary"])["id"] for _ in range(3)]

    assert raised == ["guard-elicitation-1", "guard-elicitation-2", "guard-elicitation-3"]


@pytest.mark.parametrize("block", _vectors()["blocks"], ids=lambda block: str(block["reply"]))
def test_the_fixture_holds_the_block_a_refused_prompt_produces(block: dict[str, Any]) -> None:
    denied: list[dict[str, Any]] = []

    def deny_tool_call(**kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        denied.append(kwargs)
        return {}, {}

    result = _proxy()._inline_approval_deny_result(
        block["payload"], deny_tool_call=deny_tool_call, tool_name=_vectors()["prompt"]["tool"]
    )

    assert result == ({}, {})
    assert denied == [
        {
            "decision_source": block["decision_source"],
            "event_decision": block["event_decision"],
            "reason": block["reason"],
        }
    ]


def test_an_approved_or_unanswered_prompt_is_not_a_block() -> None:
    def deny_tool_call(**_kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        raise AssertionError("an approved or unanswered prompt does not block the call")

    for payload in ({"action": "accept", "content": {"decision": "approve"}}, {"action": "cancel"}):
        assert (
            _proxy()._inline_approval_deny_result(
                payload, deny_tool_call=deny_tool_call, tool_name="delete_secret_file"
            )
            is None
        )


def test_opencode_raises_no_prompt() -> None:
    proxy = object.__new__(runtime_mcp.OpenCodeMcpGuardProxy)

    with pytest.raises(RuntimeError):
        proxy._inline_approval_request("delete_secret_file", "summary")


@pytest.mark.parametrize(
    ("capabilities", "available"),
    [
        ({"elicitation": {}}, True),
        ({"elicitation": {"form": True}}, True),
        ({"elicitation": True}, False),
        ({}, False),
        (None, False),
    ],
)
def test_only_a_declared_elicitation_capability_offers_the_prompt(capabilities: object, available: bool) -> None:
    proxy = _proxy()
    proxy._inline_prompt_available = False

    proxy._record_client_capabilities("initialize", {"capabilities": capabilities})

    assert proxy._inline_prompt_available is available


def test_only_the_initialize_declares_the_capability() -> None:
    proxy = _proxy()
    proxy._inline_prompt_available = False

    proxy._record_client_capabilities("tools/call", {"capabilities": {"elicitation": {}}})
    proxy._record_client_capabilities("initialize", SimpleNamespace(capabilities={"elicitation": {}}))

    assert proxy._inline_prompt_available is False
