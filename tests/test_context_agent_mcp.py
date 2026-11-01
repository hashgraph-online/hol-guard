"""Private transport/discovery framing. Actual SDK authority is tested natively."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp.server.fastmcp import FastMCP

from codex_plugin_scanner.guard import native_context_agent as transport
from codex_plugin_scanner.guard.mcp.registry import build_tool_registry
from codex_plugin_scanner.guard.mcp.server import GuardMCPServer, _create_annotations
from codex_plugin_scanner.guard.native_context_assistance import ContextAssistanceError


@pytest.fixture
def native(monkeypatch, tmp_path):
    calls = []
    state = {"available": False, "authorized": False, "fail_begin": False}

    def decide(query, _home, _fields, validate, **kwargs):
        assert kwargs["operation"].operation == "context_agent"
        calls.append(query["input"])
        message = query["input"]
        action = message["action"]
        if action == "discover":
            result = {"available": state["available"], "tools": []}
        elif action == "begin":
            if state["fail_begin"]:
                raise ContextAssistanceError("native_context_assistance_unavailable")
            result = {"credential": "f" * 64, "session_id": "agent:public", "phase": "pending"}
        elif action == "status":
            result = {
                "phase": "authorized" if state["authorized"] else "pending",
                "session_id": "agent:public",
                "tools": list(transport.CONTEXT_TOOLS) if state["authorized"] else ["get_context_status"],
            }
        else:
            raise ContextAssistanceError("native_context_assistance_context_scope_denied")
        answer = {"kind": "agent", "data": {"schema": "guard-cigar-agent-data.v1", "data_role": True, "result": result}}
        validate(answer)
        return answer

    monkeypatch.setattr(transport, "_resolve_digest_home", lambda home: home)
    monkeypatch.setattr(transport, "_decide", decide)
    return transport.NativeContextAgent(tmp_path), state, calls


def test_off_discovery_does_not_begin_and_private_credential_never_becomes_a_tool_argument(native):
    client, state, calls = native
    assert client.tool_names() == ()
    assert [call["action"] for call in calls] == ["discover"]
    state["available"] = True
    assert client.tool_names() == ("get_context_status",)
    assert "f" * 64 not in json.dumps(client.call("get_context_status", {}))
    state["authorized"] = True
    assert client.tool_names() == transport.CONTEXT_TOOLS
    with pytest.raises(ContextAssistanceError):
        client.call("get_guard_context", {"query": "x", "app": "forged", "credential": "caller"})
    assert calls[-1]["credential"] == "f" * 64
    assert calls[-1]["arguments"] == {"query": "x", "app": "forged", "credential": "caller"}
    state["available"] = False
    assert client.tool_names() == ()


def test_unknown_begin_outcome_does_not_blindly_issue_another_session(native):
    client, state, calls = native
    state.update(available=True, fail_begin=True)
    assert client.tool_names() == ()
    assert client.tool_names() == ()
    assert sum(call["action"] == "begin" for call in calls) == 1


def test_direct_cached_calls_are_refused_and_context_never_opens_the_general_store(native, monkeypatch, tmp_path):
    client, state, _ = native
    server = GuardMCPServer(tmp_path)
    server._context_agent = client

    def unexpected_store(_self):
        raise AssertionError("context tools cannot open the general Guard store")

    monkeypatch.setattr(GuardMCPServer, "store", property(unexpected_store))
    state["available"] = True
    data = json.loads(server.call_tool("get_context_status", {}).text)
    assert data["data"]["phase"] == "pending"
    assert "credential" not in json.dumps(data)
    refused = json.loads(server.call_tool("get_guard_context", {"query": "x"}).text)
    assert refused["ok"] is False
    assert refused["data_role"] is True
    assert refused["error"]["code"] == "native_context_assistance_context_scope_denied"
    assert "f" * 64 not in json.dumps(refused)


def test_shared_registry_and_fastmcp_resolve_all_context_schemas(tmp_path: Path):
    server = GuardMCPServer(tmp_path)
    mcp = FastMCP("context-contract")
    definitions = build_tool_registry(context_tools=transport.CONTEXT_TOOLS)
    assert len(definitions) == 13
    for definition in definitions:
        server._register_fastmcp_tool(mcp, definition, definition.description, _create_annotations())
    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    for name in transport.CONTEXT_TOOLS:
        assert tools[name].outputSchema is None
        schema = tools[name].inputSchema
        assert "credential" not in json.dumps(schema)
        assert "app" not in schema.get("properties", {})
        assert "workspace" not in schema.get("properties", {})
        assert "ctx" not in schema.get("properties", {})
    action_schema = tools["explain_guard_action"].inputSchema
    assert action_schema["required"] == ["decision_id"]
    assert set(action_schema["properties"]) == {"decision_id", "snapshot_id"}
    note_schema = tools["propose_guard_context_note"].inputSchema
    assert set(note_schema["required"]) == {"snapshot_id", "request_key", "text"}
    registry = {definition.name: definition for definition in definitions}
    assert registry["propose_guard_context_note"].annotations.read_only is False
    assert registry["forget_guard_context_proposal"].annotations.destructive is True


def test_native_action_arguments_keep_private_credentials_and_pass_all_fields_for_native_validation(native):
    client, state, calls = native
    state.update(available=True, authorized=True)
    assert "explain_guard_action" in client.tool_names()
    arguments = {"decision_id": "d" * 64, "workspace": "/forged", "credential": "caller"}
    with pytest.raises(ContextAssistanceError):
        client.call("explain_guard_action", arguments)
    assert calls[-1]["action"] == "review_action"
    assert calls[-1]["credential"] == "f" * 64
    assert calls[-1]["arguments"] == arguments


@pytest.mark.parametrize("agent", [False, True])
def test_bound_busy_keeps_default_transport_health_success(monkeypatch, tmp_path, agent):
    from codex_plugin_scanner.guard import native_context_assistance, native_resident_decision

    original = transport._OPERATION if agent else native_context_assistance._OPERATION
    spec = replace(original, shared_resident_health=True)
    health = []
    monkeypatch.setattr(native_resident_decision, "_resolve_digest_home", lambda _: tmp_path)
    monkeypatch.setattr(native_resident_decision, "ensure_resident_prerequisite", lambda _: True)
    monkeypatch.setattr(native_resident_decision, "_canonical_request_sha256", lambda _: "d" * 64)
    monkeypatch.setattr(native_resident_decision, "native_runtime_status", lambda: None)
    monkeypatch.setattr(native_resident_decision, "record_resident", lambda _home, **kwargs: health.append(kwargs))

    def reply(**kwargs):
        return {
            "schema": spec.result_schema,
            "request_id": kwargs["request"]["request_id"],
            "request_sha256": "sha256:" + "d" * 64,
            "status": "error",
            "code": "native_context_assistance_busy",
            "payload": None,
        }

    for _ in range(3):
        with pytest.raises(ContextAssistanceError, match=r"^native_context_assistance_busy$"):
            native_resident_decision.resident_decide(
                spec,
                reply,
                {"kind": "agent" if agent else "workspace"},
                tmp_path,
                lambda _: pytest.fail("a capacity refusal cannot return context"),
            )
    assert len(health) == 3
    assert all(event["success"] is True for event in health)


@pytest.mark.parametrize("agent", [False, True])
@pytest.mark.parametrize("outcome", ["missing", "unbound", "busy"])
def test_optional_transport_refusals_never_change_the_shared_hook_health_circuit(monkeypatch, tmp_path, agent, outcome):
    from codex_plugin_scanner.guard import native_context_assistance, native_execution, native_resident_decision

    spec = transport._OPERATION if agent else native_context_assistance._OPERATION
    assert spec.shared_resident_health is False
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "not-executed", sha256="a" * 64),
        capabilities=SimpleNamespace(features=["resident-protocol-v2", spec.feature]),
    )
    monkeypatch.setattr(native_resident_decision, "_resolve_digest_home", lambda _: tmp_path)
    monkeypatch.setattr(native_resident_decision, "ensure_resident_prerequisite", lambda _: True)
    monkeypatch.setattr(native_resident_decision, "_canonical_request_sha256", lambda _: "d" * 64)
    monkeypatch.setattr(native_resident_decision, "native_runtime_status", lambda: status)
    monkeypatch.setattr(native_execution, "_isolated_environment", lambda: {})

    def unexpected_health(*_args, **_kwargs):
        pytest.fail("an optional context request changed the shared Guard health circuit")

    monkeypatch.setattr(native_resident_decision, "record_resident", unexpected_health)
    monkeypatch.setattr(native_execution, "native_record_resident_failure", unexpected_health)
    monkeypatch.setattr(native_execution, "native_record_resident_success", unexpected_health)

    def client(**kwargs):
        if outcome == "missing":
            return None
        if outcome == "unbound":
            return b'{"schema":"wrong-result"}'
        request = json.loads(kwargs["payload"])["request"]
        return json.dumps(
            {
                "schema": spec.result_schema,
                "request_id": request["request_id"],
                "request_sha256": "sha256:" + "d" * 64,
                "status": "error",
                "code": "native_context_assistance_busy",
                "payload": None,
            }
        ).encode()

    monkeypatch.setattr(native_execution, "native_resident_client_request", client)
    for _ in range(3):
        with pytest.raises(ContextAssistanceError):
            native_resident_decision.resident_decide(
                spec,
                native_execution._resident_request,
                {"kind": "agent" if agent else "workspace"},
                tmp_path,
                lambda _: pytest.fail("an unavailable context was accepted"),
            )
