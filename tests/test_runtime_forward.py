"""The context CLI and MCP tools only carry data to and from the native runtime."""

from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_recovery_store
from codex_plugin_scanner.guard.cli import runtime_forward
from codex_plugin_scanner.guard.config import resolve_guard_home
from codex_plugin_scanner.guard.mcp import native_tools
from codex_plugin_scanner.guard.mcp.server import GuardMCPServer

_TOOL = {
    "name": "get_context_status",
    "description": "Read this connection's native context status.",
    "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    "annotations": {"read_only": True, "destructive": False, "idempotent": True, "open_world": False},
}


@pytest.fixture
def runtime(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    def fake_run(argv: list[str], **kwargs: object) -> SimpleNamespace:
        request = json.loads(kwargs["input"]) if kwargs.get("input") else None
        calls.append({"argv": list(argv), "request": request})
        if argv[1] == "context":
            return SimpleNamespace(returncode=3, stdout=b"from runtime\n")
        op = request["op"]
        session = {"credential": "c" * 64, "started": True}
        if op == "catalog":
            answer: dict[str, object] = {"tools": [_TOOL]}
        elif op == "tools":
            answer = {"session": session, "tools": [_TOOL]}
        elif op == "call":
            answer = {"session": session, "known": True, "text": '{"ok":true}'}
        else:
            answer = {"session": {"credential": None, "started": True}}
        return SimpleNamespace(returncode=0, stdout=json.dumps(answer).encode())

    monkeypatch.setattr(native_recovery_store, "recovery_runtime_path", lambda feature: f"/runtime/{feature}")
    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_cli_hands_every_argument_and_the_resolved_home_to_the_runtime(runtime, tmp_path: Path) -> None:
    args = SimpleNamespace(
        runtime_command="context",
        guard_home=None,
        json=True,
        forward_help=False,
        forward_args=["switch", "--guard-home", str(tmp_path), "--job-id", "j", "cigar-1"],
    )
    out = io.StringIO()
    assert runtime_forward.run_forward(args, output_stream=out) == 3
    assert out.getvalue() == "from runtime\n"
    argv = runtime[0]["argv"]
    assert argv[0] == f"/runtime/{runtime_forward.FEATURE}" and argv[1] == "context"
    assert argv[2:4] == ["--guard-home", str(resolve_guard_home(str(tmp_path)))]
    assert argv[4:] == ["--json", "switch", "--job-id", "j", "cigar-1"]


def test_cli_reports_a_missing_runtime_without_running_anything(monkeypatch, tmp_path: Path) -> None:
    def missing(feature: str) -> str:
        raise RuntimeError(feature)

    monkeypatch.setattr(native_recovery_store, "recovery_runtime_path", missing)
    args = SimpleNamespace(
        runtime_command="context", guard_home=str(tmp_path), json=False, forward_help=False, forward_args=["status"]
    )
    out = io.StringIO()
    assert runtime_forward.run_forward(args, output_stream=out) == 1
    assert "native runtime is unavailable" in out.getvalue()


def test_mcp_lists_and_calls_runtime_tools_and_carries_the_session_back(runtime, tmp_path: Path) -> None:
    server = GuardMCPServer(tmp_path)
    tool = next(tool for tool in server.list_tools() if tool.name == "get_context_status")
    assert tool.description == _TOOL["description"] and tool.annotations.readOnlyHint
    assert server.call_tool("get_context_status", {"extra": 1}).text == '{"ok":true}'
    server._native.close()
    requests = [call["request"] for call in runtime]
    assert [request["op"] for request in requests] == ["tools", "catalog", "call", "close"]
    assert requests[0]["session"] is None
    assert requests[2]["session"] == {"credential": "c" * 64, "started": True}
    assert requests[2]["arguments"] == {"extra": 1}


def test_mcp_answers_a_fixed_error_when_the_runtime_is_gone(monkeypatch, tmp_path: Path) -> None:
    def broken(*_args: object, **_kwargs: object) -> SimpleNamespace:
        raise OSError("gone")

    monkeypatch.setattr(native_recovery_store, "recovery_runtime_path", lambda feature: "/runtime")
    monkeypatch.setattr(subprocess, "run", broken)
    session = native_tools.NativeToolSession(tmp_path)
    assert session.allowed() == [] and session.names() == frozenset()
    assert json.loads(session.call("get_context_status", {}))["ok"] is False
