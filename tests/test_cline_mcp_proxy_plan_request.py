"""The Cline MCP proxy install asks the native `cline_install_plan` kind which servers to proxy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.adapters import cline_mcp
from codex_plugin_scanner.guard.adapters.base import HarnessContext

_SERVER = {"name": "local", "command": "node", "args": ["s.js"], "transport": "stdio", "env": {"K": "v"}}


def _fake(monkeypatch: pytest.MonkeyPatch, answer: object) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []

    def fake_native(kind: str, request: dict[str, object], **_: object) -> object:
        assert kind == "cline_install_plan"
        sent.append(json.loads(json.dumps(request)))
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)
    return sent


def _plan(tmp_path: Path, payload: dict[str, object]) -> tuple[str, list[cline_mcp.ManagedMcpServer], list[str]]:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    return cline_mcp._proxy_plan(context, tmp_path / "settings.json", payload)


def test_the_settings_travel_as_json_text_and_the_plan_returns_servers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan = {"key": "mcp", "managed": [_SERVER], "remote": ["far"]}
    sent = _fake(monkeypatch, {"plan": json.dumps(plan)})

    key, servers, remote = _plan(tmp_path, {"mcp": {"local": {"command": "node"}}, "n": 1})

    assert sent == [{"op": "mcp_proxy", "settings": '{"mcp": {"local": {"command": "node"}}, "n": 1}'}]
    assert key == "mcp"
    assert remote == ["far"]
    assert servers == [
        cline_mcp.ManagedMcpServer(
            harness="cline",
            name="local",
            source_scope="global",
            config_path=str(tmp_path / "settings.json"),
            command="node",
            args=("s.js",),
            transport="stdio",
            env={"K": "v"},
            enabled=True,
        )
    ]


@pytest.mark.parametrize(
    "answer",
    [
        authority.NativeRunnerAuthorityError("native runtime unavailable"),
        {"plan": "{"},
        {"plan": 1},
        {"plan": "{}", "extra": True},
        {"plan": json.dumps({"key": "other", "managed": [], "remote": []})},
        {"plan": json.dumps({"key": "mcp", "managed": {}, "remote": []})},
        {"plan": json.dumps({"key": "mcp", "managed": [], "remote": [1]})},
        {"plan": json.dumps({"key": "mcp", "managed": [{**_SERVER, "extra": 1}], "remote": []})},
        {"plan": json.dumps({"key": "mcp", "managed": [{**_SERVER, "args": "s.js"}], "remote": []})},
        {"plan": json.dumps({"key": "mcp", "managed": [{**_SERVER, "env": {"K": 1}}], "remote": []})},
        {"plan": json.dumps({"key": "mcp", "managed": [{**_SERVER, "command": None}], "remote": []})},
    ],
)
def test_a_failed_or_malformed_answer_refuses_the_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: object
) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(RuntimeError, match="Could not plan the Cline MCP proxy install"):
        _plan(tmp_path, {"mcpServers": {}})
