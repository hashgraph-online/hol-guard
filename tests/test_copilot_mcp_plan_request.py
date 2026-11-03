"""The Copilot install's native MCP plan request, how its answer is applied, and the answers it refuses."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.adapters import copilot
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError

_NOTES = ["first note", "second note"]
_PLAN = {"key": "mcpServers", "source": "mcpServers", "refresh": [], "add": [], "fields": []}


def _fake(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]) -> list[tuple[str, dict[str, object]]]:
    sent: list[tuple[str, dict[str, object]]] = []

    def fake_native(kind: str, request: dict[str, object]) -> dict[str, object]:
        sent.append((kind, request))
        return answer

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)
    return sent


def _server(name: str, scope: str, path: str) -> Any:
    return SimpleNamespace(name=name, source_scope=scope, config_path=path)


def _context(root: Path, *, workspace: bool = True) -> HarnessContext:
    return HarnessContext(
        home_dir=root / "home", workspace_dir=root / "work" if workspace else None, guard_home=root / "guard"
    )


@pytest.fixture
def launches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(copilot, "guard_cli_launcher", lambda: "PY")
    monkeypatch.setattr(copilot, "mcp_proxy_launch", lambda python, args: (python, list(args)))
    monkeypatch.setattr(copilot, "merge_guard_launcher_env", lambda env: dict(env))
    monkeypatch.setattr(
        copilot,
        "proxy_launcher_entry",
        lambda *, proxy_command, context, server: {"command": proxy_command, "args": [server.name]},
    )


def test_the_request_carries_ordered_launch_pairs_and_normalized_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent = _fake(monkeypatch, {"targets": [_PLAN, _PLAN], "notes": _NOTES})
    target = tmp_path / "work" / ".mcp.json"
    payload: dict[str, object] = {
        "mcpServers": {"z": {"command": "node", "args": ["a"], "env": {"TOKEN": "x"}}, "a": "text"},
        "servers": [1],
    }
    managed = (_server("g", "global", str(tmp_path / "g.json")),)

    plans, notes = copilot._plan_mcp_targets(
        _context(tmp_path), [(target, payload), (tmp_path / "work" / "mcp.json", {})], managed
    )

    assert notes == _NOTES
    assert plans == [_PLAN, _PLAN]
    assert sent == [
        (
            "copilot_mcp_plan",
            {
                "workspace": True,
                "managed": [["g", "global", os.path.normcase(str(tmp_path / "g.json"))]],
                "targets": [
                    {
                        "path": os.path.normcase(str(target)),
                        "name": ".mcp.json",
                        "mcpServers": [["z", {"command": "node", "args": ["a"]}], ["a", None]],
                        "servers": False,
                    },
                    {
                        "path": os.path.normcase(str(tmp_path / "work" / "mcp.json")),
                        "name": "mcp.json",
                        "mcpServers": None,
                        "servers": None,
                    },
                ],
            },
        )
    ]


@pytest.mark.usefixtures("launches")
def test_a_plan_refreshes_adds_and_moves_the_servers_key_in_order(tmp_path: Path) -> None:
    payload: dict[str, object] = {
        "servers": {
            "proxy": {"command": ["/old/python", "-m", "x"], "environment": {"A": "1"}, "keep": True},
            "plain": {"command": "node"},
        },
        "other": 1,
    }
    managed = (_server("m0", "global", "g"), _server("m1", "global", "g"))
    plan = {
        "key": "mcpServers",
        "source": "servers",
        "refresh": [[0, ["-m", "x", "copilot-mcp-proxy"]]],
        "add": [1],
        "fields": [["type", "local"], ["tools", ["*"]]],
    }

    copilot._apply_mcp_plan(_context(tmp_path), plan, payload, managed)

    assert list(payload) == ["other", "mcpServers"]
    servers = cast(dict[str, dict[str, object]], payload["mcpServers"])
    assert servers == {
        "proxy": {
            "command": "PY",
            "args": ["-m", "x", "copilot-mcp-proxy"],
            "environment": {"A": "1"},
            "keep": True,
            "env": {"A": "1"},
        },
        "plain": {"command": "node"},
        "m1": {"command": "copilot-mcp-proxy", "args": ["m1"], "type": "local", "tools": ["*"]},
    }
    assert list(servers["m1"]) == ["command", "args", "type", "tools"]


@pytest.mark.usefixtures("launches")
def test_a_refresh_without_launcher_env_drops_both_env_keys(tmp_path: Path) -> None:
    payload: dict[str, object] = {"mcpServers": {"p": {"command": "x", "env": "bad", "environment": "bad"}}}
    plan = dict(_PLAN, refresh=[[0, ["arg"]]])

    copilot._apply_mcp_plan(_context(tmp_path), plan, payload, ())

    assert payload == {"mcpServers": {"p": {"command": "PY", "args": ["arg"]}}}


@pytest.mark.parametrize(
    "answer",
    [
        {"targets": [_PLAN]},
        {"targets": [_PLAN], "notes": _NOTES, "extra": 1},
        {"targets": [], "notes": _NOTES},
        {"targets": {"a": _PLAN}, "notes": _NOTES},
        {"targets": [_PLAN], "notes": [1]},
    ],
)
def test_a_malformed_answer_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: dict[str, object]
) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(ValueError, match="malformed"):
        copilot._plan_mcp_targets(_context(tmp_path), [(tmp_path / ".mcp.json", {})], ())


@pytest.mark.parametrize(
    "change",
    [
        {"extra": 1},
        {"key": "other"},
        {"source": "servers"},
        {"source": "other"},
        {"refresh": [[2, []]]},
        {"refresh": [[0, ["a"]], [0, ["a"]]]},
        {"refresh": [[True, []]]},
        {"refresh": [[0, [1]]]},
        {"refresh": [[1, []]], "source": "mcpServers"},
        {"refresh": [[0]]},
        {"add": [1]},
        {"add": [0, 0]},
        {"add": "0"},
        {"fields": [["type"]]},
        {"fields": {"type": "stdio"}},
    ],
)
def test_a_malformed_target_plan_is_refused(tmp_path: Path, change: dict[str, object]) -> None:
    payload: dict[str, object] = {"mcpServers": {"p": {"command": "x"}, "text": "t"}}
    plan = {**_PLAN, **change}

    with pytest.raises(ValueError, match="malformed"):
        copilot._apply_mcp_plan(_context(tmp_path), plan, payload, (_server("m", "global", "g"),))
    assert payload == {"mcpServers": {"p": {"command": "x"}, "text": "t"}}


def test_a_native_error_reaches_the_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_native(kind: str, request: dict[str, object]) -> dict[str, object]:
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)

    with pytest.raises(NativeRunnerAuthorityError, match="unavailable"):
        copilot._plan_mcp_targets(_context(tmp_path, workspace=False), [(tmp_path / "mcp-config.json", {})], ())
