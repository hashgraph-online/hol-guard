"""The OpenCode install plan shim asks the native `opencode_install_plan` kind and builds its specs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.adapters import opencode_install_plan as plan
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.mcp_servers import ManagedMcpServer


def _fake(monkeypatch: pytest.MonkeyPatch, answer: object) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []

    def fake_native(kind: str, request: dict[str, object], **_: object) -> object:
        assert kind == "opencode_install_plan"
        sent.append(json.loads(json.dumps(request)))
        if isinstance(answer, Exception):
            raise answer
        return json.loads(json.dumps(answer))

    def fake_args(*, proxy_command: str, guard_home: str, server: ManagedMcpServer, **extra: str | None) -> list[str]:
        del guard_home
        return [proxy_command, server.name, extra["workspace"] or "-"]

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)
    monkeypatch.setattr(plan, "merge_guard_launcher_env", lambda env: {**env, "LAUNCHER": "1"})
    monkeypatch.setattr(plan, "proxy_cli_args", fake_args)
    monkeypatch.setattr(plan, "guard_cli_command", lambda _context, args: ["guard", *args])
    monkeypatch.setattr(plan, "mcp_proxy_command", lambda command: ["relay", *command])
    return sent


def _server(name: str, config: Path, *, scope: str = "global", env: dict[str, str] | None = None) -> ManagedMcpServer:
    return ManagedMcpServer(
        harness="opencode",
        name=name,
        source_scope=scope,
        config_path=str(config),
        command="node",
        args=("s.js",),
        transport="stdio",
        env=dict(env or {}),
        enabled=True,
    )


def _context(tmp_path: Path, *, workspace: bool = False) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "work" if workspace else None,
        guard_home=tmp_path / "guard",
    )


def _answer(**overrides: object) -> dict[str, object]:
    answer: dict[str, object] = {
        "managed": [0],
        "skipped": [],
        "permission": ["object", []],
        "mcp": ["object", []],
        "overlay": ["object", []],
    }
    answer.update(overrides)
    return answer


def _ask(tmp_path: Path, servers: tuple[ManagedMcpServer, ...], **values: object) -> plan.OpenCodeInstallPlan:
    return plan.plan_opencode_install(
        _context(tmp_path, workspace=bool(values.get("workspace"))),
        servers=servers,
        skipped=("remote",),
        artifacts=("hol-guard::x", "files"),
        workspace_servers={"b", "a"},
        permission=values.get("permission"),
        mcp=values.get("mcp"),
    )


def test_the_request_carries_servers_sources_and_the_mcp_key_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = tmp_path / "opencode.json"
    config.write_text(json.dumps({"mcp": {"files": {"type": "local", "timeout": 5}}}), encoding="utf-8")
    sent = _fake(monkeypatch, _answer(managed=[0, 1]))
    servers = (
        _server("files", config, env={"TOKEN": "t"}),
        _server("files", tmp_path / "missing.json", scope="project"),
    )
    _ = _ask(tmp_path, servers, mcp={"z": {}, "a": 1}, permission="ask", workspace=True)
    assert sent == [
        {
            "op": "plan",
            "workspace": True,
            "servers": [
                {
                    "name": "files",
                    "source_scope": "global",
                    "command": "node",
                    "args": ["s.js"],
                    "env": {"TOKEN": "t"},
                    "enabled": True,
                    "proxy_environment": {"TOKEN": "t", "LAUNCHER": "1"},
                    "source": {"type": "local", "timeout": 5},
                },
                {
                    "name": "files",
                    "source_scope": "project",
                    "command": "node",
                    "args": ["s.js"],
                    "env": {},
                    "enabled": True,
                    "proxy_environment": {"LAUNCHER": "1"},
                    "source": None,
                },
            ],
            "skipped": ["remote"],
            "artifacts": ["hol-guard::x", "files"],
            "workspace_servers": ["a", "b"],
            "permission": "ask",
            "mcp": {"z": {}, "a": 1},
            "mcp_keys": ["z", "a"],
        }
    ]


def test_specs_build_new_dicts_over_the_users_own_values(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    servers = (_server("files", tmp_path / "missing.json"), _server("other", tmp_path / "missing.json"))
    user_entry: dict[str, object] = {"z": 1, "enabled": True, "a": {"k": 2}}
    answer = _answer(
        managed=[1],
        skipped=["remote", "hol-guard::x"],
        permission=["merge", [["ref", ["permission"]], ["object", [["bash", ["value", "allow"]]]]]],
        mcp=[
            "object",
            [
                ["files", ["merge", [["ref", ["mcp", "files"]], ["object", [["enabled", ["value", False]]]]]]],
                ["hol-guard::other", ["object", [["command", ["launch", 1, "companion"]]]]],
            ],
        ],
        overlay=["object", [["mcp", ["object", [["other", ["launch", 1, "override"]]]]], ["n", ["value", None]]]],
    )
    _ = _fake(monkeypatch, answer)
    result = _ask(tmp_path, servers, mcp={"files": user_entry}, permission={"x": "ask", "bash": "deny"}, workspace=True)
    assert result.managed == (servers[1],)
    assert result.skipped == ("remote", "hol-guard::x")
    assert list(result.permission.items()) == [("x", "ask"), ("bash", "allow")]
    files = result.mcp["files"]
    assert isinstance(files, dict)
    assert list(files) == ["z", "enabled", "a"]
    assert files["enabled"] is False
    assert files["a"] is user_entry["a"]
    assert user_entry["enabled"] is True
    assert result.mcp["hol-guard::other"] == {"command": ["relay", "guard", "opencode-mcp-proxy", "other", "-"]}
    workspace = str(tmp_path / "work")
    assert result.overlay == {
        "mcp": {"other": ["relay", "guard", "opencode-mcp-proxy", "other", workspace]},
        "n": None,
    }


@pytest.mark.parametrize(
    "answer",
    [
        {"managed": [0]},
        _answer(extra=1),
        _answer(managed=[1, 0]),
        _answer(managed=[0, 0]),
        _answer(managed=[5]),
        _answer(managed=[True]),
        _answer(skipped=[1]),
        _answer(permission=["value", "x"]),
        _answer(permission=["object", [["k", ["value", {"o": 1}]]]]),
        _answer(permission=["object", [["k", ["ref", ["nope"]]]]]),
        _answer(permission=["object", [["k", ["ref", ["servers", 9]]]]]),
        _answer(permission=["object", [["k", ["ref", ["servers", True]]]]]),
        _answer(permission=["object", [["k"]]]),
        _answer(permission=["merge", [["value", "x"]]]),
        _answer(permission=["merge", "x"]),
        _answer(permission=["unknown", []]),
        _answer(permission=["object", [], "extra"]),
        _answer(mcp=["object", [["k", ["launch", 0, "other"]]]]),
        _answer(mcp=["object", [["k", ["launch", 3, "companion"]]]]),
        _answer(mcp=["object", [["k", ["launch", 0, []]]]]),
        _answer(mcp=["object", [["k", ["launch", 0, {}]]]]),
        _answer(overlay=[]),
        _answer(overlay="object"),
    ],
)
def test_a_malformed_answer_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: object) -> None:
    _ = _fake(monkeypatch, answer)
    with pytest.raises(ValueError, match="malformed"):
        _ = _ask(tmp_path, (_server("files", tmp_path / "missing.json"),))


def test_an_unanswered_request_raises_value_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _ = _fake(monkeypatch, authority.NativeRunnerAuthorityError("native_unavailable"))
    with pytest.raises(ValueError, match="native_unavailable"):
        _ = _ask(tmp_path, (_server("files", tmp_path / "missing.json"),))
