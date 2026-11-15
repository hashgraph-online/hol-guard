"""The requests the stdio MCP discovery shims send the native kind, and the answers they refuse."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.adapters import harness_mcp_discovery as discovery
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.mcp_servers import ManagedMcpServer, proxy_process_env
from codex_plugin_scanner.guard.models import HarnessDetection
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.mcp_protection import McpServerIdentity

_FAKE_SECRET = "fake-secret-value"


def _identity(seed: str, env_keys: tuple[str, ...] = ()) -> McpServerIdentity:
    return McpServerIdentity(
        config_path="~/.cursor/mcp.json",
        command="npx",
        args_hash=f"args-{seed}",
        package_name=None,
        package_version=None,
        package_source="",
        transport="stdio",
        env_keys=env_keys,
        env_values_hash="",
        identity_hash=f"hash-{seed}",
    )


def _server(harness: str, name: str, identity: McpServerIdentity | None) -> ManagedMcpServer:
    return ManagedMcpServer(
        harness=harness,
        name=name,
        source_scope="user",
        config_path="~/.cursor/mcp.json",
        command="npx",
        args=("-y", name),
        transport="stdio",
        env={"API_TOKEN": _FAKE_SECRET},
        enabled=True,
        identity=identity,
    )


def _fake(monkeypatch: pytest.MonkeyPatch, answer: object) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []

    def fake_native(kind: str, request: dict[str, object]) -> object:
        assert kind == "harness_mcp_discovery"
        sent.append(request)
        if isinstance(answer, Exception):
            raise answer
        if callable(answer):
            return answer(request)
        return answer

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)
    return sent


def _grouped(index: int, **overrides: object) -> dict[str, object]:
    item: dict[str, object] = dict.fromkeys(("cli_id", "name", "identity_hash", "configuration_hash"), f"v{index}")
    item.update(index=index, example_label="npx -y '*****'", launch_command="npx -y one", source_label="Cursor")
    item.update(overrides)
    return item


def _discover(monkeypatch: pytest.MonkeyPatch, servers: dict[str, tuple[ManagedMcpServer, ...]]):
    monkeypatch.setattr(discovery, "observable_stdio_servers_with_proxy", lambda detection: servers[detection.harness])
    detections = cast("list[HarnessDetection]", [SimpleNamespace(harness=harness) for harness in servers])
    return discovery.discover_harness_mcp_servers(
        home_dir=Path("home"), guard_home=Path("guard"), detections=detections
    )


def test_one_group_request_carries_every_server_and_no_env_value(monkeypatch: pytest.MonkeyPatch) -> None:
    first = _server("cursor", "one", _identity("1"))
    second = _server("codex", "two", _identity("2"))
    sent = _fake(monkeypatch, {"servers": [_grouped(1), _grouped(0, source_label="Cursor, Codex")]})

    found = _discover(monkeypatch, {"cursor": (first, _server("cursor", "bare", None)), "codex": (second,)})

    assert len(sent) == 1
    assert sent[0]["op"] == "group"
    assert sent[0]["limit"] == discovery.MAX_DISCOVERED_MCP_SERVERS
    assert isinstance(sent[0]["windows"], bool)
    assert sent[0]["servers"] == [
        {
            "harness": server.harness,
            "label": discovery.display_name_for(server.harness),
            "name": server.name,
            "command": "npx",
            "args": ["-y", server.name],
            "source_scope": "user",
            "config_path": "~/.cursor/mcp.json",
            "identity_hash": f"hash-{seed}",
            "package_name": None,
            "server_command": "npx",
            "args_hash": f"args-{seed}",
        }
        for server, seed in ((first, "1"), (second, "2"))
    ]
    assert _FAKE_SECRET not in json.dumps(sent)
    assert [server.harness for server in found] == ["codex", "cursor"]
    assert found[1].identity == UnlistedCliIdentity("v0", "v0", "executable", "v0", "npx -y '*****'")
    assert found[1].server_identity is first.identity
    assert found[1].source_label == "Cursor, Codex"
    assert found[1].env == tuple(sorted(proxy_process_env(first.env).items()))
    connection = found[1].connection_identity
    assert connection is not None
    assert (connection.host, connection.configuration_hash, connection.identity_hash) == ("cursor", "v0", "v0")
    assert connection.server_identity_hash == "hash-1"


def test_no_identified_server_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"servers": []})

    assert _discover(monkeypatch, {"cursor": (_server("cursor", "bare", None),)}) == ()
    assert sent == []


@pytest.mark.parametrize(
    "answer",
    [
        [],
        {"servers": [], "extra": 1},
        {"servers": {}},
        {"servers": [_grouped(1)]},
        {"servers": [_grouped(True)]},
        {"servers": [_grouped(0), _grouped(0)]},
        {"servers": [_grouped(0, name=None)]},
        {"servers": [{**_grouped(0), "extra": "x"}]},
        NativeRunnerAuthorityError("native_runner_authority_unavailable"),
    ],
)
def test_a_refused_group_answer_raises(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(ValueError):
        _discover(monkeypatch, {"cursor": (_server("cursor", "one", _identity("1")),)})


def _discovered(seed: str, env: tuple[tuple[str, str], ...] = ()) -> discovery.DiscoveredHarnessMcpServer:
    return discovery.DiscoveredHarnessMcpServer(
        identity=UnlistedCliIdentity(f"local-cli.mcp-{seed}", seed, "executable", seed, "npx"),
        server_identity=_identity(seed, env_keys=tuple(key for key, _value in env)),
        source_label="Cursor",
        launch_command="npx",
        env=env,
    )


def test_match_sends_every_server_and_the_observation(monkeypatch: pytest.MonkeyPatch) -> None:
    servers = (_discovered("a"), _discovered("b"))
    sent = _fake(monkeypatch, {"index": 1})

    found = discovery.discovered_server_for_observation(servers, cli_id="local-cli.mcp-b", source_label="Cursor")

    assert found is servers[1]
    assert sent == [
        {
            "op": "match",
            "servers": [
                {
                    "cli_id": f"local-cli.mcp-{seed}",
                    "identity_hash": f"hash-{seed}",
                    "command": "npx",
                    "args_hash": f"args-{seed}",
                    "source_label": "Cursor",
                }
                for seed in ("a", "b")
            ],
            "query": {
                "cli_id": "local-cli.mcp-b",
                "server_command": None,
                "args_hash": None,
                "server_identity_hash": None,
                "source_label": "Cursor",
            },
        }
    ]


def test_match_without_servers_asks_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"index": 0})

    assert discovery.discovered_server_for_observation((), cli_id="local-cli.mcp-a") is None
    assert sent == []


@pytest.mark.parametrize("answer", [{"index": 2}, {"index": -1}, {"index": True}, {"index": "0"}, {}, []])
def test_a_malformed_match_answer_is_refused(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(ValueError):
        discovery.discovered_server_for_observation((_discovered("a"), _discovered("b")), cli_id="x")


def _launch_answer(from_process: object) -> object:
    def answer(request: dict[str, object]) -> object:
        return {"index": 0} if request["op"] == "match" else {"from_process": from_process}

    return answer


def test_launch_env_matches_by_id_and_keeps_values_local(monkeypatch: pytest.MonkeyPatch) -> None:
    env = (("API_TOKEN", "${API_TOKEN}"), ("MODE", "fake"), ("UNSET", "x"))
    sent = _fake(monkeypatch, _launch_answer(["API_TOKEN"]))
    monkeypatch.setenv("API_TOKEN", _FAKE_SECRET)
    monkeypatch.setenv("MODE", "process")
    monkeypatch.delenv("UNSET", raising=False)

    extra = discovery.extra_env_for_mcp_launch((_discovered("a", env),), command="npx", cli_id="local-cli.mcp-a")

    assert extra == {"API_TOKEN": _FAKE_SECRET, "MODE": "fake", "UNSET": "x"}
    assert sent[0]["query"] == {
        "cli_id": "local-cli.mcp-a",
        "server_command": None,
        "args_hash": None,
        "server_identity_hash": None,
        "source_label": None,
    }
    assert sent[1] == {
        "op": "launch_env",
        "configured": [["API_TOKEN", "${API_TOKEN}"], ["MODE", "fake"], ["UNSET", "x"]],
        "present": ["API_TOKEN", "MODE"],
    }
    assert _FAKE_SECRET not in json.dumps(sent)


def test_launch_env_asks_nothing_when_guard_sets_none_of_the_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, _launch_answer(["API_TOKEN"]))
    monkeypatch.delenv("API_TOKEN", raising=False)

    extra = discovery.extra_env_for_mcp_launch(
        (_discovered("a", (("API_TOKEN", "${API_TOKEN}"),)),), command="npx", cli_id="local-cli.mcp-a"
    )

    assert extra == {"API_TOKEN": "${API_TOKEN}"}
    assert [request["op"] for request in sent] == ["match"]


@pytest.mark.parametrize("from_process", [None, "API_TOKEN", [1], ["OTHER"]])
def test_a_malformed_launch_env_answer_is_refused(monkeypatch: pytest.MonkeyPatch, from_process: object) -> None:
    _fake(monkeypatch, _launch_answer(from_process))
    monkeypatch.setenv("API_TOKEN", _FAKE_SECRET)
    monkeypatch.setenv("OTHER", "other")

    with pytest.raises(ValueError):
        discovery.extra_env_for_mcp_launch(
            (_discovered("a", (("API_TOKEN", "${API_TOKEN}"),)),), command="npx", cli_id="local-cli.mcp-a"
        )


def test_a_refused_group_answer_still_records_remote_servers(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, NativeRunnerAuthorityError("native_runner_authority_unavailable"))
    detection = SimpleNamespace(harness="cursor")
    remote = (SimpleNamespace(name="remote"),)
    persisted: list[tuple[object, object]] = []
    monkeypatch.setattr(discovery, "_safe_detections", lambda *_args: [detection])
    monkeypatch.setattr(
        discovery, "observable_stdio_servers_with_proxy", lambda _detection: (_server("cursor", "one", _identity("1")),)
    )
    monkeypatch.setattr(discovery, "_remote_servers", lambda _detections, _guard_home: remote)
    monkeypatch.setattr(discovery, "remote_scan_harnesses", lambda _detections, _remote: ("cursor",))

    def persist(_store: object, stdio: object, **kwargs: object) -> tuple[str, ...]:
        persisted.append((stdio, kwargs["remote"]))
        return ("remote",)

    monkeypatch.setattr(discovery, "persist_discovered_harness_mcp_servers", persist)
    context = HarnessContext(home_dir=Path("home"), workspace_dir=None, guard_home=Path("guard"))

    assert discovery.observe_configured_mcp_servers(object(), context=context, seen_at="now") == 1
    assert persisted == [((), remote)]
