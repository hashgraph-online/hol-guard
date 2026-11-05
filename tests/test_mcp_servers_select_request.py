"""Managed MCP servers are selected by one native `harness_mcp_discovery` `select` request."""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.adapters import mcp_servers
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection

_IDENTITY = {
    "config_path": "/c/mcp.json",
    "command": "node",
    "args_hash": "a" * 64,
    "package_name": None,
    "package_version": None,
    "package_source": "",
    "transport": "stdio",
    "env_keys": ["API_KEY"],
    "env_values_hash": "b" * 64,
    "identity_hash": "c" * 64,
}
_FOUND = {
    "command": "node",
    "args": ["s.js"],
    "source_scope": "project",
    "config_path": "/w/.cursor/mcp.json",
    "transport": "stdio",
    "env": [["API_KEY", "value"]],
    "enabled": True,
    "identity": _IDENTITY,
}


def _fake(monkeypatch: pytest.MonkeyPatch, answer: object) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []

    def fake_native(kind: str, request: dict[str, object], **_: object) -> object:
        assert kind == "harness_mcp_discovery"
        sent.append(json.loads(json.dumps(request)))
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)
    return sent


def _artifact(name: str = "srv", artifact_type: str = "mcp_server", **private: object) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=name,
        name=name,
        harness="cursor",
        artifact_type=artifact_type,
        source_scope="global",
        config_path="/c/mcp.json",
        command="hol-guard",
        args=("cursor-mcp-proxy", "--command", "node"),
        metadata={"env": {"API_KEY": "meta", "N": 1}, "guard_managed_proxy": True},
        runtime_private_metadata=dict(private),
    )


def _detection(*artifacts: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness="cursor",
        installed=True,
        command_available=True,
        config_paths=("/c/mcp.json",),
        artifacts=artifacts,
    )


def test_one_request_carries_every_server_and_the_answer_keeps_its_order(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"servers": [None, _FOUND]})
    detection = _detection(
        _artifact("first"),
        _artifact("skill", artifact_type="skill"),
        _artifact(
            "second",
            managed_mcp_origin=("project", "/w/.cursor/mcp.json"),
            managed_guard_home="/g",
            mcp_env={"API_KEY": "value", 3: "x"},
            mcp_args=("cursor-mcp-proxy", "--arg=s.js"),
        ),
    )

    servers = mcp_servers.observable_stdio_servers_with_proxy(detection)

    assert len(sent) == 1
    assert sent[0]["op"] == "select"
    assert sent[0]["include_proxy"] is True
    requests = sent[0]["artifacts"]
    assert isinstance(requests, list)
    assert [row["name"] for row in requests] == ["first", "second"]
    assert requests[0]["env"] == [["API_KEY", "meta"]]
    assert requests[0]["saved_origin"] is None
    assert requests[0]["guard_managed_proxy"] is True
    assert requests[1] == {
        "harness": "cursor",
        "name": "second",
        "source_scope": "global",
        "config_path": "/c/mcp.json",
        "command": "hol-guard",
        "args": ["cursor-mcp-proxy", "--arg=s.js"],
        "transport": None,
        "env": [["API_KEY", "value"]],
        "guard_managed_proxy": True,
        "enabled": True,
        "saved_origin": ["project", "/w/.cursor/mcp.json"],
        "saved_guard_home": "/g",
    }
    assert len(servers) == 1
    server = servers[0]
    assert (server.name, server.command, server.args) == ("second", "node", ("s.js",))
    assert (server.source_scope, server.config_path) == ("project", "/w/.cursor/mcp.json")
    assert server.env == {"API_KEY": "value"}
    assert server.identity is not None
    assert server.identity.env_keys == ("API_KEY",)
    assert server.identity.identity_hash == "c" * 64


def test_install_selection_excludes_proxies_and_names_what_it_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    detection = _detection(_artifact(), _artifact(" "))
    managed = _fake(monkeypatch, {"servers": [None, None]})

    assert mcp_servers.managed_stdio_servers(detection) == ()
    assert [(row["include_proxy"], len(row["artifacts"])) for row in managed] == [(False, 2)]

    skipped = _fake(monkeypatch, {"servers": [None]})

    assert mcp_servers.skipped_stdio_server_names(detection) == ("srv",)
    assert [(row["include_proxy"], len(row["artifacts"])) for row in skipped] == [(False, 1)]


def test_no_server_never_asks(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"servers": []})

    assert mcp_servers.managed_stdio_servers(_detection(_artifact("skill", artifact_type="skill"))) == ()
    assert sent == []


def test_private_args_that_are_not_strings_are_never_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"servers": []})

    assert mcp_servers.managed_stdio_servers(_detection(_artifact(mcp_args=("ok", 1)))) == ()
    assert sent == []


def test_an_unencodable_entry_is_left_out_of_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"servers": [None]})
    unencodable = _artifact("bad", mcp_env={"KEY": "\ud800"})

    assert mcp_servers.managed_stdio_servers(_detection(unencodable, _artifact("good"))) == ()
    requests = sent[0]["artifacts"]
    assert isinstance(requests, list)
    assert [row["name"] for row in requests] == ["good"]


def test_saved_state_that_is_not_a_string_pair_is_not_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"servers": [None, None]})
    detection = _detection(
        _artifact("a", managed_mcp_origin=["project", "/w"], managed_guard_home=1, mcp_env=["API_KEY"]),
        _artifact("b", managed_mcp_origin=("project", 2)),
    )

    mcp_servers.observable_stdio_servers_with_proxy(detection)

    rows = sent[0]["artifacts"]
    assert isinstance(rows, list)
    assert [(row["saved_origin"], row["saved_guard_home"], row["env"]) for row in rows] == [
        (None, None, None),
        (None, None, [["API_KEY", "meta"]]),
    ]


@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"servers": None},
        {"servers": []},
        {"servers": ["node"]},
        {"servers": [{**_FOUND, "command": None}]},
        {"servers": [{**_FOUND, "env": [["API_KEY"]]}]},
        {"servers": [{key: value for key, value in _FOUND.items() if key != "identity"}]},
    ],
)
def test_a_malformed_answer_is_refused(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(ValueError, match="native_mcp_server_select_malformed"):
        mcp_servers.observable_stdio_servers_with_proxy(_detection(_artifact()))


def test_a_native_failure_names_the_identity_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, authority.NativeRunnerAuthorityError("native runtime unavailable"))

    with pytest.raises(ValueError, match="native_mcp_server_identity_unavailable"):
        mcp_servers.managed_stdio_servers(_detection(_artifact()))


def test_a_server_id_is_one_native_request(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"ids": ["mcp_server:cursor:global:srv:0123"]})
    server = mcp_servers.ManagedMcpServer(
        harness="cursor",
        name="srv",
        source_scope="global",
        config_path="/c/mcp.json",
        command="node",
        args=("s.js",),
        transport="stdio",
        env={"API_KEY": "value"},
        enabled=True,
    )

    assert mcp_servers.stable_mcp_server_identifier(server) == "mcp_server:cursor:global:srv:0123"
    assert sent == [
        {
            "op": "server_id",
            "servers": [
                {
                    "harness": "cursor",
                    "name": "srv",
                    "source_scope": "global",
                    "command": "node",
                    "args": ["s.js"],
                    "transport": "stdio",
                }
            ],
        }
    ]
    assert "value" not in json.dumps(sent)
