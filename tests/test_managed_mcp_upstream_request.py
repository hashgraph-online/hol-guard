"""A Guard MCP proxy's upstream launch is read by the native `harness_mcp_discovery` kind."""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.adapters import managed_mcp_upstream
from codex_plugin_scanner.guard.models import GuardArtifact

_COMMANDS = frozenset({"cursor-mcp-proxy", "mcp-proxy"})
_FOUND = {
    "command": "node",
    "args": ["s.js"],
    "env_names": ["API_KEY"],
    "server_id": "sid",
    "source_scope": "project",
    "config_path": "/w/.cursor/mcp.json",
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


def _artifact(**private: object) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="a",
        name="srv",
        harness="cursor",
        artifact_type="mcp_server",
        source_scope="global",
        config_path="/c/mcp.json",
        command="hol-guard",
        args=("cursor-mcp-proxy", "--command", "node"),
        metadata={"env": {" API_KEY ": "meta", "N": 1}},
        runtime_private_metadata=dict(private),
    )


def test_the_request_names_env_keys_and_the_answer_maps_their_values(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"upstream": _FOUND})
    artifact = _artifact(
        managed_mcp_origin=("project", "/w/.cursor/mcp.json"),
        managed_guard_home="/g",
        mcp_env={" API_KEY ": "secret-value", 3: "x"},
    )

    upstream = managed_mcp_upstream.read_managed_mcp_upstream(artifact, _COMMANDS)

    assert sent == [
        {
            "op": "upstream",
            "commands": ["cursor-mcp-proxy", "mcp-proxy"],
            "harness": "cursor",
            "name": "srv",
            "transport": "stdio",
            "source_scope": "global",
            "config_path": "/c/mcp.json",
            "args": ["cursor-mcp-proxy", "--command", "node"],
            "saved_origin": ["project", "/w/.cursor/mcp.json"],
            "saved_guard_home": "/g",
            "env_names": ["API_KEY"],
        }
    ]
    assert "secret-value" not in json.dumps(sent)
    assert upstream == managed_mcp_upstream.ManagedMcpUpstream(
        command="node",
        args=("s.js",),
        env={"API_KEY": "secret-value"},
        server_id="sid",
        source_scope="project",
        config_path="/w/.cursor/mcp.json",
    )


def test_an_env_key_that_cannot_travel_as_utf8_is_left_out(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"upstream": _FOUND})
    artifact = _artifact(mcp_env={"API_KEY": "secret-value", "BAD\ud800": "x"})

    upstream = managed_mcp_upstream.read_managed_mcp_upstream(artifact, _COMMANDS)

    assert sent[0]["env_names"] == ["API_KEY"]
    assert upstream is not None
    assert upstream.env == {"API_KEY": "secret-value"}


def test_saved_state_that_is_not_a_string_pair_is_not_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"upstream": None})

    assert (
        managed_mcp_upstream.read_managed_mcp_upstream(
            _artifact(managed_mcp_origin=["project", "/w"], managed_guard_home=1), _COMMANDS
        )
        is None
    )
    assert (
        managed_mcp_upstream.read_managed_mcp_upstream(_artifact(managed_mcp_origin=("project", 2)), _COMMANDS) is None
    )

    assert [(row["saved_origin"], row["saved_guard_home"]) for row in sent] == [(None, None), (None, None)]


def test_a_configured_env_that_is_not_a_mapping_never_asks(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"upstream": _FOUND})

    assert managed_mcp_upstream.read_managed_mcp_upstream(_artifact(mcp_env=["API_KEY"]), _COMMANDS) is None
    assert sent == []


@pytest.mark.parametrize(
    "answer",
    [
        authority.NativeRunnerAuthorityError("native runtime unavailable"),
        {},
        {"upstream": "node"},
        {"upstream": {**_FOUND, "command": None}},
        {"upstream": {**_FOUND, "args": "s.js"}},
        {"upstream": {**_FOUND, "args": [1]}},
        {"upstream": {**_FOUND, "env_names": ["UNKNOWN"]}},
        {"upstream": {**_FOUND, "env_names": [["API_KEY"]]}},
        {"upstream": {key: value for key, value in _FOUND.items() if key != "server_id"}},
    ],
)
def test_a_failed_or_malformed_answer_leaves_the_launch_unavailable(
    monkeypatch: pytest.MonkeyPatch, answer: object
) -> None:
    _fake(monkeypatch, answer)

    assert managed_mcp_upstream.read_managed_mcp_upstream(_artifact(), _COMMANDS) is None
