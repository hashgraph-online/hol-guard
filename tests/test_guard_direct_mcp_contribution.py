"""Native MCP catalog selection is portable, opt-in, and tightening-only."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.runtime import mcp_server_grants as grants
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_catalog import _values_for_payload
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    load_mcp_contribution_payloads,
    validate_mcp_contribution,
)

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401

_ROOT = Path(__file__).resolve().parents[1]


def payload():
    value = json.loads((_ROOT / "contributions/mcp-servers/mcp.filesystem.json").read_text())
    value["id"] = "mcp.native-fixture"
    value["launch"] = {"kind": "direct-command", "command": "fixture-mcp"}
    return value


def artifact(command="fixture-mcp", args=(), transport="stdio"):
    identity = build_mcp_server_identity(config_path="", command=command, args=args, transport=transport)
    return build_tool_call_artifact(
        harness="codex",
        server_name="custom-name",
        tool_name="write_file",
        source_scope="project",
        config_path=".mcp.json",
        transport=transport,
        server_identity=identity,
    )


def test_validates_and_projects_runnable_example():
    value = payload()
    validate_mcp_contribution(value)
    projected = _values_for_payload(value)
    assert projected["executables"] == ("fixture-mcp",)
    assert {p.example_command for p in projected["permissions"]} == {"fixture-mcp"}


@pytest.mark.parametrize(
    "command",
    [
        "",
        "../fixture-mcp",
        "/bin/fixture-mcp",
        "fixture-mcp.exe",
        "fixture-mcp.cmd",
        "fixture-mcp.bat",
        "fixture-mcp --serve",
        "Fixture",
        "sh",
        "bash",
        "node",
        "python",
        "docker",
        "npx",
        "uv",
        "cargo",
        "python3.11",
        "pythonw",
        "py",
        "nodejs",
        "node20",
        "java17",
        "lua5.4",
        "ksh",
        "csh",
        "tcsh",
        "tsx",
        "ts-node",
        "sudo",
        "busybox",
        "é",
        "a..b",
        "a.",
        "-a",
        "a\n",
        "a" * 129,
    ],
)
def test_rejects_noncanonical_commands(command):
    value = payload()
    value["launch"]["command"] = command
    with pytest.raises(ValueError):
        validate_mcp_contribution(value)


@pytest.mark.parametrize("field,value", [("args", ["--serve"]), ("package", "fixture"), ("url", "https://example.com")])
def test_rejects_undeclared_launch_fields(field, value):
    data = payload()
    data["launch"][field] = value
    with pytest.raises(ValueError):
        validate_mcp_contribution(data)


def test_rejects_allow_even_for_read_tools():
    value = payload()
    value["tools"][0]["state"] = "allow"
    with pytest.raises(ValueError, match="cannot declare allow"):
        validate_mcp_contribution(value)


def test_rejects_duplicate_direct_commands(tmp_path):
    value = payload()
    (tmp_path / "mcp.one.json").write_text(json.dumps(value))
    value["id"] = "mcp.second-fixture"
    (tmp_path / "mcp.two.json").write_text(json.dumps(value))
    with pytest.raises(ValueError, match="duplicate MCP direct command"):
        load_mcp_contribution_payloads(tmp_path)


@pytest.mark.parametrize(
    "command",
    [
        "fixture-mcp",
        "/opt/bin/fixture-mcp",
        "fixture-mcp.exe",
        "FIXTURE-MCP.EXE",
        "Fixture-MCP.Exe",
        "fixture-mcp.cmd",
        "fixture-mcp.BAT",
        r"C:\\Program Files\\Fixture\\fixture-mcp.exe",
    ],
)
@pytest.mark.parametrize("args", [(), ("--root", "/repo one"), ("--root", "/another", "--budget", "10000")])
def test_matches_real_stdio_tool_identity_with_variable_user_paths(monkeypatch, command, args):
    value = payload()
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (value,))
    assert grants.matching_mcp_contribution(artifact(command, args)) == value


@pytest.mark.parametrize(
    "command,args,transport",
    [
        ("other-mcp", (), "stdio"),
        ("fixture-mcp --serve", (), "stdio"),
        ("https://example.com/fixture-mcp", (), "http"),
        ("fixture-mcp", (), "http"),
        ("sh", ("-c", "fixture-mcp"), "stdio"),
        ("npx", ("fixture-mcp",), "stdio"),
    ],
)
def test_does_not_match_other_servers_wrappers_or_transports(monkeypatch, command, args, transport):
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (payload(),))
    assert grants.matching_mcp_contribution(artifact(command, args, transport)) is None


@pytest.mark.parametrize("missing", ["mcp_server_identity", "mcp_tool_identity"])
def test_requires_both_server_and_tool_identity(monkeypatch, missing):
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (payload(),))
    original = artifact()
    metadata = {k: v for k, v in original.metadata.items() if k != missing}
    assert grants.matching_mcp_contribution(replace(original, metadata=metadata)) is None


def test_catalog_matching_does_not_make_saved_approvals_portable():
    identities = [
        build_mcp_server_identity(config_path="", command=command, args=args, transport="stdio")
        for command, args in [
            ("/opt/bin/fixture-mcp", ("--root", "/one")),
            ("/opt/bin/fixture-mcp", ("--root", "/two")),
            ("/other/fixture-mcp", ("--root", "/one")),
        ]
    ]
    assert len({identity.identity_hash for identity in identities}) == 3


def test_direct_defaults_require_local_enable_and_preserve_stronger_floors(monkeypatch):
    from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState

    from .test_guard_mcp_server_grants import _AuthorityStore, _layer

    value = payload()
    # Reuse an existing reviewed external catalog slot to exercise real trust composition.
    value["id"] = "mcp.filesystem"
    value["tools"] = [{"name": "write_file", "state": "review"}, {"name": "other", "state": "inherit"}]
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (value,))
    tool = artifact()
    for kind, state in [
        (ControlLayerKind.SIGNED_CLOUD, ControlState.ENABLED),
        (ControlLayerKind.LOCAL_ADMIN, ControlState.DISABLED),
    ]:
        store = _AuthorityStore((_layer(kind, "command.mcp-filesystem", state),))
        assert grants.apply_contributed_mcp_decision(store, tool, "allow") is None
    assert grants.apply_contributed_mcp_decision(_AuthorityStore(), tool, "allow") is None
    store = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-filesystem", ControlState.ENABLED),))
    assert grants.apply_contributed_mcp_decision(store, tool, "allow")[0] == "review"
    assert grants.apply_contributed_mcp_decision(store, tool, "block") is None
    assert grants.apply_contributed_mcp_decision(store, tool, "require-reapproval") is None


@pytest.mark.parametrize("state,expected", [("allow", "allow"), ("block", "block"), ("review", "review")])
def test_this_device_grant_precedes_direct_catalog_default(monkeypatch, tmp_path, state, expected):
    from codex_plugin_scanner.guard.local_cli_trust import apply_local_mcp_extension_decision
    from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
    from codex_plugin_scanner.guard.store import GuardStore

    from .test_guard_local_mcp_grants import _enroll

    tool = artifact()
    identity = build_mcp_server_identity(config_path="", command="fixture-mcp", args=(), transport="stdio")
    store = GuardStore(tmp_path / "guard-home")
    _enroll(
        store,
        identity,
        states={"write_file": state},
        commands=(LocalCliCommand("write_file", "Write", "write_file", "Write"),),
    )

    def unexpected_catalog_read():
        pytest.fail("A matched device grant must take precedence over catalog defaults")

    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", unexpected_catalog_read)
    decision = apply_local_mcp_extension_decision(store, tool, "review")
    assert decision[0] == expected
    assert decision[1] == "local-mcp-extension"
