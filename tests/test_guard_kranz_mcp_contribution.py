"""Kranz MCP defaults preserve local activation, launch identity, and stronger floors."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.local_cli_trust import apply_local_mcp_extension_decision
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.runtime import mcp_server_grants as grants
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState
from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import load_generated_command_catalog_bytes
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    catalog_id_for_mcp_id,
    mcp_tool_state,
    validate_mcp_contribution,
)

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401
from .test_guard_mcp_server_grants import _AuthorityStore, _layer
from .test_native_source_program import build as build
from .test_native_source_program import canonical
from .test_native_source_program import compiled as compiled
from .test_native_source_program import compiler as compiler

ROOT = Path(__file__).resolve().parents[1]
CATALOG_ID = "command.mcp-kranz"
MUTATIONS = (
    "up",
    "down",
    "run_delete",
    "start",
    "stop",
    "restart",
    "action_run",
    "action_cancel",
    "reload",
    "logs_clear",
)
OBSERVATIONS = (
    "runtimes",
    "status",
    "runs",
    "changes",
    "plan",
    "graph",
    "ports",
    "port_inspect",
    "logs",
    "wait",
    "health",
    "action_list",
    "action_info",
    "action_result",
    "doctor",
)


@pytest.fixture(scope="module")
def kranz_payload() -> dict:
    return json.loads((ROOT / "contributions/mcp-servers/mcp.kranz.json").read_bytes())


def artifact(tool: str, command: str = "kranz", args: tuple[str, ...] = ("mcp",), transport: str = "stdio"):
    identity = build_mcp_server_identity(config_path="", command=command, args=args, transport=transport)
    return build_tool_call_artifact(
        harness="codex",
        server_name="shop-services",
        tool_name=tool,
        source_scope="project",
        config_path=".mcp.json",
        transport=transport,
        server_identity=identity,
    )


def enabled_store() -> _AuthorityStore:
    return _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, CATALOG_ID, ControlState.ENABLED),))


def test_reviewed_inventory_and_external_binding(kranz_payload: dict) -> None:
    validate_mcp_contribution(kranz_payload, filename="mcp.kranz.json")
    assert catalog_id_for_mcp_id(kranz_payload["id"]) == CATALOG_ID
    assert kranz_payload["trustClass"] == "external"
    assert kranz_payload["activation"] == "opt-in"
    assert kranz_payload["launch"] == {"kind": "direct-command", "command": "kranz"}
    assert kranz_payload["publisher"]["displayName"] == "Community"
    names = [tool["name"] for tool in kranz_payload["tools"]]
    assert len(names) == len(set(names))
    assert set(names) == set(MUTATIONS) | set(OBSERVATIONS) | {"other"}
    binding = json.loads((ROOT / f"contracts/extensions/trust/{CATALOG_ID}.v1.json").read_bytes())
    assert binding == {
        "extension": CATALOG_ID,
        "schemaVersion": "guard.extension-trust-binding.v1",
        "trustClass": "external",
    }


def test_canonical_native_compilation_contains_mcp_coverage(compiled: dict) -> None:
    # Use current source compilation even when checked-in projections await regeneration.
    program = compiled["program"]
    catalog = {
        "schema": "guard.command-catalog.v1",
        "catalog": compiled["catalog"],
        "catalog_digest": program["catalog_digest"],
        "program_digest": program["program_digest"],
        "source_digest": compiled["source_digest"],
        "implementation_digest": compiled["implementation_digest"],
    }
    registry = load_generated_command_catalog_bytes(canonical(catalog), canonical(program))
    extension = registry.get(CATALOG_ID)
    assert extension is not None
    value = extension.to_dict()
    assert value["surface"] == "mcp"
    assert value["trust_class"] == "external"
    assert value["activation"] == "opt-in"
    assert value["enabled"] is False
    assert value["mcp_launch"] == {"kind": "direct-command", "command": "kranz"}
    assert value["permissions"][0]["configurable"] is False
    assert registry.get("command.kranz") is not None


@pytest.mark.parametrize("tool", (*MUTATIONS, "future_mutation"))
def test_locally_enabled_mutations_require_review(kranz_payload: dict, monkeypatch, tool: str) -> None:
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (kranz_payload,))
    assert mcp_tool_state(kranz_payload, tool) == "review"
    decision = grants.apply_contributed_mcp_decision(enabled_store(), artifact(tool), "allow")
    assert decision is not None
    assert decision[0:2] == ("review", "catalog-mcp-extension")


@pytest.mark.parametrize("tool", OBSERVATIONS)
def test_observation_tools_inherit_without_allow_grants(kranz_payload: dict, monkeypatch, tool: str) -> None:
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (kranz_payload,))
    assert mcp_tool_state(kranz_payload, tool) == "inherit"
    for current in ("allow", "review", "block"):
        assert grants.apply_contributed_mcp_decision(enabled_store(), artifact(tool), current) is None


@pytest.mark.parametrize(
    "layers",
    [
        (),
        ((ControlLayerKind.SIGNED_CLOUD, ControlState.ENABLED),),
        ((ControlLayerKind.LOCAL_ADMIN, ControlState.DISABLED),),
        (
            (ControlLayerKind.LOCAL_ADMIN, ControlState.ENABLED),
            (ControlLayerKind.SIGNED_CLOUD, ControlState.DISABLED),
        ),
    ],
)
def test_contribution_stays_inert_without_effective_local_enable(kranz_payload: dict, monkeypatch, layers) -> None:
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (kranz_payload,))
    store = _AuthorityStore(tuple(_layer(kind, CATALOG_ID, state) for kind, state in layers))
    for tool in MUTATIONS:
        assert grants.apply_contributed_mcp_decision(store, artifact(tool), "allow") is None


@pytest.mark.parametrize("current", ["block", "require-reapproval", "review", "sandbox-required"])
def test_review_default_preserves_stronger_floors(kranz_payload: dict, monkeypatch, current: str) -> None:
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (kranz_payload,))
    assert grants.apply_contributed_mcp_decision(enabled_store(), artifact("action_run"), current) is None


@pytest.mark.parametrize(
    "command,args",
    [
        ("kranz", ("mcp",)),
        ("/opt/tools/kranz", ("mcp", "-C", "/workspace/shop")),
        ("kranz", ("mcp", "-p", "shop")),
    ],
)
def test_launch_identity_matches_independent_of_server_alias_and_project_flags(
    kranz_payload: dict, monkeypatch, command: str, args: tuple[str, ...]
) -> None:
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (kranz_payload,))
    assert grants.matching_mcp_contribution(artifact("action_run", command, args)) == kranz_payload


@pytest.mark.parametrize(
    "command,args,transport",
    [
        ("shop-mcp", ("mcp",), "stdio"),
        ("sh", ("-c", "kranz mcp"), "stdio"),
        ("go", ("run", "github.com/kranz-org/kranz", "mcp"), "stdio"),
        ("docker", ("run", "example/kranz", "mcp"), "stdio"),
        ("kranz", ("mcp",), "http"),
    ],
)
def test_unrelated_launchers_and_remote_transport_do_not_match(
    kranz_payload: dict, monkeypatch, command: str, args: tuple[str, ...], transport: str
) -> None:
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (kranz_payload,))
    assert grants.matching_mcp_contribution(artifact("action_run", command, args, transport)) is None


@pytest.mark.parametrize("state,expected", [("allow", "allow"), ("review", "review"), ("block", "block")])
def test_this_device_grant_precedes_catalog_defaults(monkeypatch, tmp_path: Path, state: str, expected: str) -> None:
    from codex_plugin_scanner.guard.store import GuardStore

    from .test_guard_local_mcp_grants import _enroll

    tool = artifact("action_run")
    identity = build_mcp_server_identity(config_path="", command="kranz", args=("mcp",), transport="stdio")
    store = GuardStore(tmp_path / "guard-home")
    _enroll(
        store,
        identity,
        states={"action_run": state},
        commands=(LocalCliCommand("action_run", "Run action", "action_run", "Run action"),),
    )

    def unexpected_catalog_read():
        pytest.fail("A this-device grant must take precedence over contributed defaults")

    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", unexpected_catalog_read)
    decision = apply_local_mcp_extension_decision(store, tool, "review")
    assert decision is not None
    assert decision[0:2] == (expected, "local-mcp-extension")
