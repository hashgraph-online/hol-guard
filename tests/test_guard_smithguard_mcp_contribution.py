"""SmithGuard is optional evidence: native defaults only tighten approved MCP calls."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState
from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog
from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import _extension
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import validate_mcp_contribution
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_directory_inventory import catalog_rows

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401
from .mcp_extension_driver import apply_contributed_mcp_decision, apply_local_mcp_extension_decision
from .test_guard_mcp_server_grants import _AuthorityStore, _layer
from .test_native_source_program import canonical_packs as canonical_packs
from .test_native_source_program import compiler as compiler

ROOT = Path(__file__).resolve().parents[1]
CATALOG_ID = "command.mcp-smithguard"
ENDPOINT = "https://api.smithguard.io/mcp"
ASSESS = "assess_public_artifact"
READS = (
    "get_coverage",
    "get_verification_key",
    "get_emerging_leads",
    "list_bulletins",
    "get_bulletin",
    "get_bulletin_changes",
    "get_bulletin_status",
)


@pytest.fixture(scope="module")
def payload() -> dict:
    return json.loads((ROOT / "contributions/mcp-servers/mcp.smithguard.json").read_bytes())


def identity(url: str = ENDPOINT):
    return build_mcp_server_identity(config_path="", command=url, args=(), transport="http")


def artifact(tool: str = ASSESS, *, url: str = ENDPOINT, name: str = "smithguard") -> GuardArtifact:
    return build_tool_call_artifact(
        harness="codex",
        server_name=name,
        tool_name=tool,
        source_scope="project",
        config_path=".mcp.json",
        transport="http",
        server_identity=identity(url),
    )


def enabled() -> _AuthorityStore:
    return _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, CATALOG_ID, ControlState.ENABLED),))


def test_inventory_binding_and_public_endpoint(payload: dict) -> None:
    validate_mcp_contribution(payload, filename="mcp.smithguard.json")
    assert payload["id"] == "mcp.smithguard"
    assert payload["trustClass"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["launch"] == {"kind": "remote-http", "url": ENDPOINT, "serverNames": ["smithguard"]}
    names = [tool["name"] for tool in payload["tools"]]
    assert len(names) == len(set(names))
    assert {tool["name"]: tool["state"] for tool in payload["tools"]} == {
        ASSESS: "review",
        **dict.fromkeys(READS, "inherit"),
        "other": "review",
    }
    assert json.loads((ROOT / f"contracts/extensions/trust/{CATALOG_ID}.v1.json").read_bytes()) == {
        "extension": CATALOG_ID,
        "schemaVersion": "guard.extension-trust-binding.v1",
        "trustClass": "external",
    }


def test_native_catalog_contains_disabled_external_entry(canonical_packs) -> None:
    reader, release = canonical_packs
    registry = GeneratedCommandCatalog(tuple(_extension(row) for _, _, row in catalog_rows(reader, release)))
    extension = registry.get(CATALOG_ID)
    assert extension is not None
    value = extension.to_dict()
    assert value["surface"] == "mcp"
    assert value["trust_class"] == "external"
    assert value["activation"] == "opt-in"
    assert value["enabled"] is False


@pytest.mark.parametrize(
    "kind,state",
    [
        (None, None),
        (ControlLayerKind.SIGNED_CLOUD, ControlState.ENABLED),
        (ControlLayerKind.LOCAL_ADMIN, ControlState.DISABLED),
    ],
)
def test_inert_without_local_enable(kind, state) -> None:
    layers = () if kind is None else (_layer(kind, CATALOG_ID, state),)
    for tool in (ASSESS, "future_tool"):
        assert apply_contributed_mcp_decision(_AuthorityStore(layers), artifact(tool), "allow") is None


@pytest.mark.parametrize("tool", [ASSESS, "future_tool"])
@pytest.mark.parametrize("name", ["smithguard", "renamed-service"])
def test_assessment_and_unknown_tools_tighten_with_exact_endpoint(tool: str, name: str) -> None:
    decision = apply_contributed_mcp_decision(enabled(), artifact(tool, name=name), "allow")
    assert decision is not None and decision[:2] == ("review", "catalog-mcp-extension")


@pytest.mark.parametrize("tool", READS)
def test_metadata_tools_preserve_host_handling(tool: str) -> None:
    for current in ("allow", "review", "block"):
        assert apply_contributed_mcp_decision(enabled(), artifact(tool), current) is None


@pytest.mark.parametrize("current", ["block", "require-reapproval", "review", "sandbox-required"])
def test_assessment_never_weakens_a_floor(current: str) -> None:
    assert apply_contributed_mcp_decision(enabled(), artifact(), current) is None


@pytest.mark.parametrize(
    "url",
    [
        "https://example.test/mcp",
        "https://api.smithguard.io/other",
        "https://api.smithguard.io.example.test/mcp",
        "http://api.smithguard.io/mcp",
    ],
)
def test_wrong_or_malformed_endpoint_cannot_fall_back_to_name(url: str) -> None:
    assert apply_contributed_mcp_decision(enabled(), artifact(url=url), "allow") is None


@pytest.mark.parametrize("name,matched", [("smithguard", True), ("renamed-service", False)])
def test_name_only_fallback_can_only_tighten(name: str, matched: bool) -> None:
    candidate = GuardArtifact(
        artifact_id=f"codex:runtime:project:{name}:{ASSESS}",
        name=f"{name}:{ASSESS}",
        harness="codex",
        artifact_type="tool_call",
        source_scope="project",
        config_path=".mcp.json",
        command=ASSESS,
        transport="http",
        metadata={"server_name": name, "mcp_tool_identity": {"tool_name": ASSESS}},
    )
    decision = apply_contributed_mcp_decision(enabled(), candidate, "allow")
    assert (decision is not None) is matched
    if decision is not None:
        assert decision[0] == "review"
    assert apply_contributed_mcp_decision(enabled(), candidate, "block") is None


def test_descriptor_cannot_introduce_allow(payload: dict) -> None:
    changed = deepcopy(payload)
    changed["tools"][0]["state"] = "allow"
    with pytest.raises(ValueError, match="cannot declare allow defaults"):
        validate_mcp_contribution(changed)


@pytest.mark.parametrize("custom_state", ["allow", "block"])
def test_custom_device_grant_keeps_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, custom_state: str
) -> None:
    server = identity()
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(
        store, "read_extension_control_authority_for_registry", enabled().read_extension_control_authority_for_registry
    )
    cli = UnlistedCliIdentity(
        cli_id=f"local-cli.mcp-{server.identity_hash[:8]}",
        name="smithguard",
        kind="executable",
        identity_hash=server.identity_hash,
        example_label=ENDPOINT,
    )
    store.record_local_cli_observation(
        cli,
        seen_at=utc_now(),
        surface="mcp",
        server_identity_hash=server.identity_hash,
        server_command=server.command,
        server_args_hash=server.args_hash,
        help_status="ok",
    )
    store.replace_local_cli_commands(cli.cli_id, (LocalCliCommand(ASSESS, ASSESS, ASSESS, "Public assessment"),))
    store.upsert_local_cli_grant(
        identity=cli, state="allowed", expected_revision=0, updated_at=utc_now(), command_states={ASSESS: custom_state}
    )
    decision = apply_local_mcp_extension_decision(store, artifact(), "review")
    assert decision is not None and decision[:2] == (custom_state, "local-mcp-extension")
