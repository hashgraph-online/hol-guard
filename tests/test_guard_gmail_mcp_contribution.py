"""Hosted Gmail MCP defaults stay opt-in, endpoint-bound and unable to add allow authority."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime import mcp_server_grants as grants
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState
from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import load_generated_command_catalog_bytes
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    catalog_id_for_mcp_id,
    mcp_tool_state,
    validate_mcp_contribution,
)

from .test_guard_mcp_server_grants import _AuthorityStore, _layer
from .test_native_source_program import build as build
from .test_native_source_program import canonical
from .test_native_source_program import compiled as compiled
from .test_native_source_program import compiler as compiler

ROOT = Path(__file__).resolve().parents[1]
CATALOG_ID = "command.mcp-google-workspace.gmail"
ENDPOINT = "https://gmailmcp.googleapis.com/mcp/v1"
MUTATIONS = (
    "create_draft",
    "label_thread",
    "unlabel_thread",
    "label_message",
    "unlabel_message",
    "create_label",
)
OBSERVATIONS = ("list_drafts", "get_thread", "get_message", "search_threads", "list_labels")


@pytest.fixture(scope="module")
def gmail_payload() -> dict:
    return json.loads((ROOT / "contributions/mcp-servers/mcp.google-workspace.gmail.json").read_bytes())


def artifact(tool: str, url: str = ENDPOINT, server_name: str = "work-mail", transport: str = "http"):
    identity = build_mcp_server_identity(config_path=".mcp.json", command=url, args=(), transport=transport)
    return build_tool_call_artifact(
        harness="codex",
        server_name=server_name,
        tool_name=tool,
        source_scope="project",
        config_path=".mcp.json",
        transport=transport,
        server_identity=identity,
    )


def enabled_store() -> _AuthorityStore:
    return _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, CATALOG_ID, ControlState.ENABLED),))


def test_documented_inventory_external_binding_and_no_allow_state(gmail_payload: dict) -> None:
    validate_mcp_contribution(gmail_payload, filename="mcp.google-workspace.gmail.json")
    assert catalog_id_for_mcp_id(gmail_payload["id"]) == CATALOG_ID
    assert gmail_payload["trustClass"] == "external"
    assert gmail_payload["activation"] == "opt-in"
    assert gmail_payload["launch"]["kind"] == "remote-http"
    assert gmail_payload["launch"]["url"] == ENDPOINT
    names = [tool["name"] for tool in gmail_payload["tools"]]
    assert len(names) == len(set(names))
    assert set(names) == set(MUTATIONS) | set(OBSERVATIONS) | {"other"}
    assert not any("send" in name for name in names)
    assert all(tool["state"] in {"inherit", "review"} for tool in gmail_payload["tools"])
    binding = json.loads((ROOT / f"contracts/extensions/trust/{CATALOG_ID}.v1.json").read_bytes())
    assert binding == {
        "extension": CATALOG_ID,
        "schemaVersion": "guard.extension-trust-binding.v1",
        "trustClass": "external",
    }


def test_canonical_native_compilation_contains_gmail_mcp_coverage(compiled: dict) -> None:
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


@pytest.mark.parametrize("tool", (*MUTATIONS, "send_message", "future_tool"))
def test_locally_enabled_mailbox_changes_and_unknown_tools_require_review(
    gmail_payload: dict, monkeypatch, tool: str
) -> None:
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (gmail_payload,))
    assert mcp_tool_state(gmail_payload, tool) == "review"
    decision = grants.apply_contributed_mcp_decision(enabled_store(), artifact(tool), "allow")
    assert decision is not None
    assert decision[0:2] == ("review", "catalog-mcp-extension")


@pytest.mark.parametrize("tool", OBSERVATIONS)
def test_read_tools_inherit_without_allow_grants(gmail_payload: dict, monkeypatch, tool: str) -> None:
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (gmail_payload,))
    assert mcp_tool_state(gmail_payload, tool) == "inherit"
    for current in ("allow", "review", "block"):
        assert grants.apply_contributed_mcp_decision(enabled_store(), artifact(tool), current) is None


@pytest.mark.parametrize(
    "layers",
    [
        (),
        ((ControlLayerKind.SIGNED_CLOUD, ControlState.ENABLED),),
        ((ControlLayerKind.LOCAL_ADMIN, ControlState.DISABLED),),
    ],
)
def test_contribution_stays_inert_without_effective_local_enable(gmail_payload: dict, monkeypatch, layers) -> None:
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (gmail_payload,))
    store = _AuthorityStore(tuple(_layer(kind, CATALOG_ID, state) for kind, state in layers))
    for tool in MUTATIONS:
        assert grants.apply_contributed_mcp_decision(store, artifact(tool), "allow") is None


@pytest.mark.parametrize("current", ["block", "require-reapproval", "review", "sandbox-required"])
def test_review_default_preserves_stronger_floors(gmail_payload: dict, monkeypatch, current: str) -> None:
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (gmail_payload,))
    assert grants.apply_contributed_mcp_decision(enabled_store(), artifact("create_draft"), current) is None


@pytest.mark.parametrize("server_name", ["gmail", "production-mail"])
def test_exact_endpoint_matches_under_any_server_name(gmail_payload: dict, monkeypatch, server_name: str) -> None:
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (gmail_payload,))
    assert grants.matching_mcp_contribution(artifact("create_draft", server_name=server_name)) == gmail_payload


@pytest.mark.parametrize(
    "url",
    [
        "https://gmailmcp.googleapis.com/mcp/v2",
        "https://gmail.googleapis.com/mcp/v1",
        "https://gmailmcp.googleapis.com.example.test/mcp/v1",
        "https://example.test/gmail/mcp/v1",
    ],
)
def test_other_endpoints_do_not_match_even_with_listed_server_name(gmail_payload: dict, monkeypatch, url: str) -> None:
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (gmail_payload,))
    assert grants.matching_mcp_contribution(artifact("create_draft", url=url, server_name="gmail")) is None


def name_only_artifact(tool: str, server_name: str) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=f"codex:runtime:project:{server_name}:{tool}",
        name=f"{server_name}:{tool}",
        harness="codex",
        artifact_type="tool_call",
        source_scope="project",
        config_path=".mcp.json",
        command=tool,
        transport="http",
        metadata={"server_name": server_name},
    )


@pytest.mark.parametrize("server_name", ["gmail", "gmail-mcp", "google-gmail"])
def test_listed_server_names_match_without_endpoint_evidence(
    gmail_payload: dict, monkeypatch, server_name: str
) -> None:
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (gmail_payload,))
    assert grants.matching_mcp_contribution(name_only_artifact("create_draft", server_name)) == gmail_payload


@pytest.mark.parametrize("server_name", ["work-mail", "gmail-backup", "google"])
def test_unlisted_server_names_do_not_match_without_endpoint_evidence(
    gmail_payload: dict, monkeypatch, server_name: str
) -> None:
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (gmail_payload,))
    assert grants.matching_mcp_contribution(name_only_artifact("create_draft", server_name)) is None
