"""Contribution schema and catalog wiring for MCP server extensions."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import _normalized_tool_name, validate_mcp_contribution
from tests import mcp_contribution_loader as mcp_loader
from tests.mcp_contribution_loader import load_mcp_contribution_payloads

from .mcp_contribution_client import mcp_tool_state
from .mcp_extension_driver import apply_contributed_mcp_decision
from .test_guard_mcp_server_grants import _AuthorityStore, _layer

_FILESYSTEM = Path(__file__).resolve().parents[1] / "contributions/mcp-servers/mcp.filesystem.json"
_TETHER = _FILESYSTEM.with_name("mcp.tether.json")
_AGENTIC_LINKEDIN = _FILESYSTEM.with_name("mcp.agentic-linkedin.json")
_DEV_MCP = _FILESYSTEM.with_name("mcp.dev-mcp.json")
_REI_SKILLS = _FILESYSTEM.with_name("mcp.rei-skills.json")
_WEBCRAWL = _FILESYSTEM.with_name("mcp.webcrawl.json")
_LIENZO_UI = _FILESYSTEM.with_name("mcp.lienzo-ui.json")
_KRUSCH_SKYLIGHT = _FILESYSTEM.with_name("mcp.krusch-skylight.json")
_NJC_CHAIN_READS = _FILESYSTEM.with_name("mcp.njc-chain-reads.json")
_LIENZO_UI = _FILESYSTEM.with_name("mcp.lienzo-ui.json")
_NJC_CHAIN_READS_URL = "https://njc-tx-explain.departmentofjazz.workers.dev/mcp"


def _filesystem_payload() -> dict[str, object]:
    payload = json.loads(_FILESYSTEM.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _tether_payload() -> dict[str, object]:
    """Read the authored Tether manifest so missing tools cannot hide behind fallback defaults."""
    payload = json.loads(_TETHER.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _agentic_linkedin_payload() -> dict[str, object]:
    payload = json.loads(_AGENTIC_LINKEDIN.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _dev_mcp_payload() -> dict[str, object]:
    payload = json.loads(_DEV_MCP.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _njc_chain_reads_payload() -> dict[str, object]:
    payload = json.loads(_NJC_CHAIN_READS.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _krusch_skylight_payload() -> dict[str, object]:
    payload = json.loads(_KRUSCH_SKYLIGHT.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _lienzo_ui_payload() -> dict[str, object]:
    payload = json.loads(_LIENZO_UI.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _rei_skills_payload() -> dict[str, object]:
    payload = json.loads(_REI_SKILLS.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _webcrawl_payload() -> dict[str, object]:
    payload = json.loads(_WEBCRAWL.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_webcrawl_launch_package_is_version_pinned() -> None:
    """Keep the reviewed webcrawl launch on the exact npm version."""
    payload = _webcrawl_payload()
    validate_mcp_contribution(payload, filename=_WEBCRAWL.name)
    assert payload["id"] == "mcp.webcrawl"
    assert payload["trustClass"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["launch"] == {
        "kind": "package-launcher",
        "command": "npx",
        "package": "@webcrawl/mcp@1.4.5",
    }


def test_webcrawl_unlisted_tools_require_review_once_locally_enabled() -> None:
    payload = _webcrawl_payload()
    assert mcp_tool_state(payload, "web_monitor") == "review"
    assert mcp_tool_state(payload, "unlisted_future_tool") == "review"
    assert mcp_tool_state(payload, "web_parse_status") == "inherit"

    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npx",
        args=("-y", "@webcrawl/mcp@1.4.5"),
        transport="stdio",
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="webcrawl",
        tool_name="unlisted_future_tool",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
    )
    catalog_id = "command.mcp-webcrawl"
    assert apply_contributed_mcp_decision(_AuthorityStore(), artifact, "allow") is None
    cloud_only = _AuthorityStore((_layer(ControlLayerKind.SIGNED_CLOUD, catalog_id, ControlState.ENABLED),))
    assert apply_contributed_mcp_decision(cloud_only, artifact, "allow") is None
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, catalog_id, ControlState.ENABLED),))
    decision = apply_contributed_mcp_decision(enabled, artifact, "allow")
    assert decision is not None
    assert decision[:2] == ("review", "catalog-mcp-extension")


def test_rei_skills_launch_package_is_version_pinned() -> None:
    """Keep the reviewed rei-skills launch on the exact npm version."""
    payload = _rei_skills_payload()
    validate_mcp_contribution(payload, filename=_REI_SKILLS.name)
    assert payload["id"] == "mcp.rei-skills"
    assert payload["trustClass"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["launch"] == {
        "kind": "package-launcher",
        "command": "npx",
        "package": "rei-skills@6.2.0",
    }


def test_rei_skills_tool_defaults_preserve_review_boundary() -> None:
    payload = _rei_skills_payload()
    defaults = {tool["name"]: tool["state"] for tool in payload["tools"]}
    assert defaults == {
        "rei_recommend_skills": "inherit",
        "rei_search_skills": "inherit",
        "rei_get_skill": "inherit",
        "rei_get_workflow": "inherit",
        "rei_list_bundles": "inherit",
        "rei_compile_skill": "inherit",
        "rei_list_ai_targets": "inherit",
        "rei_install_skill": "review",
        "other": "review",
    }
    assert mcp_tool_state(payload, "unlisted_tool") == "review"


def test_lienzo_ui_launch_package_is_version_pinned() -> None:
    """Keep the reviewed Lienzo UI launch on the exact npm release."""
    payload = json.loads(_LIENZO_UI.read_text(encoding="utf-8"))
    validate_mcp_contribution(payload, filename=_LIENZO_UI.name)
    assert payload["trustClass"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["launch"] == {
        "kind": "package-launcher",
        "command": "npx",
        "package": "lienzo-ui-mcp@1.7.4",
    }


def test_lienzo_ui_export_and_its_hidden_alias_require_review() -> None:
    """The server accepts exportar_unity for export_unity; both names must stay review-gated."""
    payload = json.loads(_LIENZO_UI.read_text(encoding="utf-8"))
    declared = {tool["name"]: tool["state"] for tool in payload["tools"]}
    for name in ("export_unity", "exportar_unity"):
        assert declared[name] == "review"
        assert mcp_tool_state(payload, name) == "review"
    assert mcp_tool_state(payload, "lienzo_info") == "allow"


def test_tether_contribution_is_external_opt_in() -> None:
    """Keep Tether bound to its published package and explicit local opt-in."""
    payload = _tether_payload()
    validate_mcp_contribution(payload, filename=_TETHER.name)
    assert payload["id"] == "mcp.tether"
    assert payload["trustClass"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["launch"] == {"kind": "package-launcher", "command": "uvx", "package": "tether-memory"}


def test_agentic_linkedin_launch_package_is_version_pinned() -> None:
    """Keep the reviewed agentic-linkedin launch on the exact npm version."""
    payload = _agentic_linkedin_payload()
    validate_mcp_contribution(payload, filename=_AGENTIC_LINKEDIN.name)
    assert payload["id"] == "mcp.agentic-linkedin"
    assert payload["trustClass"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["launch"] == {
        "kind": "package-launcher",
        "command": "npx",
        "package": "agentic-linkedin@0.1.0",
    }


def test_agentic_linkedin_private_reads_require_review() -> None:
    payload = _agentic_linkedin_payload()
    defaults = {tool["name"]: tool["state"] for tool in payload["tools"]}
    assert defaults["get_posts"] == "review"
    assert defaults["get_voice_profile"] == "review"
    assert mcp_tool_state(payload, "get_posts") == "review"
    assert mcp_tool_state(payload, "get_voice_profile") == "review"


def test_agentic_linkedin_stays_inert_until_local_admin_enable() -> None:
    """Keep LinkedIn tools inert until a local admin enables the external catalog entry."""
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npx",
        args=("-y", "agentic-linkedin@0.1.0"),
        transport="stdio",
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="agentic-linkedin",
        tool_name="get_posts",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
    )
    catalog_id = "command.mcp-agentic-linkedin"
    assert apply_contributed_mcp_decision(_AuthorityStore(), artifact, "allow") is None
    assert (
        apply_contributed_mcp_decision(
            _AuthorityStore((_layer(ControlLayerKind.SIGNED_CLOUD, catalog_id, ControlState.ENABLED),)),
            artifact,
            "allow",
        )
        is None
    )
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, catalog_id, ControlState.ENABLED),))
    decision = apply_contributed_mcp_decision(enabled, artifact, "allow")
    assert decision is not None
    assert decision[:2] == ("review", "catalog-mcp-extension")


def test_tether_declares_every_memory_tool_with_inherited_policy() -> None:
    """Require all four memory verbs before checking their inherited states."""
    payload = _tether_payload()
    tools = payload.get("tools")
    assert isinstance(tools, list)
    declared = {item["name"]: item["state"] for item in tools}
    required = {"remember", "recall", "link", "forget"}
    assert required <= declared.keys()
    for tool_name in required:
        assert declared[tool_name] == "inherit"
        assert mcp_tool_state(payload, tool_name) == "inherit"


def test_tether_unknown_tool_inherits_policy() -> None:
    """Check the fallback independently of the required memory-tool declarations."""
    payload = _tether_payload()
    tools = payload.get("tools")
    assert isinstance(tools, list)
    declared = {item["name"]: item["state"] for item in tools}
    assert declared["other"] == "inherit"
    assert "unknown_tool" not in declared
    assert mcp_tool_state(payload, "unknown_tool") == "inherit"


def test_dev_mcp_contribution_is_external_opt_in() -> None:
    """Keep dev-mcp pinned to its publisher repository and explicitly opt-in."""
    payload = _dev_mcp_payload()
    validate_mcp_contribution(payload, filename=_DEV_MCP.name)
    assert payload["id"] == "mcp.dev-mcp"
    assert payload["trustClass"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["launch"] == {
        "kind": "package-launcher",
        "command": "uvx",
        "package": "git+https://github.com/pranjal2410719/dev-mcp.git@0e842cfc6c60d62cbe517b198db0df9a9024e8cb",
    }


def test_dev_mcp_sensitive_tools_require_review() -> None:
    """Keep execution, filesystem, Git, and project-state mutations review-gated."""
    payload = _dev_mcp_payload()
    tools = payload.get("tools")
    assert isinstance(tools, list)
    declared = {item["name"]: item["state"] for item in tools}
    review_tools = {
        "run_command",
        "desktop_action",
        "desktop_click",
        "desktop_type",
        "desktop_press",
        "desktop_scroll",
        "desktop_launch",
        "desktop_close_app",
        "desktop_focus_window",
        "desktop_clipboard",
        "desktop_screenshot",
        "delete_path",
        "delete_recursive",
        "reset_project_brain",
        "reset_context",
        "write_file",
        "edit_file",
        "batch_replace",
        "create_directory",
        "git_add",
        "git_commit",
        "git_create_branch",
        "install_git_hooks",
        "commit_changes",
        "adopt_existing_project",
        "bootstrap_project",
        "create_project_workspace",
        "archive_project_brain",
        "init_context",
        "update_context",
        "update_prd",
        "add_to_context_list",
        "remove_context_item",
        "add_key_file",
        "add_decision",
        "get_context",
        "generate_handoff",
        "create_task",
        "set_phase",
        "update_task",
        "complete_task",
        "complete_phase",
        "next_phase",
        "add_milestone",
        "add_task",
        "end_session",
        "extract_requirements",
        "sync_workspace",
        "export_context_markdown",
    }
    assert review_tools <= declared.keys()
    for tool_name in review_tools:
        assert declared[tool_name] == "review"
        assert mcp_tool_state(payload, tool_name) == "review"


def test_dev_mcp_unlisted_tools_default_to_review() -> None:
    """Keep future/unlisted dev-mcp tools on the conservative review fallback."""
    payload = _dev_mcp_payload()
    tools = payload.get("tools")
    assert isinstance(tools, list)
    declared = {item["name"]: item["state"] for item in tools}
    assert declared["other"] == "review"
    assert mcp_tool_state(payload, "unlisted_future_tool") == "review"


def test_njc_chain_reads_contribution_is_external_opt_in_remote() -> None:
    """Keep the hosted chain-reads server external, opt-in and bound to its HTTPS endpoint."""
    payload = _njc_chain_reads_payload()
    validate_mcp_contribution(payload, filename=_NJC_CHAIN_READS.name)
    assert payload["id"] == "mcp.njc-chain-reads"
    assert payload["trustClass"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["launch"] == {
        "kind": "remote-http",
        "url": "https://njc-tx-explain.departmentofjazz.workers.dev/mcp",
        "serverNames": ["njc-chain-reads", "rh-tx-explain"],
    }


def test_krusch_skylight_local_writes_require_review() -> None:
    """Keep tools that can write local state review-gated even when they look like reads."""
    payload = _krusch_skylight_payload()
    validate_mcp_contribution(payload, filename=_KRUSCH_SKYLIGHT.name)
    declared = {tool["name"]: tool["state"] for tool in payload["tools"]}
    assert payload["launch"] == {"kind": "direct-command", "command": "krusch-skylight-mcp"}
    for tool_name in ("skylight_status", "skylight_list_events", "skylight_pull_chores", "skylight_list_meals"):
        assert declared[tool_name] == "review"
        assert mcp_tool_state(payload, tool_name) == "review"


def test_lienzo_ui_stays_inert_until_local_admin_enable() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npx",
        args=("-y", "lienzo-ui-mcp@1.7.4"),
        transport="stdio",
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="lienzo-ui",
        tool_name="exportar_unity",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
    )
    assert apply_contributed_mcp_decision(_AuthorityStore(), artifact, "allow") is None
    enabled = _AuthorityStore(
        (_layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-lienzo-ui", ControlState.ENABLED),)
    )
    decision = apply_contributed_mcp_decision(enabled, artifact, "allow")
    assert decision is not None
    assert decision[:2] == ("review", "catalog-mcp-extension")


def test_njc_chain_reads_paid_tools_require_review() -> None:
    """Paid reads settle an attached x402 payment from the caller's wallet, so they stay review-gated."""
    payload = _njc_chain_reads_payload()
    declared = {tool["name"]: tool["state"] for tool in payload["tools"]}
    free = {"explain_transaction", "who_controls_agent", "jobs_board"}
    paid = {
        "money_trail",
        "line_read",
        "transfer_read",
        "sol_trail",
        "base_trail",
        "halt_check",
        "usdg_ledger",
        "wallet_handover",
        "poison_check",
        "income_read",
    }
    assert "allow" not in declared.values()
    for tool_name in free:
        assert declared[tool_name] == "inherit"
        assert mcp_tool_state(payload, tool_name) == "inherit"
    for tool_name in paid:
        assert declared[tool_name] == "review"
        assert mcp_tool_state(payload, tool_name) == "review"


def test_njc_chain_reads_unlisted_tools_default_to_review() -> None:
    """Keep future chain-read tools on the conservative review fallback."""
    payload = _njc_chain_reads_payload()
    declared = {tool["name"]: tool["state"] for tool in payload["tools"]}
    assert declared["other"] == "review"
    normalized_declared = {_normalized_tool_name(name) for name in declared}
    assert _normalized_tool_name("unlisted_future_tool") not in normalized_declared
    assert mcp_tool_state(payload, "unlisted_future_tool") == "review"


def test_njc_chain_reads_stays_inert_until_local_admin_enable() -> None:
    """Keep the paid remote tool inert until the external catalog entry is enabled locally."""
    identity = build_mcp_server_identity(
        config_path=".mcp.json", command=_NJC_CHAIN_READS_URL, args=(), transport="http"
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="njc-chain-reads",
        tool_name="money_trail",
        source_scope="project",
        config_path=".mcp.json",
        transport="http",
        server_identity=identity,
    )
    assert apply_contributed_mcp_decision(_AuthorityStore(), artifact, "allow") is None
    enabled = _AuthorityStore(
        (_layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-njc-chain-reads", ControlState.ENABLED),)
    )
    decision = apply_contributed_mcp_decision(enabled, artifact, "allow")
    assert decision is not None
    assert decision[:2] == ("review", "catalog-mcp-extension")


def test_filesystem_contribution_cannot_self_declare_trusted_library() -> None:
    payload = _filesystem_payload()
    payload["trustClass"] = "trusted-library"
    with pytest.raises(ValueError, match="schema"):
        validate_mcp_contribution(payload, filename="evil.json")


def test_mcp_contribution_rejects_svg_ref_icons() -> None:
    payload = _filesystem_payload()
    payload["icon"] = {"kind": "svg-ref", "name": "untrusted-symbol"}
    with pytest.raises(ValueError, match="schema"):
        validate_mcp_contribution(payload, filename="svg.json")


def test_mcp_contribution_requires_safer_alternatives() -> None:
    payload = _filesystem_payload()
    del payload["saferAlternatives"]
    with pytest.raises(ValueError, match="schema"):
        validate_mcp_contribution(payload, filename="safer.json")


def test_mcp_contribution_rejects_whitespace_aliased_tool_names() -> None:
    payload = _filesystem_payload()
    payload["tools"] = [
        {"name": " read_file", "state": "allow"},
        {"name": "read_file ", "state": "block"},
        {"name": "other", "state": "inherit"},
    ]
    with pytest.raises(ValueError, match="duplicate"):
        validate_mcp_contribution(payload, filename="dup.json")


def test_mcp_contribution_rejects_unknown_icon() -> None:
    payload = _filesystem_payload()
    payload["icon"] = {"kind": "react-icon", "name": "NotAnAllowlistedIcon"}
    with pytest.raises(ValueError, match="allowlisted"):
        validate_mcp_contribution(payload, filename="icon.json")


def test_duplicate_launch_packages_are_rejected(tmp_path: Path) -> None:
    first = _filesystem_payload()
    second = _filesystem_payload()
    second["id"] = "mcp.filesystem-dup"
    directory = tmp_path / "mcp-servers"
    directory.mkdir()
    (directory / "mcp.filesystem.json").write_text(json.dumps(first), encoding="utf-8")
    (directory / "mcp.filesystem-dup.json").write_text(json.dumps(second), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate MCP launch package"):
        load_mcp_contribution_payloads(directory)


def test_frozen_mcp_payloads_fail_closed_without_package_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    def missing_package(_name: str) -> object:
        raise ModuleNotFoundError("missing packaged MCP servers")

    monkeypatch.setattr(mcp_loader.resources, "files", missing_package)
    with pytest.raises(FileNotFoundError, match="contributions"):
        mcp_loader._load_packaged_payloads()
