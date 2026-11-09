"""Contribution schema and catalog wiring for MCP server extensions."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.mcp_server_contribution import validate_mcp_contribution
from tests import mcp_contribution_loader as mcp_loader
from tests.mcp_contribution_loader import load_mcp_contribution_payloads

from .mcp_contribution_client import mcp_tool_state

_FILESYSTEM = Path(__file__).resolve().parents[1] / "contributions/mcp-servers/mcp.filesystem.json"
_TETHER = _FILESYSTEM.with_name("mcp.tether.json")
_DEV_MCP = _FILESYSTEM.with_name("mcp.dev-mcp.json")


def _filesystem_payload() -> dict[str, object]:
    payload = json.loads(_FILESYSTEM.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _tether_payload() -> dict[str, object]:
    """Read the authored Tether manifest so missing tools cannot hide behind fallback defaults."""
    payload = json.loads(_TETHER.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload



def _dev_mcp_payload() -> dict[str, object]:
    payload = json.loads(_DEV_MCP.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_tether_contribution_is_external_opt_in() -> None:
    """Keep Tether bound to its published package and explicit local opt-in."""
    payload = _tether_payload()
    validate_mcp_contribution(payload, filename=_TETHER.name)
    assert payload["id"] == "mcp.tether"
    assert payload["trustClass"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["launch"] == {"kind": "package-launcher", "command": "uvx", "package": "tether-memory"}


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
        "update_context",
        "add_to_context_list",
        "remove_context_item",
        "update_prd",
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
