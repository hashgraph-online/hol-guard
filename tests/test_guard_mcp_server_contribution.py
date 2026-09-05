"""Contribution schema and catalog wiring for MCP server extensions."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import mcp_server_contribution as mcp_module
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_trust import ids_for_class, trust_class_for
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    catalog_id_for_mcp_id,
    catalog_mcp_fields,
    load_mcp_contribution_payloads,
    mcp_catalog_ids,
    mcp_tool_state,
    validate_mcp_contribution,
)

_FILESYSTEM = Path(__file__).resolve().parents[1] / "contributions/mcp-servers/mcp.filesystem.json"


def _filesystem_payload() -> dict[str, object]:
    payload = json.loads(_FILESYSTEM.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_in_tree_mcp_contributions_are_external_catalog_ids() -> None:
    payloads = load_mcp_contribution_payloads()
    ids = {catalog_id_for_mcp_id(str(item["id"])) for item in payloads}
    assert ids == mcp_catalog_ids()
    assert ids <= ids_for_class("external")
    assert "command.mcp-filesystem" in ids
    for payload in payloads:
        validate_mcp_contribution(payload, filename=str(payload["id"]))


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


def test_action_classes_preserve_id_separators() -> None:
    from codex_plugin_scanner.guard.runtime.mcp_server_catalog import _action_class_for

    assert _action_class_for("mcp.foo.bar") != _action_class_for("mcp.foo-bar")


def test_mcp_contribution_rejects_unknown_icon() -> None:
    payload = _filesystem_payload()
    payload["icon"] = {"kind": "react-icon", "name": "NotAnAllowlistedIcon"}
    with pytest.raises(ValueError, match="allowlisted"):
        validate_mcp_contribution(payload, filename="icon.json")


def test_filesystem_catalog_item_is_external_opt_in() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.mcp-filesystem")
    assert extension is not None
    payload = extension.to_dict()
    assert payload["enabled"] is False
    assert payload["trust_class"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["surface"] == "mcp"
    assert payload["mcp_launch"]["package"] == "@modelcontextprotocol/server-filesystem"
    assert payload["publisher"]["id"] == "community.modelcontextprotocol"
    assert payload["icon"]["name"] == "HiMiniFolder"
    assert trust_class_for("command.mcp-filesystem") == "external"
    overlay = catalog_mcp_fields("command.mcp-filesystem")
    assert overlay is not None
    assert overlay["surface"] == "mcp"


def test_mcp_tool_state_uses_named_then_other() -> None:
    payload = _filesystem_payload()
    assert mcp_tool_state(payload, "write_file") == "block"
    assert mcp_tool_state(payload, "read_file") == "inherit"
    assert mcp_tool_state(payload, "unknown_tool") == "inherit"


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


def test_frozen_mcp_payloads_load_from_meipass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dest = tmp_path / "codex_plugin_scanner" / "guard" / "contracts" / "data" / "mcp_servers"
    contributions = dest / "contributions"
    contributions.mkdir(parents=True)
    shutil.copyfile(_FILESYSTEM, contributions / "mcp.filesystem.json")
    shutil.copyfile(
        Path(__file__).resolve().parents[1] / "contracts" / "mcp-servers" / "contribution.v1.schema.json",
        dest / "contribution.v1.schema.json",
    )
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    def missing_package(_name: str) -> object:
        raise ModuleNotFoundError("missing packaged MCP servers")

    monkeypatch.setattr(mcp_module.resources, "files", missing_package)
    mcp_module.reset_mcp_contribution_cache()
    try:
        payloads = mcp_module._load_packaged_payloads()
        assert any(item.get("id") == "mcp.filesystem" for item in payloads)
    finally:
        mcp_module.reset_mcp_contribution_cache()


def test_frozen_mcp_payloads_fail_closed_without_package_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    def missing_package(_name: str) -> object:
        raise ModuleNotFoundError("missing packaged MCP servers")

    monkeypatch.setattr(mcp_module.resources, "files", missing_package)
    with pytest.raises(FileNotFoundError, match="contributions"):
        mcp_module._load_packaged_payloads()
