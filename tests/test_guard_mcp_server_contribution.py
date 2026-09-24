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
    from codex_plugin_scanner.guard.runtime.command_permission_catalog import permissions_for_action_classes
    from codex_plugin_scanner.guard.runtime.mcp_server_catalog import _action_class_for

    dotted = _action_class_for("mcp.foo.bar")
    hyphen = _action_class_for("mcp.foo-bar")
    encoded = _action_class_for("mcp.foo-dot-bar")
    assert len({dotted, hyphen, encoded}) == 3
    assert _action_class_for("mcp.filesystem") == "mcp filesystem tool"
    extension_id = "command.mcp-test"
    ids = {
        permissions_for_action_classes(
            extension_id,
            "1.0.0",
            (action_class,),
            ("Inspect first.",),
            configurable=False,
        )[0].permission_id
        for action_class in (dotted, hyphen, encoded)
    }
    assert len(ids) == 3


def test_declared_display_name_matches_live_tool_name() -> None:
    payload = _filesystem_payload()
    payload["tools"] = [
        {"name": "Read File", "state": "block"},
        {"name": "other", "state": "inherit"},
    ]
    validate_mcp_contribution(payload, filename="alias.json")
    assert mcp_tool_state(payload, "read_file") == "block"


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
    assert payload["permissions"][0]["configurable"] is False
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


_QUIDLI_CONNECT = Path(__file__).resolve().parents[1] / "contributions/mcp-servers/mcp.quidli-connect.json"
_QUIDLI_CONNECT_URL = "https://mcp.connect.quid.li"
_QUIDLI_CONNECT_ID = "command.mcp-quidli-connect"
_QUIDLI_REVIEW_TOOLS = ("connect_drop", "connect_trust_create", "connect_trust_revoke", "connect_lookup_exposed")
_QUIDLI_INHERIT_TOOLS = (
    "connect_trust_check",
    "connect_trust_graph",
    "connect_drop_balance",
    "connect_lookup",
    "connect_me",
    "connect_get_price",
)


def _quidli_payload() -> dict[str, object]:
    payload = json.loads(_QUIDLI_CONNECT.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


class _QuidliAuthorityStore:
    def __init__(self, *, enabled: bool) -> None:
        self._enabled = enabled

    def read_extension_control_authority_for_registry(self, registry: object):
        from codex_plugin_scanner.guard.runtime.extension_control_authority import (
            AuthorityHealth,
            ExtensionControlAuthorityView,
        )
        from codex_plugin_scanner.guard.runtime.extension_control_contract import (
            CONTROL_SCHEMA_VERSION,
            ControlLayerKind,
            ControlState,
            ControlTarget,
            ControlTargetKind,
            ExtensionControl,
            ExtensionControlLayer,
        )

        digest = getattr(registry, "catalog_digest", "0" * 64)
        assert isinstance(digest, str)
        controls = (
            (
                ExtensionControl(
                    target=ControlTarget(ControlTargetKind.EXTENSION, _QUIDLI_CONNECT_ID),
                    state=ControlState.ENABLED,
                ),
            )
            if self._enabled
            else ()
        )
        layer = ExtensionControlLayer(
            schema_version=CONTROL_SCHEMA_VERSION,
            kind=ControlLayerKind.LOCAL_ADMIN,
            catalog_digest=digest,
            global_lockdown=False,
            controls=controls,
        )
        return ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=1,
            catalog_digest=digest,
            layers=(layer,),
        )


def _quidli_artifact(tool_name: str, *, server_name: str = "quidli-connect", url: str = _QUIDLI_CONNECT_URL):
    from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
    from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity

    identity = build_mcp_server_identity(config_path=".mcp.json", command=url, args=(), transport="http")
    return build_tool_call_artifact(
        harness="codex",
        server_name=server_name,
        tool_name=tool_name,
        source_scope="project",
        config_path=".mcp.json",
        transport="http",
        server_identity=identity,
    )


def test_quidli_connect_contribution_is_valid_remote_http_external_opt_in() -> None:
    payload = _quidli_payload()
    validate_mcp_contribution(payload, filename="mcp.quidli-connect.json")
    assert payload["trustClass"] == "external"
    assert payload["activation"] == "opt-in"
    launch = payload["launch"]
    assert isinstance(launch, dict)
    assert launch["kind"] == "remote-http"
    assert launch["url"] == _QUIDLI_CONNECT_URL
    tools = payload["tools"]
    assert isinstance(tools, list)
    assert all(isinstance(tool, dict) and tool["state"] != "allow" for tool in tools)


def test_quidli_connect_catalog_item_is_external_and_off_by_default() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_QUIDLI_CONNECT_ID)
    assert extension is not None
    item = extension.to_dict()
    assert item["enabled"] is False
    assert item["trust_class"] == "external"
    assert item["activation"] == "opt-in"
    assert item["surface"] == "mcp"
    assert trust_class_for(_QUIDLI_CONNECT_ID) == "external"
    assert _QUIDLI_CONNECT_ID in ids_for_class("external")


def test_quidli_connect_tool_defaults_review_writes_and_inherit_reads() -> None:
    payload = _quidli_payload()
    for tool in _QUIDLI_REVIEW_TOOLS:
        assert mcp_tool_state(payload, tool) == "review", tool
    for tool in _QUIDLI_INHERIT_TOOLS:
        assert mcp_tool_state(payload, tool) == "inherit", tool
    assert mcp_tool_state(payload, "connect_future_tool") == "inherit"


def test_quidli_connect_is_inert_until_local_admin_enable() -> None:
    from codex_plugin_scanner.guard.runtime.mcp_server_grants import (
        apply_contributed_mcp_decision,
        matching_mcp_contribution,
    )

    artifact = _quidli_artifact("connect_drop")
    matched = matching_mcp_contribution(artifact)
    assert matched is not None
    assert matched["id"] == "mcp.quidli-connect"
    assert apply_contributed_mcp_decision(_QuidliAuthorityStore(enabled=False), artifact, "allow") is None


@pytest.mark.parametrize("tool", _QUIDLI_REVIEW_TOOLS)
def test_quidli_connect_enabled_review_strengthens_allow(tool: str) -> None:
    from codex_plugin_scanner.guard.runtime.mcp_server_grants import apply_contributed_mcp_decision

    decision = apply_contributed_mcp_decision(_QuidliAuthorityStore(enabled=True), _quidli_artifact(tool), "allow")
    assert decision is not None
    assert decision[0] == "review"
    assert decision[1] == "catalog-mcp-extension"


@pytest.mark.parametrize("tool", ("connect_trust_check", "connect_trust_graph", "connect_drop_balance"))
def test_quidli_connect_enabled_reads_inherit(tool: str) -> None:
    from codex_plugin_scanner.guard.runtime.mcp_server_grants import apply_contributed_mcp_decision

    assert apply_contributed_mcp_decision(_QuidliAuthorityStore(enabled=True), _quidli_artifact(tool), "allow") is None


def test_quidli_connect_does_not_match_wrong_endpoint() -> None:
    from codex_plugin_scanner.guard.runtime.mcp_server_grants import matching_mcp_contribution

    artifact = _quidli_artifact("connect_drop", url="https://mcp.connect.quid.li.evil.example/")
    assert matching_mcp_contribution(artifact) is None


def test_quidli_connect_enabled_review_cannot_weaken_block() -> None:
    from codex_plugin_scanner.guard.runtime.mcp_server_grants import apply_contributed_mcp_decision

    decision = apply_contributed_mcp_decision(
        _QuidliAuthorityStore(enabled=True), _quidli_artifact("connect_drop"), "block"
    )
    assert decision is None or decision[0] == "block"
