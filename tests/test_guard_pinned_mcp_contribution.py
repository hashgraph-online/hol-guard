"""Optional exact npm pins do not grant execution authority."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.runtime import mcp_server_grants as grants
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_catalog import _values_for_payload
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import validate_mcp_contribution

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "@modelcontextprotocol/server-filesystem"


def payload():
    value = json.loads((ROOT / "contributions/mcp-servers/mcp.filesystem.json").read_bytes())
    value["launch"]["packageVersion"] = "1.2.3"
    return value


def artifact(package=f"{PACKAGE}@1.2.3", command="npx", extra=(), transport="stdio"):
    identity = build_mcp_server_identity(config_path="", command=command, args=(*extra, package), transport=transport)
    return build_tool_call_artifact(
        harness="codex",
        server_name="filesystem",
        tool_name="write_file",
        source_scope="project",
        config_path=".mcp.json",
        transport=transport,
        server_identity=identity,
    )


@pytest.mark.parametrize("version", ["", "latest", "^1.2.3", "~1.2.3", "*", "1.2", "01.2.3", "1.2.3\n", None])
def test_pin_rejects_tags_ranges_and_noncanonical_versions(version):
    value = payload()
    value["launch"]["packageVersion"] = version
    with pytest.raises(ValueError):
        validate_mcp_contribution(value)


@pytest.mark.parametrize("command", ["uvx", "pipx"])
def test_npm_pin_rejects_other_ecosystem_launchers(command):
    value = payload()
    value["launch"]["command"] = command
    with pytest.raises(ValueError, match="npm launcher"):
        validate_mcp_contribution(value)


@pytest.mark.parametrize("package", ["fixture@1.2.3", "fixture --help", "https://example.com/pkg", "Pkg"])
def test_pin_requires_canonical_npm_package_name(package):
    value = payload()
    value["launch"]["package"] = package
    with pytest.raises(ValueError, match="canonical package"):
        validate_mcp_contribution(value)


@pytest.mark.parametrize("package", ["a" * 215, "@scope/" + "a" * 208])
def test_pin_rejects_npm_names_over_214_characters(package):
    value = payload()
    value["launch"]["package"] = package
    with pytest.raises(ValueError, match="canonical package"):
        validate_mcp_contribution(value)


@pytest.mark.parametrize("package", ["a" * 214, "@scope/" + "a" * 207])
def test_pin_accepts_npm_names_at_214_character_boundary(package):
    value = payload()
    value["launch"]["package"] = package
    validate_mcp_contribution(value)


def test_exact_pin_matches_and_projects_runnable_example(monkeypatch):
    value = payload()
    validate_mcp_contribution(value)
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (value,))
    assert grants.matching_mcp_contribution(artifact()) == value
    assert {permission.example_command for permission in _values_for_payload(value)["permissions"]} == {
        f"npx -y {PACKAGE}@1.2.3"
    }


@pytest.mark.parametrize(
    "package", [PACKAGE, f"{PACKAGE}@latest", f"{PACKAGE}@1.2.2", f"{PACKAGE}@^1.2.3", "other@1.2.3"]
)
def test_unpinned_or_mismatched_release_does_not_receive_catalog_defaults(monkeypatch, package):
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (payload(),))
    assert grants.matching_mcp_contribution(artifact(package)) is None


@pytest.mark.parametrize(
    "command,extra,transport",
    [
        ("bunx", (), "stdio"),
        ("npx", ("--registry", "https://unreviewed.example"), "stdio"),
        ("npx", (), "http"),
    ],
)
def test_pin_does_not_transfer_to_other_launcher_registry_or_transport(monkeypatch, command, extra, transport):
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (payload(),))
    assert grants.matching_mcp_contribution(artifact(command=command, extra=extra, transport=transport)) is None


@pytest.mark.parametrize(
    "missing", ["package_version", "package_source", "command", "transport", "env_keys", "mcp_tool_identity"]
)
def test_missing_identity_evidence_does_not_match(monkeypatch, missing):
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (payload(),))
    tool = artifact()
    metadata = dict(tool.metadata)
    if missing == "mcp_tool_identity":
        metadata.pop(missing)
    else:
        identity = dict(metadata["mcp_server_identity"])
        identity.pop(missing)
        metadata["mcp_server_identity"] = identity
    assert grants.matching_mcp_contribution(replace(tool, metadata=metadata)) is None


@pytest.mark.parametrize(
    "key",
    [
        "NPM_CONFIG_REGISTRY",
        "npm_config_registry",
        "NPM_CONFIG_USERCONFIG",
        "NPM_CONFIG_GLOBALCONFIG",
        "NPM_CONFIG_PREFIX",
        "npm_config_@example:registry",
        "YARN_REGISTRY",
        "YARN_NPM_REGISTRY_SERVER",
        "YARN_RC_FILENAME",
        "BUN_CONFIG_REGISTRY",
        "BUN_INSTALL_REGISTRY",
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_CONFIG_HOME",
        "XDG_CONFIG_DIRS",
        "BUN_INSTALL",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PATH",
        "NPM_CONFIG_CACHE",
        "YARN_CACHE_FOLDER",
        "BUN_INSTALL_CACHE_DIR",
    ],
)
def test_configured_registry_environment_cannot_select_reviewed_pin(monkeypatch, key):
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (payload(),))
    identity = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=(f"{PACKAGE}@1.2.3",),
        transport="stdio",
        env={key: "https://unreviewed.example"},
    )
    tool = build_tool_call_artifact(
        harness="codex",
        server_name="filesystem",
        tool_name="write_file",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
    )
    assert grants.matching_mcp_contribution(tool) is None


@pytest.mark.parametrize("transport", ["http", "sse", "", None])
def test_pinned_identity_cannot_override_conflicting_artifact_transport(monkeypatch, transport):
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (payload(),))
    assert grants.matching_mcp_contribution(replace(artifact(), transport=transport)) is None


def test_non_source_server_environment_remains_compatible(monkeypatch):
    value = payload()
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (value,))
    identity = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=(f"{PACKAGE}@1.2.3",),
        transport="stdio",
        env={"REDIS_URL": "redis://localhost:6379"},
    )
    tool = build_tool_call_artifact(
        harness="codex",
        server_name="filesystem",
        tool_name="write_file",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
    )
    assert grants.matching_mcp_contribution(tool) == value
    assert grants.matching_mcp_contribution(replace(tool, transport=" STDIO ")) == value


@pytest.mark.parametrize("package", [PACKAGE.upper(), f" {PACKAGE}", f"{PACKAGE} "])
def test_pinned_identity_requires_canonical_package_spelling(monkeypatch, package):
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (payload(),))
    tool = artifact()
    metadata = dict(tool.metadata)
    metadata["mcp_server_identity"] = {**metadata["mcp_server_identity"], "package_name": package}
    assert grants.matching_mcp_contribution(replace(tool, metadata=metadata)) is None


def test_unversioned_existing_contributions_remain_compatible(monkeypatch):
    value = payload()
    value["launch"].pop("packageVersion")
    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (value,))
    assert grants.matching_mcp_contribution(artifact(PACKAGE)) == value


def test_pinned_defaults_stay_inert_until_local_enable(monkeypatch):
    from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState

    from .test_guard_mcp_server_grants import _AuthorityStore, _layer

    monkeypatch.setattr(grants, "load_mcp_contribution_payloads", lambda: (payload(),))
    tool = artifact()
    assert grants.apply_contributed_mcp_decision(_AuthorityStore(), tool, "allow") is None
    cloud = _AuthorityStore((_layer(ControlLayerKind.SIGNED_CLOUD, "command.mcp-filesystem", ControlState.ENABLED),))
    assert grants.apply_contributed_mcp_decision(cloud, tool, "allow") is None
    local = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-filesystem", ControlState.ENABLED),))
    assert grants.apply_contributed_mcp_decision(local, tool, "allow")[0] == "block"
