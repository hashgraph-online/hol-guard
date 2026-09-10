"""The public artifact describes native source, never changes its authority."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_trust import trust_class_for
from tests.extension_builder_support import REPOSITORY

spec = importlib.util.spec_from_file_location(
    "guard_directory_export", REPOSITORY / "scripts/export_extension_directory.py"
)
assert spec and spec.loader
exporter = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = exporter
spec.loader.exec_module(exporter)


def test_export_is_deterministic_and_current() -> None:
    first = exporter.render_directory()
    assert first == exporter.render_directory()
    assert first == (REPOSITORY / "docs/guard/extensions/catalog.v1.json").read_text()
    payload = json.loads(first)
    assert payload["schemaVersion"] == "guard.extension-directory.v1"
    ids = [row["id"] for row in payload["entries"]]
    assert ids == sorted(set(ids))


def test_every_native_extension_appears_once_with_unchanged_authority() -> None:
    native = {row.extension_id: row for row in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions}
    entries = exporter.export_directory()["entries"]
    assert {row["runtimeExtensionId"] for row in entries} == set(native)
    for row in entries:
        extension = native[row["runtimeExtensionId"]]
        assert row["trustClass"] == trust_class_for(extension.extension_id)
        assert row["ruleCount"] == len(extension.rules)
        assert row["permissionCount"] == len(extension.permissions)
        assert len(row["operations"]) == len(extension.rules)
        assert (row["claimPolicy"] == "provenance") == (row["trustClass"] == "external")
        if row["claimPolicy"] == "provenance":
            assert row["protectionModel"] == "external-opt-in"
            assert row["sourcePath"].startswith("contributions/")
            assert row["contributionDigest"].startswith("sha256:")
        assert "enabled" not in row and "safe" not in row and "rating" not in row


def test_mcp_entry_preserves_contribution_identity_and_inheritance() -> None:
    entries = exporter.export_directory()["entries"]
    row = next(row for row in entries if row["id"] == "mcp.filesystem")
    assert row["runtimeExtensionId"] == "command.mcp-filesystem"
    assert row["kind"] == "mcp"
    assert row["toolStates"][-1] == {"name": "other", "state": "inherit"}
    assert "command.mcp-filesystem" not in {entry["id"] for entry in entries}


def copy_sources(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for directory in ("extensions", "mcp-servers"):
        shutil.copytree(REPOSITORY / "contributions" / directory, root / "contributions" / directory)
    (root / "contributions/extension-listings").mkdir()
    return root


def test_orphan_or_authoritative_listing_is_rejected(tmp_path: Path) -> None:
    root = copy_sources(tmp_path)
    path = root / "contributions/extension-listings/command.orphan.json"
    path.write_text("{}")
    with pytest.raises(ValueError, match="existing external"):
        exporter.export_directory(root)
    path.unlink()
    path = root / "contributions/extension-listings/command.blitcp.json"
    path.write_text(json.dumps({"extensionId": "command.blitcp", "activation": "default-on"}))
    with pytest.raises(BuilderError):
        exporter.export_directory(root)


def test_source_identity_mismatch_is_rejected(tmp_path: Path) -> None:
    root = copy_sources(tmp_path)
    source = root / "contributions/extensions/command.blitcp.json"
    source.rename(source.with_name("command.wrong-name.json"))
    with pytest.raises(ValueError):
        exporter.export_directory(root)


def test_public_directory_matches_cross_repository_contract() -> None:
    from jsonschema import Draft202012Validator

    schema = json.loads((REPOSITORY / "contracts/extensions/directory.v1.schema.json").read_text())
    Draft202012Validator(schema).validate(exporter.export_directory())
    catalog = exporter.export_directory()
    entry = dict(catalog["entries"][0])
    entry.pop("operations", None)
    Draft202012Validator(schema).validate({"schemaVersion": catalog["schemaVersion"], "entries": [entry]})
