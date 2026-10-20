"""Authenticated offline compatibility and bounded core-profile packaging."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import installed_bundle as installed
from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import descriptor, validate
from codex_plugin_scanner.guard.catalog_delivery.located_store import LocatedStore
from codex_plugin_scanner.guard.extension_builder.repository_edits import edit_pyproject
from codex_plugin_scanner.guard.runtime import extension_contribution as commands
from codex_plugin_scanner.guard.runtime import mcp_server_contribution as mcp
from tests.extension_builder_support import metadata
from tests.test_command_projection_build_hook import hook as hook
from tests.test_installed_command_pack_bundle import ENGINE, SOURCE, encoded, root
from tests.test_installed_command_pack_bundle import package as package


@pytest.fixture
def compatibility(package, monkeypatch, tmp_path, request):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    assets = importlib.import_module("extension_delivery_assets")
    directory, native = package
    plan = assets.AssetPlan(directory / "assets", SOURCE)
    store = LocatedStore(tmp_path / "metadata", publisher=plan)
    payloads = {
        "commands": {"schemaVersion": "guard.extension-contribution.v2", "id": "command.example"},
        "mcp": {"schemaVersion": "guard.mcp-server-contribution.v1", "id": "mcp.example"},
    }
    if getattr(request, "param", None) == "large":
        payloads["commands"]["description"] = "x" * 5000
    value = root()
    value["policy"]["root"]["extensions"] = 2
    value["compatibility"] = {
        family: {"count": 1, "index": store.index({payload["id"]: store.put_json(payload)})}
        for family, payload in payloads.items()
    }
    plan.finish()

    def publish(value):
        data = encoded(value)
        (directory / installed.MANIFEST).write_bytes(data)
        for name in ("runtime-manifest.json", "source-compiler-manifest.json"):
            path = native / name
            manifest = json.loads(path.read_bytes())
            manifest["command_pack_bundle"] = descriptor(data, source_sha=SOURCE, engine=ENGINE)
            path.write_bytes(encoded(manifest))

    publish(value)
    return value, payloads, publish


def test_offline_apis_read_authenticated_metadata_without_policy_archives(compatibility, monkeypatch):
    _, payloads, _ = compatibility
    monkeypatch.setattr(commands, "_load_packaged_payloads", lambda: pytest.fail("no loose records"))
    monkeypatch.setattr(mcp, "_load_packaged_payloads", lambda: pytest.fail("no loose records"))
    assert commands.load_contribution_payloads() == (payloads["commands"],)
    assert mcp.load_mcp_contribution_payloads() == (payloads["mcp"],)
    assert commands.contribution_ids() == frozenset({"command.example"})


@pytest.mark.parametrize("family", ["commands", "mcp"])
def test_explicit_checkout_lookup_never_reads_installed_bundle(compatibility, monkeypatch, tmp_path, family):
    module = commands if family == "commands" else mcp
    monkeypatch.setattr(installed, "load_installed_bundle", lambda: pytest.fail("explicit source root"))
    monkeypatch.setattr(module, "_load_from_directory", lambda path: (path,))
    loader = commands.load_contribution_payloads if family == "commands" else mcp.load_mcp_contribution_payloads
    assert loader(tmp_path) == (tmp_path,)


def test_advertised_missing_or_corrupt_bundle_does_not_fallback(compatibility, package):
    directory, _ = package
    (directory / installed.MANIFEST).unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        commands.load_contribution_payloads()


def test_compatibility_member_corruption_fails_closed(compatibility, package):
    directory, _ = package
    asset = next((directory / "assets").rglob("*.zip"))
    asset.write_bytes(b"invalid")
    with pytest.raises(ValueError):
        mcp.load_mcp_contribution_payloads()


def test_offline_metadata_total_budget_is_enforced(compatibility, monkeypatch):
    monkeypatch.setattr(installed, "MAX_BYTES", 1)
    with pytest.raises(ValueError, match="byte budget"):
        commands.load_contribution_payloads()


@pytest.mark.parametrize("compatibility", ["large"], indirect=True)
def test_expanded_metadata_budget_is_checked_before_loading_payload(compatibility, monkeypatch):
    monkeypatch.setattr(installed, "MAX_BYTES", 4096)
    with pytest.raises(ValueError, match="expanded byte budget"):
        commands.load_contribution_payloads()


def test_frozen_bundle_uses_extracted_package_root(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert installed._package() == tmp_path / "codex_plugin_scanner"


def test_frozen_input_inventory_rejects_symlink_fixture_directories(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    build = importlib.import_module("command_pack_bundle_build")
    fixtures = tmp_path / "tests/fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "linked").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        build.inputs(tmp_path)


def test_index_count_must_match_advertised_inventory(compatibility):
    value, _, publish = compatibility
    value["compatibility"]["commands"]["count"] = 2
    value["compatibility"]["mcp"] = {"count": 0, "index": None}
    publish(value)
    with pytest.raises(ValueError, match="count"):
        commands.load_contribution_payloads()


@pytest.mark.parametrize("kind", ["cli", "mcp"])
def test_core_profile_builder_does_not_change_native_build_input(kind):
    project = (Path(__file__).parents[1] / "pyproject.toml").read_text()
    assert edit_pyproject(project, metadata(kind), core_profile=True) == project


def test_root_compatibility_contract_rejects_source_substitution(compatibility):
    value, _, _ = compatibility
    row = value["compatibility"]["commands"]
    row["index"]["location"]["tag"] = "extension-data-" + "c" * 40 + "-0.0-000000"
    with pytest.raises(ValueError):
        validate(encoded(value), source_sha=SOURCE, engine=ENGINE)


def test_true_legacy_absence_and_old_root_remain_compatible(package, tmp_path, monkeypatch):
    assert installed.compatibility_payloads("commands") is None
    monkeypatch.setattr(installed, "_package", lambda: tmp_path / "legacy")
    assert installed.compatibility_payloads("mcp") is None


@pytest.mark.parametrize("target", ["wheel", "sdist"])
@pytest.mark.parametrize("archive", [False, True])
def test_core_profile_omits_loose_metadata_and_descriptor_fingerprint(hook, monkeypatch, target, archive):
    root = Path(hook.root)
    if archive:
        (root / "PKG-INFO").write_text("frozen")
    hook.target_name = target
    monkeypatch.setattr(importlib.import_module("subprocess"), "run", lambda *args, **kwargs: None)
    fingerprints = []
    hook.archive_test_support.write_projection_manifest = lambda root, **kwargs: fingerprints.append(kwargs)
    prefix = "codex_plugin_scanner/guard/contracts/data"
    data = {
        "force_include": {
            "contributions/mcp-servers": "codex_plugin_scanner/guard/contracts/data/mcp_servers/contributions",
            "contributions/command-sources/command.old.json": f"{prefix}/extensions/command-sources/command.old.json",
            "contributions/extensions/command.old.json": f"{prefix}/extensions/contributions/command.old.json",
        }
    }
    configured = {str(root / source): destination for source, destination in data["force_include"].items()}
    hook.build_config = SimpleNamespace(force_include=configured)
    hook.initialize("standard", data)
    assert not any("build-descriptors" in path for path in data["force_include"])
    assert not any(path.startswith("contributions/extensions") for path in data["force_include"])
    if target == "wheel":
        assert not any(path.startswith("contributions/") for path in data["force_include"])
        assert configured == {}
    else:
        assert fingerprints[0]["descriptors"] is None
