"""Generated descriptors cannot create reviewed trust inventory entries."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


@pytest.fixture
def refresh(tmp_path, monkeypatch):
    path = Path(__file__).parents[1] / "scripts/refresh_extension_artifacts.py"
    spec = importlib.util.spec_from_file_location("refresh_trust_inventory", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for directory in ("command-sources", "mcp-servers", "extensions"):
        (tmp_path / "contributions" / directory).mkdir(parents=True)
    bindings = tmp_path / "contracts/extensions/trust"
    bindings.mkdir(parents=True)
    detector = module._detector()
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(detector, "ROOT", tmp_path)
    monkeypatch.setattr(module, "TRUST_BINDINGS", bindings)
    monkeypatch.setattr(module, "TRUST_MAP", bindings.parent / "trust-class-map.v1.json")
    return module


def write(path, payload):
    path.write_text(json.dumps(payload))


def test_orphan_descriptor_cannot_create_a_trust_binding(refresh):
    write(
        refresh.ROOT / "contributions/extensions/command.orphan.json",
        {"schemaVersion": "guard.extension-contribution.v1", "id": "command.orphan"},
    )
    write(
        refresh.ROOT / "contributions/command-sources/command.active.json",
        {"extension": {"extension_id": "command.active", "trustClass": "first-party"}},
    )
    write(refresh.ROOT / "contributions/mcp-servers/mcp.active.json", {"id": "mcp.active"})
    write(
        refresh.TRUST_BINDINGS / "command.core.v1.json",
        {"schemaVersion": "guard.extension-trust-binding.v1", "extension": "command.core", "trustClass": "first-party"},
    )

    assert refresh.sync_trust_map()

    assert not (refresh.TRUST_BINDINGS / "command.orphan.v1.json").exists()
    assert refresh._trust_binding_index() == {
        "command.core": "first-party",
        "command.active": "external",
        "command.mcp-active": "external",
    }
    assert "command.orphan" not in json.loads(refresh.TRUST_MAP.read_text())["classes"]["external"]


def test_stale_descriptor_does_not_make_regeneration_pending(refresh, monkeypatch):
    write(refresh.ROOT / "contributions/extensions/command.retired.json", {"id": "command.retired"})
    write(
        refresh.ROOT / "contributions/command-sources/command.active.json",
        {"extension": {"extension_id": "command.active"}},
    )
    monkeypatch.setattr(refresh, "catalog_ids", lambda: {"command.active"})
    assert refresh.pending_contribution_ids() == []
