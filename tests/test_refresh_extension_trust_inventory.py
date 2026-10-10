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
    monkeypatch.setattr(module, "TRUST_MAP", bindings.parent / "build-trust-class-map.v1.json")
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


@pytest.mark.parametrize("kind", ["command", "mcp"])
def test_check_rejects_missing_ownership_without_staging_it(refresh, kind, capsys):
    write(
        refresh.TRUST_BINDINGS / "command.core.v1.json",
        {"schemaVersion": "guard.extension-trust-binding.v1", "extension": "command.core", "trustClass": "first-party"},
    )
    if kind == "mcp":
        write(refresh.ROOT / "contributions/mcp-servers/mcp.run.json", {"id": "mcp.run"})
        identity = "command.mcp-run"
    else:
        write(
            refresh.ROOT / "contributions/command-sources/command.new.json",
            {"extension": {"extension_id": "command.new", "trustClass": "first-party"}},
        )
        identity = "command.new"
    before = {p: p.read_bytes() for p in refresh.ROOT.rglob("*") if p.is_file()}

    with pytest.raises(SystemExit, match=identity):
        refresh.main(["--check-trust"])

    assert {p: p.read_bytes() for p in refresh.ROOT.rglob("*") if p.is_file()} == before
    assert refresh.main(["--trust-only"]) == 0
    assert refresh.main(["--check-trust"]) == 0
    assert refresh._trust_binding_index() == {"command.core": "first-party", identity: "external"}
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["authored_trust_complete"] is True
    assert not (refresh.TRUST_BINDINGS.parent / "trust-class-map.v1.json").exists()


def test_check_does_not_require_bindings_for_orphan_generated_descriptors(refresh):
    write(
        refresh.TRUST_BINDINGS / "command.core.v1.json",
        {"schemaVersion": "guard.extension-trust-binding.v1", "extension": "command.core", "trustClass": "first-party"},
    )
    write(refresh.ROOT / "contributions/extensions/command.orphan.json", {"id": "command.orphan"})
    assert refresh.main(["--check-trust"]) == 0
    assert not refresh.TRUST_MAP.exists()


def test_check_rejects_invalid_authored_class_without_repair(refresh):
    path = refresh.TRUST_BINDINGS / "command.core.v1.json"
    write(
        path,
        {"schemaVersion": "guard.extension-trust-binding.v1", "extension": "command.core", "trustClass": "unknown"},
    )
    before = path.read_bytes()
    with pytest.raises(ValueError, match="unknown trust class"):
        refresh.main(["--check-trust"])
    assert path.read_bytes() == before
    assert not refresh.TRUST_MAP.exists()


def test_required_quality_checks_ownership_before_package_preparation():
    action = (Path(__file__).parents[1] / ".github/actions/ci-job-quality/action.yml").read_text()
    assert action.index("scripts/refresh_extension_artifacts.py --check-trust") < action.index("uv sync")
