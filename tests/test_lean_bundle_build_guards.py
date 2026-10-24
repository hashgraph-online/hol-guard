"""Installed data boundaries remain explicit even before native assembly."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def helpers(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import installed_bundle_assets

    return installed_bundle_assets


def test_normal_build_rejects_optional_resident_ir(tmp_path, helpers):
    directory = tmp_path / "contracts/extensions"
    directory.mkdir(parents=True)
    (directory / "core-defaults.v1.json").write_text(
        json.dumps({"schema": "guard.core-defaults.v1", "entries": [{"extension_id": "command.core"}]})
    )
    program = directory / "native-command-program.v1.json"
    program.write_text(
        json.dumps({"extensions": [{"extension_id": "command.core"}, {"extension_id": "command.optional"}]})
    )
    with pytest.raises(ValueError, match="optional policy"):
        helpers.validate_resident_core(tmp_path)
    program.write_text(json.dumps({"extensions": [{"extension_id": "command.core"}]}))
    helpers.validate_resident_core(tmp_path)


def test_complete_offline_asset_staging_is_explicit(tmp_path, helpers):
    from extension_delivery_assets import AssetPlan

    source = tmp_path / "public"
    plan = AssetPlan(source, "a" * 40, standalone_policy=True)
    core = plan.asset(b"core-policy", "pack")
    optional = plan.asset(b"optional-policy", "pack")
    plan.asset(b"public-metadata", "object")
    rows = plan.pending
    defaults = {(core["tag"], core["asset"])}
    normal, offline = tmp_path / "normal", tmp_path / "offline"
    assert helpers.stage_assets(source, normal, rows, defaults, source_sha="a" * 40, offline=False)[0] == 2
    assert helpers.stage_assets(source, offline, rows, defaults, source_sha="a" * 40, offline=True)[0] == 3
    assert "member" not in core and "member" not in optional
    batch = optional["tag"].rsplit("-", 1)[1]
    assert not (normal / batch / optional["asset"]).exists()
    assert (offline / batch / optional["asset"]).read_bytes() == b"optional-policy"


def test_immutable_pack_names_change_with_policy(tmp_path, helpers):
    from extension_delivery_assets import AssetPlan

    first = AssetPlan(tmp_path / "first", "a" * 40, standalone_policy=True)
    second = AssetPlan(tmp_path / "second", "a" * 40, standalone_policy=True)
    before = first.asset(b"policy-before", "pack")
    after = second.asset(b"policy-after", "pack")
    first.finish()
    second.finish()
    assert before["asset"] != after["asset"]
    assert before["asset"].startswith("pack-") and after["asset"].endswith(".zip")


def test_publication_plan_records_are_bounded_and_counted(tmp_path, helpers):
    import publish_installed_bundle_assets as publisher

    plan = tmp_path / "asset-plan.jsonl"
    plan.write_bytes(b"{}\n")
    assert list(publisher.plan_rows(tmp_path, 1)) == [{}]
    with pytest.raises(ValueError, match="count differs"):
        list(publisher.plan_rows(tmp_path, 0))
    with pytest.raises(ValueError, match="missing or oversized"):
        list(publisher.plan_rows(tmp_path, 2))
    plan.write_bytes(b"x" * 2048 + b"\n")
    with pytest.raises(ValueError, match="missing or oversized"):
        list(publisher.plan_rows(tmp_path, 1))
