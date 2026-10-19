"""Container batching preserves fixed bounds and independent member integrity."""

from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import containers, transport


@pytest.fixture
def plan_type(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("extension_delivery_assets").AssetPlan


def test_batched_metadata_uses_one_download_and_checks_each_selected_member(plan_type, monkeypatch, tmp_path):
    plan = plan_type(tmp_path / "assets", "1" * 40)
    one, two = b'{"one":1}', b'{"two":2}'
    first, second = plan.asset(one, "object"), plan.asset(two, "object")
    assert first["asset"] == second["asset"] and first["member"] != second["member"]
    assert len(plan.pending) == 1
    reads = []

    def download(url, maximum):
        reads.append((url, maximum))
        return (plan.directory / first["tag"] / first["asset"]).read_bytes()

    monkeypatch.setattr(transport, "download", download)
    fetch = transport.cached_fetcher(tmp_path / "cache")
    assert fetch(first, len(one)) == one and fetch(second, len(two)) == two
    assert len(reads) == 1 and reads[0][1] == containers.METADATA_BYTES
    with pytest.raises(ValueError, match="length"):
        fetch(first, len(one) + 1)
    assert len(reads) == 2

    cached = next((tmp_path / "cache").glob("*.zip"))
    cached.write_bytes(b"truncated untrusted cache")
    assert fetch(first, len(one)) == one
    assert len(reads) == 3
    assert fetch(second, len(two)) == two and len(reads) == 3


def test_containers_split_without_changing_member_or_byte_bounds(plan_type, tmp_path):
    plan = plan_type(tmp_path / "assets", "1" * 40)
    for number in range(containers.MAX_MEMBERS + 1):
        plan.asset(json.dumps({"entry": number}).encode(), "object")
    assert len(plan.pending) == 2
    counts = []
    for row in plan.pending:
        target = row["location"]
        data = (plan.directory / target["tag"] / target["asset"]).read_bytes()
        archive, infos = containers.inspect(data, target["asset"])
        counts.append(len(infos))
        archive.close()
        assert len(data) <= containers.METADATA_BYTES
    assert counts == [containers.MAX_MEMBERS, 1]


def test_new_container_cannot_publish_unreferenced_bytes(plan_type, tmp_path):
    from extension_delivery_inventory import InventoryStore, read_plan

    plan = plan_type(tmp_path / "assets", "1" * 40, publication_id="12.1")
    data = b"reviewed public metadata"
    target = plan.asset(data, "object")
    plan.asset(b"unbound bytes", "object")
    row = plan.pending[0]
    (tmp_path / "asset-plan.jsonl").write_text(json.dumps(row) + "\n")
    inventory = InventoryStore(tmp_path / "metadata")
    inventory.mark("object", hashlib.sha256(data).hexdigest(), len(data), target)
    with pytest.raises(ValueError, match="unbound"):
        read_plan(tmp_path, inventory.assets, "1" * 40, "12.1")


def test_selected_member_cannot_be_substituted_by_same_length_data(plan_type, tmp_path):
    plan = plan_type(tmp_path / "assets", "1" * 40)
    data = b"reviewed object"
    target = plan.asset(data, "object")
    plan.finish()
    raw = (plan.directory / target["tag"] / target["asset"]).read_bytes()
    wrong = "object-" + hashlib.sha256(b"untrusted bytes").hexdigest() + ".json"
    with pytest.raises(ValueError, match="missing"):
        containers.member(raw, target["asset"], wrong, len(data))
    with pytest.raises(ValueError, match="terminator"):
        containers.member(raw[:-1], target["asset"], target["member"], len(data))
