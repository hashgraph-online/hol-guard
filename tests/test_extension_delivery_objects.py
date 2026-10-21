"""Content-addressed delivery keeps page, object and archive budgets fixed."""

from __future__ import annotations

import hashlib
import importlib
import io
import stat
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def delivery(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("extension_delivery_objects"), importlib.import_module("extension_pack_archives")


def test_metadata_concatenation_and_index_growth_keep_object_budgets(delivery, tmp_path):
    objects, _ = delivery
    store = objects.ObjectStore(tmp_path / "objects")
    value = {"description": "a" * 100000}
    reference = store.put_json(value)
    assert reference["kind"] == "concat"
    assert store.json(reference) == value
    assert store.put_json(value) == reference
    values = {f"command.test-{index:05}": reference for index in range(1660)}
    root = store.index(values)
    assert dict(objects.entries(store, root, len(values))) == values
    with pytest.raises(ValueError, match="count"):
        list(objects.entries(store, root, len(values) + 1))
    assert max(path.stat().st_size for path in store.directory.iterdir()) <= 65536
    broken = {**reference, "sha256": "0" * 64}
    with pytest.raises(FileNotFoundError):
        store.json(broken)


def test_corrupt_object_and_symlink_cache_cannot_be_reused(delivery, tmp_path):
    objects, _ = delivery
    store = objects.ObjectStore(tmp_path / "objects")
    reference = store.put_json({"test": True})
    path = store.directory / (reference["sha256"] + ".json")
    path.write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="integrity"):
        store.put_json({"test": True})
    with pytest.raises(ValueError, match="integrity"):
        store.json(reference)
    link = tmp_path / "linked"
    link.symlink_to(store.directory, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        objects.ObjectStore(link)


def test_archive_is_deterministic_and_excludes_unrelated_objects(delivery, tmp_path):
    objects, archives = delivery
    store = objects.ObjectStore(tmp_path / "objects")
    first = store.put_json({"policy": "one"})
    second = store.put_json({"policy": "two"})
    part = next(archives.parts(store.directory, {first["sha256"]}))
    store.put_json({"unrelated": "disabled"})
    assert next(archives.parts(store.directory, {first["sha256"]})) == part
    assert next(archives.parts(store.directory, {second["sha256"]})) != part
    count = archives.ingest(part, hashlib.sha256(part).hexdigest(), len(part), tmp_path / "received")
    assert count == 1
    assert (tmp_path / "received" / (first["sha256"] + ".json")).read_bytes() == store.blob(first)
    assert len(list((tmp_path / "received").iterdir())) == 1


@pytest.mark.parametrize(
    "fault", ["digest", "length", "compressed", "path", "mode", "duplicate", "object-digest", "footer"]
)
def test_malicious_transfer_is_rejected_before_activation(delivery, tmp_path, fault):
    _, archives = delivery
    content = b"{}"
    identity = hashlib.sha256(content).hexdigest()
    name = identity + ".json"
    if fault == "path":
        name = "../" + name
    if fault == "object-digest":
        name = "0" * 64 + ".json"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        row = zipfile.ZipInfo(name)
        row.create_system = 3
        row.external_attr = ((stat.S_IFLNK if fault == "mode" else stat.S_IFREG) | 0o644) << 16
        row.compress_type = zipfile.ZIP_DEFLATED if fault == "compressed" else zipfile.ZIP_STORED
        archive.writestr(row, content)
        if fault == "duplicate":
            with pytest.warns(UserWarning, match="Duplicate"):
                archive.writestr(row, content)
    data = output.getvalue()
    if fault == "footer":
        data = data[:-1]
    digest = "0" * 64 if fault == "digest" else hashlib.sha256(data).hexdigest()
    length = len(data) + (1 if fault == "length" else 0)
    with pytest.raises(ValueError):
        archives.ingest(data, digest, length, tmp_path / "received")
    assert not list(tmp_path.rglob("*.json"))


def test_archive_splits_at_fixed_member_budget(delivery, tmp_path):
    objects, archives = delivery
    store = objects.ObjectStore(tmp_path / "objects")
    identities = {store.put_json({"index": index})["sha256"] for index in range(2049)}
    parts = list(archives.parts(store.directory, identities))
    assert len(parts) == 2
    sizes = []
    for data in parts:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            sizes.append(len(archive.infolist()))
    assert sizes == [2048, 1]
    for data in parts:
        archives.ingest(data, hashlib.sha256(data).hexdigest(), len(data), tmp_path / "received")
    assert len(list((tmp_path / "received").iterdir())) == 2049


def test_located_metadata_fetches_only_verified_pages_and_reuses_assets(delivery, tmp_path):
    from extension_delivery_assets import AssetPlan
    from extension_delivery_located_store import LocatedStore

    objects, _ = delivery
    plan = AssetPlan(tmp_path / "assets", "1" * 40)
    store = LocatedStore(tmp_path / "objects", publisher=plan)
    expected = {"description": "x" * 100000}
    first = store.put_json(expected)
    second = store.put_json({"separate": "unrelated"})
    root = store.index({"command.one": first, "command.two": second})
    plan.finish()
    reads = []

    def fetch(target, length):
        reads.append(target)
        data = (plan.directory / target["tag"] / target["asset"]).read_bytes()
        if "member" in target:
            from codex_plugin_scanner.guard.catalog_delivery.containers import member

            data = member(data, target["asset"], target["member"], length)
        assert len(data) == length
        return data

    client = LocatedStore(tmp_path / "client", fetch=fetch)
    assert client.json(first) == expected
    assert all(target != second["location"] for target in reads)
    previous = len(reads)
    assert client.json(first) == expected and len(reads) == previous
    assert dict(objects.entries(client, root, 2)) == {"command.one": first, "command.two": second}
    next_plan = AssetPlan(tmp_path / "next-assets", "2" * 40, existing=plan.locations)
    next_store = LocatedStore(tmp_path / "next-objects", publisher=next_plan)
    assert next_store.put_json(expected) == first
    assert next_plan.pending == []
    broken = {**second, "sha256": "../escape"}
    with pytest.raises(ValueError, match="bounds"):
        client.blob(broken)
    broken = {**second, "location": {"tag": "untrusted", "asset": "untrusted"}}
    with pytest.raises(ValueError, match="location"):
        client.blob(broken)


def test_corrupt_fetched_metadata_is_not_cached(delivery, tmp_path):
    from extension_delivery_assets import AssetPlan
    from extension_delivery_located_store import LocatedStore

    plan = AssetPlan(tmp_path / "assets", "1" * 40)
    store = LocatedStore(tmp_path / "objects", publisher=plan)
    reference = store.put_json({"test": True})
    client = LocatedStore(tmp_path / "client", fetch=lambda *args: b"corrupt")
    with pytest.raises(ValueError, match="integrity"):
        client.json(reference)
    assert not list(client.directory.iterdir())


def test_single_pack_public_entries_match_existing_directory(delivery, tmp_path, monkeypatch):
    import export_extension_directory
    from extension_pack_directory import public_entry
    from native_directory_inventory import catalog_rows, compiled_inventory

    from tests.support.extension_directory import bounded_extensions, copy_projected_contribution_sources

    root = Path(__file__).resolve().parents[1]
    bounded = tmp_path / "bounded"
    copy_projected_contribution_sources(root, bounded)
    listings = bounded / "contributions/extension-listings"
    listings.mkdir()
    for extension in bounded_extensions():
        identity = (
            "mcp." + extension.extension_id.removeprefix("command.mcp-")
            if extension.surface == "mcp"
            else extension.extension_id
        )
        source = root / "contributions/extension-listings" / f"{identity}.json"
        if source.exists():
            (listings / source.name).write_bytes(source.read_bytes())
    monkeypatch.setattr(export_extension_directory, "native_extensions", bounded_extensions)
    current = export_extension_directory.export_directory_v2(bounded)
    expected = {entry["runtimeExtensionId"]: entry for entry in current["entries"]}
    with compiled_inventory() as (_, reader, release):
        catalog = [row for _, _, row in catalog_rows(reader, release) if row["extension_id"] in expected]
    assert {row["extension_id"] for row in catalog} == set(expected)
    for row in catalog:
        assert public_entry(root, [row]) == expected[row["extension_id"]]


def test_pack_directory_import_does_not_load_aggregate_catalog(delivery, tmp_path):
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[1]
    program = (
        "import sys;sys.path.insert(0,sys.argv[1]);import extension_pack_directory;"
        "assert 'codex_plugin_scanner.guard.runtime.command_extensions' not in sys.modules"
    )
    subprocess.run([sys.executable, "-c", program, str(root / "scripts")], cwd=tmp_path, check=True)


def test_policy_lookup_verifies_native_path_without_downloading_pack_payloads(delivery, tmp_path):
    from build_extension_delivery import policy_transport
    from extension_delivery_assets import AssetPlan
    from extension_delivery_located_store import LocatedStore
    from extension_delivery_policy_lookup import lookup

    objects, _ = delivery
    native = objects.ObjectStore(tmp_path / "native")
    manifest = native.put_json({"schema": "test-policy-manifest"})
    native_index = native.index({f"command.test-{index:03}": manifest for index in range(166)})
    root = {"schema": "guard.command-pack-release.v1", "engine": "1" * 64, "index": native_index, "extensions": 166}
    plan = AssetPlan(tmp_path / "assets", "1" * 40)
    store = LocatedStore(tmp_path / "metadata", publisher=plan)
    data = b"test archive; deliberately never fetched by availability lookup"
    archive = {"sha256": hashlib.sha256(data).hexdigest(), "length": len(data), "location": plan.asset(data, "pack")}
    records = {}
    for index in range(166):
        identity = f"command.test-{index:03}"
        records[identity] = store.put_json(
            {
                "schema": "guard.policy-delivery.v2",
                "extension_id": identity,
                "manifest": manifest,
                "catalog_metadata": store.put_json({"extension_id": identity}),
                "archives": [archive],
                "dependencies": [],
                "related_interfaces": [],
                "required": False,
                "activation": "opt-in",
                "trust_class": "external",
            }
        )
    transport = policy_transport(native, native_index, records, store)
    plan.finish()
    reads = []

    def fetch(target, length):
        reads.append(target)
        assert target["asset"].startswith("objects-")
        from codex_plugin_scanner.guard.catalog_delivery.containers import member

        return member(
            (plan.directory / target["tag"] / target["asset"]).read_bytes(), target["asset"], target["member"], length
        )

    client = LocatedStore(tmp_path / "client", fetch=fetch)
    result = lookup(client, root, transport, "command.test-001")
    assert result["manifest"] == manifest
    assert len(reads) <= 7
    assert lookup(client, root, transport, "command.missing") is None
    with pytest.raises(ValueError, match="count"):
        lookup(client, {**root, "extensions": 167}, transport, "command.test-001")
    # The transport itself can be hash-valid while pointing at another native
    # manifest. The independent native index binding must still reject it.
    record = store.json(records["command.test-001"])
    record["manifest"] = native.put_json({"different": "policy"})
    records["command.test-001"] = store.put_json(record)
    bad_transport = policy_transport(native, native_index, records, store)
    plan.finish()
    with pytest.raises(ValueError, match="differs from native index"):
        lookup(client, root, bad_transport, "command.test-001")
