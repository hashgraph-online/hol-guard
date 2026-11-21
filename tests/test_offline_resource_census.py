from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import struct
import zipfile
import zlib
from dataclasses import replace

import pytest

from tests import offline_resource_census as resource


def _archive(entries, method=zipfile.ZIP_STORED):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            info.compress_type = method if not name.endswith("/") else zipfile.ZIP_STORED
            archive.writestr(info, data)
    return output.getvalue()


def _publication(tmp_path, assets):
    root = tmp_path / "publication"
    root.mkdir()
    rows = []
    for name, data in assets:
        target = root / "release" / name
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(data)
        rows.append(
            {
                "location": {"tag": "release", "asset": name},
                "length": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    _plan(root, rows)
    return root


def _plan(root, rows):
    (root / "asset-plan.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    (root / "installed-bundle-assets.v1.json").write_text(
        json.dumps(
            {
                "schema": "guard.installed-bundle-assets.v1",
                "source_sha": "a" * 40,
                "root_sha256": "b" * 64,
                "asset_count": len(rows),
            }
        )
    )


def _census(root, **kwargs):
    return resource.census(root, page_size=4096, metadata_reserve_bytes=1000, transient_reserve_bytes=5000, **kwargs)


def test_verified_assets_and_actual_zip_expansions_are_counted_without_writes(tmp_path):
    regular, directory = stat.S_IFREG | 0o644, stat.S_IFDIR | 0o755
    stored = _archive([("dir/", b"", directory), ("dir/a", b"x" * 4097, regular), ("dir/empty", b"", regular)])
    deflated = _archive([("file", b"abc", regular)], zipfile.ZIP_DEFLATED)
    root = _publication(tmp_path, [("object.json", b"{}"), ("stored.zip", stored), ("deflated.zip", deflated)])
    before = {p: p.stat().st_mtime_ns for p in root.rglob("*")}
    result = _census(root)
    assert result["publication_source_sha"] == "a" * 40
    assert result["publication_files"] == 3
    assert result["zip_member_files"] == 3  # Includes the empty file, with no data page.
    assert result["zip_expanded_bytes"] == 4100
    assert result["zip_expanded_page_bytes"] == 3 * 4096
    assert result["counted_file_count"] == 8
    assert result["conservative_directory_count"] == 9  # Shared parents overcount.
    assert result["counted_data_page_bytes"] == 9 * 4096
    assert result["metadata_reserve_bytes"] == 1000
    assert result["transient_reserve_bytes"] == 5000
    assert result["data_plus_reserve_page_bytes"] == 12 * 4096
    assert not result["complete_native_tree_bound"]
    assert not result["reserve_adequacy_proved"]
    assert {p: p.stat().st_mtime_ns for p in root.rglob("*")} == before


def test_duplicate_asset_records_conservatively_overcount(tmp_path):
    data = _archive([("file", b"x", stat.S_IFREG | 0o644)])
    root = _publication(tmp_path, [("pack.zip", data)])
    row = json.loads((root / "asset-plan.jsonl").read_text())
    _plan(root, [row, row])
    result = _census(root)
    assert result["publication_files"] == 2
    assert result["zip_member_files"] == 2
    assert result["zip_expanded_page_bytes"] == 8192


def test_root_alias_and_inconsistent_metadata_are_rejected(tmp_path):
    root = _publication(tmp_path, [("object.json", b"{}")])
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        _census(alias)
    metadata = root / "installed-bundle-assets.v1.json"
    value = json.loads(metadata.read_text())
    value["asset_count"] = 2
    metadata.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="does not match"):
        _census(root)


def test_duplicate_json_keys_are_not_silently_overridden(tmp_path):
    root = _publication(tmp_path, [("object.json", b"{}")])
    plan = root / "asset-plan.jsonl"
    plan.write_text(plan.read_text().replace('"length": 2', '"length": 1, "length": 2'))
    with pytest.raises(ValueError, match="duplicate JSON key"):
        _census(root)


@pytest.mark.parametrize("change", ["length", "hash", "boolean", "extra-key", "absolute", "traversal", "url"])
def test_invalid_or_out_of_root_plan_is_rejected(tmp_path, change):
    root = _publication(tmp_path, [("object.json", b"{}")])
    row = json.loads((root / "asset-plan.jsonl").read_text())
    if change == "length":
        row["length"] += 1
    elif change == "hash":
        row["sha256"] = "0" * 64
    elif change == "boolean":
        row["length"] = True
    elif change == "extra-key":
        row["location"]["member"] = "unexpected"
    elif change == "absolute":
        row["location"]["asset"] = "/etc/passwd"
    elif change == "traversal":
        row["location"]["tag"] = ".."
    else:
        row["location"]["tag"] = "https://invalid.example"
    _plan(root, [row])
    with pytest.raises((ValueError, OSError)):
        _census(root)


@pytest.mark.parametrize(
    "path", ["release", "release/object.json", "asset-plan.jsonl", "installed-bundle-assets.v1.json"]
)
def test_symlinks_in_every_input_layer_are_rejected(tmp_path, path):
    root = _publication(tmp_path, [("object.json", b"{}")])
    target = root / path
    outside = tmp_path / "outside"
    target.rename(outside)
    target.symlink_to(outside, target_is_directory=outside.is_dir())
    with pytest.raises((ValueError, OSError)):
        _census(root)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX fixture")
def test_nonregular_metadata_is_rejected_without_blocking(tmp_path):
    root = _publication(tmp_path, [("object.json", b"{}")])
    plan = root / "asset-plan.jsonl"
    plan.rename(tmp_path / "old-plan")
    os.mkfifo(plan)
    with pytest.raises(ValueError, match="regular"):
        _census(root)


def test_unlisted_files_and_oversized_plan_are_rejected(tmp_path):
    root = _publication(tmp_path, [("object.json", b"{}")])
    unlisted = root / "release" / "unlisted"
    unlisted.write_bytes(b"missing from plan")
    with pytest.raises(ValueError, match="unlisted"):
        _census(root)
    unlisted.unlink()
    (root / "asset-plan.jsonl").write_bytes(b" " * 2049)
    with pytest.raises(ValueError, match="row bounds"):
        _census(root)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "a//b", "C:/drive", "a\\b"])
def test_unsafe_zip_members_never_reach_extraction(tmp_path, name):
    data = _archive([(name, b"payload", stat.S_IFREG | 0o644)])
    root = _publication(tmp_path, [("pack.zip", data)])
    with pytest.raises(ValueError, match="unsafe"):
        _census(root)
    assert not (tmp_path / "escape").exists()


def test_zip_symlink_is_rejected(tmp_path):
    data = _archive([("link", b"target", stat.S_IFLNK | 0o777)])
    root = _publication(tmp_path, [("pack.zip", data)])
    with pytest.raises(ValueError, match="unsafe"):
        _census(root)


@pytest.mark.parametrize("name", ["pack.zip", "pack.ZIP", "object.json"])
def test_one_level_members_are_opaque_even_when_their_bytes_are_zip(tmp_path, name):
    inner = _archive([("file", b"content", stat.S_IFREG | 0o644)])
    outer = _archive([(name, inner, stat.S_IFREG | 0o644)])
    root = _publication(tmp_path, [("container.zip", outer)])
    result = _census(root)
    assert result["zip_member_files"] == 1
    assert result["zip_expanded_bytes"] == len(inner)


def test_direct_object_zip_bytes_are_opaque_and_fixture_model_refuses_pack_containers(tmp_path):
    data = _archive([("file", b"content", stat.S_IFREG | 0o644)])
    root = _publication(tmp_path, [("object-" + hashlib.sha256(data).hexdigest() + ".json", data)])
    result = resource.census(
        root, page_size=4096, metadata_reserve_bytes=0, transient_reserve_bytes=0, standalone_fixture=True
    )
    assert result["zip_member_files"] == 0
    assert result["asset_bytes"] == len(data)
    path = next((root / "release").iterdir())
    path.rename(path.with_name("packs-000000.zip"))
    rows = [json.loads(line) for line in (root / "asset-plan.jsonl").read_text().splitlines()]
    rows[0]["location"]["asset"] = "packs-000000.zip"
    _plan(root, rows)
    with pytest.raises(ValueError, match="standalone fixture"):
        resource.census(
            root, page_size=4096, metadata_reserve_bytes=0, transient_reserve_bytes=0, standalone_fixture=True
        )


@pytest.mark.parametrize("damage", ["crc", "truncated", "trailing", "understated-deflate"])
def test_outer_hash_cannot_make_malformed_zip_accounting_valid(tmp_path, damage):
    method = zipfile.ZIP_DEFLATED if damage == "understated-deflate" else zipfile.ZIP_STORED
    data = bytearray(_archive([("file", b"hello", stat.S_IFREG | 0o644)], method))
    if damage == "crc":
        data[34] ^= 1
    elif damage == "truncated":
        data = data[:-1]
    elif damage == "trailing":
        data += b"extra"
    else:
        central = data.index(b"PK\x01\x02")
        # Forge both lengths/CRCs to describe only the first output byte. A
        # reader trusting declared size would undercount the real deflate output.
        struct.pack_into("<I", data, 22, 1)
        struct.pack_into("<I", data, central + 24, 1)
        struct.pack_into("<I", data, 14, zlib.crc32(b"h"))
        struct.pack_into("<I", data, central + 16, zlib.crc32(b"h"))
    root = _publication(tmp_path, [("pack.zip", bytes(data))])
    with pytest.raises((ValueError, zipfile.BadZipFile, zlib.error)):
        _census(root)


@pytest.mark.parametrize(
    "field",
    [
        "asset_bytes",
        "total_asset_bytes",
        "zip_members",
        "total_zip_members",
        "zip_directory_bytes",
        "member_bytes",
        "expanded_bytes",
    ],
)
def test_explicit_read_and_expansion_budgets_fail_closed(tmp_path, field):
    data = _archive([("one", b"ab", stat.S_IFREG | 0o644), ("two", b"cd", stat.S_IFREG | 0o644)])
    root = _publication(tmp_path, [("pack.zip", data)])
    with pytest.raises(ValueError, match="bound"):
        _census(root, limits=replace(resource.Limits(), **{field: 1}))


def test_input_mutation_during_second_pass_invalidates_result(tmp_path, monkeypatch):
    data = _archive([("file", b"hello", stat.S_IFREG | 0o644)])
    root = _publication(tmp_path, [("pack.zip", data)])
    original = resource._zip

    def mutate(*args):
        result = original(*args)
        with (root / "release" / "pack.zip").open("ab") as stream:
            stream.write(b"changed")
        return result

    monkeypatch.setattr(resource, "_zip", mutate)
    with pytest.raises(ValueError, match="changed during census"):
        _census(root)
