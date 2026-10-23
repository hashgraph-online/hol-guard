"""Publish exact package-pinned positive data before a normal package is installable.

This uses the existing immutable GitHub asset publisher. It publishes no Root,
selector, authority epoch or freshness statement for the installed 0.0 profile.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path

import extension_delivery_github as provider
from extension_delivery_containers import member, target, verify_inventory
from extension_delivery_inventory_store import InventoryStore
from extension_delivery_objects import entries
from extension_delivery_policy_lookup import read_transport_page, validate_record

from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import ROOT, asset_path, validate
from codex_plugin_scanner.guard.extension_builder.io import checked_path, read_bytes


def plan_rows(directory, count):
    from codex_plugin_scanner.guard.catalog_delivery.authority import decode

    with checked_path(directory / "asset-plan.jsonl").open("rb") as stream:
        for _ in range(count):
            line = stream.readline(2049)
            if len(line) > 2048 or not line.endswith(b"\n"):
                raise ValueError("installed publication asset record missing or oversized")
            yield decode(line)
        if stream.read(1):
            raise ValueError("installed publication asset count differs from inventory")


def inventory(directory, wheel, source):
    from codex_plugin_scanner.guard.catalog_delivery.authority import decode

    value = decode(read_bytes(directory / "installed-bundle-assets.v1.json", limit=65536))
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "source_sha", "root_sha256", "asset_count"}
        or value["schema"] != "guard.installed-bundle-assets.v1"
        or value["source_sha"] != source
        or re.fullmatch(r"[0-9a-f]{40}", source) is None
        or type(value["asset_count"]) is not int
        or not 0 < value["asset_count"] <= 256 * 1000000
    ):
        raise ValueError("installed publication inventory identity invalid")
    with zipfile.ZipFile(wheel) as archive:
        infos = [info for info in archive.infolist() if info.filename == ROOT]
        if len(infos) != 1 or not 0 < infos[0].file_size <= 65536:
            raise ValueError("normal wheel must contain one bounded installed Root")
        data = archive.read(infos[0])
    root = decode(data)
    validate(data, source_sha=source, engine=root["engine"])
    if hashlib.sha256(data).hexdigest() != value["root_sha256"]:
        raise ValueError("publication inventory differs from normal wheel Root")
    groups, seen = defaultdict(dict), set()
    for row in plan_rows(directory, value["asset_count"]):
        if not isinstance(row, dict) or set(row) != {"location", "sha256", "length"}:
            raise ValueError("installed publication asset invalid")
        location = row["location"]
        if not isinstance(location, dict) or set(location) != {"tag", "asset"}:
            raise ValueError("installed publication location invalid")
        tag, name = location["tag"], location["asset"]
        asset_path("assets/" + tag + "/" + name, source_sha=source)
        if (tag, name) in seen or len(groups[tag]) >= 256:
            raise ValueError("installed publication duplicate or oversized release")
        seen.add((tag, name))
        length = row["length"]
        if type(length) is not int or not 0 < length <= 32 * 1024 * 1024:
            raise ValueError("installed publication asset bounds invalid")
        path = directory / tag / name
        content = read_bytes(path, limit=length)
        if len(content) != length or hashlib.sha256(content).hexdigest() != row["sha256"]:
            raise ValueError("installed publication asset integrity invalid")
        groups[tag][name] = (path, {"length": length, "sha256": row["sha256"]})
    actual = {path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file()}
    if actual != {tag + "/" + name for tag, name in seen} | {"installed-bundle-assets.v1.json", "asset-plan.jsonl"}:
        raise ValueError("installed publication assets are incomplete or unexpected")
    verify_reachable(directory, root, groups)
    return groups


def verify_reachable(directory, root, groups):
    with tempfile.TemporaryDirectory(prefix="guard-publication-inventory-") as temporary:
        store = InventoryStore(Path(temporary).resolve())

        def fetch(location, length):
            name, _, _ = target(location, source_sha=root["source_sha"])
            path, spec = groups[location["tag"]][location["asset"]]
            data = read_bytes(path, limit=spec["length"])
            return member(data, location["asset"], name, length) if "member" in location else data

        store.fetch = fetch
        policy = root["policy"]

        def walk(reference, native, count, prefix="", depth=0):
            if depth > 64:
                raise ValueError("installed publication transport depth invalid")
            wrapper, page = read_transport_page(store, reference, native, count, prefix)
            if page["kind"] == "branch":
                for index, (key, size, child) in enumerate(page["children"]):
                    walk(wrapper["children"][index][2], child, size, key, depth + 1)
                return
            for index, (identity, reference) in enumerate(page["entries"]):
                record = validate_record(store.json(wrapper["records"][index][1]), identity, reference)
                store.json(record["catalog_metadata"])
                for archive in record["archives"]:
                    target(archive["location"], source_sha=root["source_sha"])
                    if "member" in archive["location"]:
                        raise ValueError("installed publication policy archives must be independent")
                    store.mark("pack", archive["sha256"], archive["length"], archive["location"])

        native = policy["root"]
        walk(policy["transport"], native["index"], native["extensions"])
        rows = [policy["defaults"], policy["revocations"], *root.get("compatibility", {}).values()]
        for row in rows:
            for _, reference in entries(store, row["index"], row["count"]) if row["count"] else ():
                store.json(reference)
        actual = {(tag, name) for tag, rows in groups.items() for name in rows}
        if actual != set(store.assets):
            raise ValueError("installed publication inventory differs from Root reachability")
        for (tag, name), spec in store.assets.items():
            path, expected = groups[tag][name]
            if spec["kind"] == "container":
                verify_inventory(read_bytes(path, limit=expected["length"]), name, spec["members"])
            elif any(spec[field] != expected[field] for field in ("sha256", "length")):
                raise ValueError("installed publication asset differs from Root reference")


def publish(directory, wheel, source, *, verify_only=False):
    groups = inventory(directory, wheel, source)
    if not verify_only:
        for tag, rows in sorted(groups.items()):
            provider.publish_assets(
                tag, source, {name: row[0] for name, row in rows.items()}, {name: row[1] for name, row in rows.items()}
            )
    return {"releases": len(groups), "assets": sum(len(rows) for rows in groups.values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    print(
        json.dumps(publish(args.directory, args.wheel, args.source_sha, verify_only=args.verify_only), sort_keys=True)
    )


if __name__ == "__main__":
    main()
