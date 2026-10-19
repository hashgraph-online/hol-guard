"""Build-time default closure and immutable installed-release asset inventory."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from extension_delivery_objects import entries
from extension_delivery_policy_lookup import lookup


def validate_resident_core(root):
    """A lean data directory cannot excuse a whole optional resident program."""
    reviewed = json.loads((root / "contracts/extensions/core-defaults.v1.json").read_bytes())
    program = json.loads((root / "contracts/extensions/native-command-program.v1.json").read_bytes())
    if reviewed.get("schema") != "guard.core-defaults.v1":
        raise ValueError("normal packages require the reviewed resident core profile")
    expected = {row["extension_id"] for row in reviewed["entries"]}
    actual = [row["extension_id"] for row in program["extensions"]]
    if not expected or len(actual) != len(expected) or set(actual) != expected:
        raise ValueError("normal package resident inputs contain optional policy or omit core policy")


def default_assets(policy, store):
    """Only build-time traversal; runtime selection belongs to the native reader."""
    defaults = policy["defaults"]
    pending = (
        [identity for identity, _ in entries(store, defaults["index"], defaults["count"])] if defaults["count"] else []
    )
    seen, result = set(), set()
    while pending:
        identity = pending.pop()
        if identity in seen:
            continue
        seen.add(identity)
        record = lookup(store, policy["root"], policy["transport"], identity)
        if record is None:
            raise ValueError("installed default dependency is unavailable")
        catalog = store.json(record["catalog_metadata"])[0]
        if catalog["trust_class"] == "external":
            raise ValueError("installed defaults cannot activate external policy")
        pending.extend(catalog["dependencies"])
        owned = {permission["permission_id"] for permission in catalog["permissions"]}
        references = {
            reference
            for permission in catalog["permissions"]
            for field in ("dependencies", "implied_permissions")
            for reference in permission[field]
        } - owned
        for reference in references:
            owners = []
            for candidate in record["related_interfaces"]:
                related = lookup(store, policy["root"], policy["transport"], candidate)
                if related is not None and any(
                    permission["permission_id"] == reference
                    for permission in store.json(related["catalog_metadata"])[0]["permissions"]
                ):
                    owners.append(candidate)
            if len(owners) != 1:
                raise ValueError("installed default permission dependency is ambiguous")
            pending.extend(owners)
        for archive in record["archives"]:
            location = archive["location"]
            if "member" in location:
                raise ValueError("installed policy must have independently addressed archives")
            result.add((location["tag"], location["asset"]))
    return result


def stage_assets(source, destination, assets, defaults, *, offline):
    """Keep metadata available offline; omit every unrelated executable archive."""
    count = total = 0
    for row in assets:
        location = row["location"]
        key = location["tag"], location["asset"]
        if not offline and location["asset"].startswith("pack-") and key not in defaults:
            continue
        relative = Path(*key)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, target)
        count += 1
        total += row["length"]
    return count, total


def publication_plan(directory, data, source, assets):
    value = {
        "schema": "guard.installed-bundle-assets.v1",
        "source_sha": source,
        "root_sha256": hashlib.sha256(data).hexdigest(),
        "asset_count": len(assets),
    }
    (directory / "installed-bundle-assets.v1.json").write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    )
    with (directory / "asset-plan.jsonl").open("x", encoding="utf-8") as stream:
        for asset in assets:
            data = json.dumps(asset, sort_keys=True, separators=(",", ":")) + "\n"
            if len(data.encode()) > 2048:
                raise ValueError("installed publication asset record exceeds byte limit")
            stream.write(data)
