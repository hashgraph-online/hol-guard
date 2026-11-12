"""Validate all reachable publication assets before any public upload."""

from __future__ import annotations

import hashlib

import build_native_command_packs as packs
from command_pack_store import PackReader
from extension_delivery_containers import maximum, verify_inventory
from extension_delivery_inventory_store import InventoryStore
from extension_delivery_objects import entries
from extension_delivery_policy_lookup import read_transport_page, validate_record
from extension_delivery_revocations import load as load_revocations
from extension_pack_archives import pack_objects, parts
from extension_pack_directory import public_entry

from codex_plugin_scanner.guard.catalog_delivery.authority import VerifiedDistribution, decode
from codex_plugin_scanner.guard.extension_builder.io import checked_path, read_bytes


def publication_inventory(directory, verified, source_root):
    if not isinstance(verified, VerifiedDistribution) or not isinstance(getattr(verified, "data", None), bytes):
        raise ValueError("publication requires an authenticated root")
    return prepared_inventory(directory, verified.manifest(), source_root)


def prepared_inventory(directory, root, source_root, *, policy_directory=None):
    """Check build integrity only; this never grants publication authority."""
    native = root["policy"]["root"]
    policy_directory = policy_directory or directory / "compiled-policy"
    local_native = decode(read_bytes(policy_directory / "release.json", limit=65536))
    if local_native != native or native["engine"] != packs.legacy.implementation_digest():
        raise ValueError("prepared native release differs from authenticated current source")
    native_reader = PackReader(policy_directory / "objects")
    native_ids = dict(entries(native_reader, native["index"], native["extensions"]))
    native_reader.verify_release(native, root["engine"], set(native_ids))
    store = InventoryStore(directory / "metadata")
    records = {}

    def walk(reference, expected, count, prefix=""):
        wrapper, page = read_transport_page(store, reference, expected, count, prefix)
        if page["kind"] == "branch":
            for index, (key, child_count, target) in enumerate(page["children"]):
                walk(wrapper["children"][index][2], target, child_count, key)
            return
        for index, (identity, target) in enumerate(page["entries"]):
            reference = wrapper["records"][index][1]
            record = validate_record(store.json(reference), identity, target)
            manifest, objects = pack_objects(PackReader(native_reader.directory), target)
            catalog = native_reader.json(manifest["catalog"])[0]
            if store.json(record["catalog_metadata"]) != [catalog]:
                raise ValueError("public catalog metadata differs from native policy")
            expected_fields = {
                "dependencies": catalog["dependencies"],
                "related_interfaces": sorted(manifest["related_interfaces"]),
                "required": catalog["required"],
                "activation": catalog["activation"],
                "trust_class": catalog["trust_class"],
            }
            if any(record[key] != value for key, value in expected_fields.items()):
                raise ValueError("delivery availability metadata differs from native policy")
            expected_archives = [
                (hashlib.sha256(data).hexdigest(), len(data)) for data in parts(native_reader.directory, objects)
            ]
            if expected_archives != [(item["sha256"], item["length"]) for item in record["archives"]]:
                raise ValueError("delivery archive content differs from compiled pack")
            for archive in record["archives"]:
                store.mark("pack", archive["sha256"], archive["length"], archive["location"])
            records[identity] = (reference, catalog)

    walk(root["policy"]["transport"], native["index"], native["extensions"])
    if set(records) != set(native_ids):
        raise ValueError("delivery transport has incomplete policy ownership")
    defaults = root["policy"]["defaults"]
    actual_defaults = dict(entries(store, defaults["index"], defaults["count"])) if defaults["count"] else {}
    expected_defaults = {key: value[0] for key, value in records.items() if value[1]["enabled"]}
    if actual_defaults != expected_defaults:
        raise ValueError("delivery default selection differs from native policy")
    seen = set()
    public_entries = {}
    for identity, reference in entries(store, root["directory"]["index"], root["directory"]["count"]):
        value = store.json(reference)
        runtime = value.get("runtimeExtensionId") if isinstance(value, dict) else None
        if runtime not in records or runtime in seen or value.get("id") != identity:
            raise ValueError("public directory does not match native ownership")
        expected = public_entry(source_root, [records[runtime][1]])
        enriched = {"maintainerGithubIds", "contributors", "originalContributions"}
        if set(value) != set(expected) or any(
            value[key] != item for key, item in expected.items() if key not in enriched
        ):
            raise ValueError("public directory differs from reviewed contribution inputs")
        seen.add(runtime)
        public_entries[identity] = value
    if seen != set(records):
        raise ValueError("public directory is incomplete")
    claims = root["directory"]["claims"]
    for identity, reference in entries(store, claims["index"], claims["count"]) if claims["count"] else ():
        invitation = store.json(reference)
        if (
            not isinstance(invitation, dict)
            or set(invitation) != {"extensionId", "githubId", "pullRequest"}
            or invitation["extensionId"] != identity
            or not isinstance(invitation["githubId"], str)
            or not invitation["githubId"].isdecimal()
            or type(invitation["pullRequest"]) is not int
            or invitation["pullRequest"] <= 0
        ):
            raise ValueError("claim invitation metadata is invalid")
        owner = public_entries.get(identity)
        if (
            owner is None
            or owner["claimPolicy"] != "provenance"
            or owner["trustClass"] != "external"
            or invitation["githubId"] not in owner["maintainerGithubIds"]
        ):
            raise ValueError("claim invitation differs from public claim authority")
    security, expected_revocations = load_revocations(source_root)
    revocations = root["policy"]["revocations"]
    actual_revocations = (
        {key: store.json(reference) for key, reference in entries(store, revocations["index"], revocations["count"])}
        if revocations["count"]
        else {}
    )
    if (
        root["authority_epoch"] != security["authority_epoch"]
        or revocations["epoch"] != security["revocation_epoch"]
        or actual_revocations != expected_revocations
    ):
        raise ValueError("delivery security metadata differs from reviewed inputs")
    return store.assets


def read_plan(directory, expected, source, publication_id):
    prefix = f"extension-data-{source}-{publication_id}-"
    required = {key for key in expected if key[0].startswith(prefix)}
    found = set()
    rows = []
    with checked_path(directory / "asset-plan.jsonl").open("rb") as stream:
        while line := stream.readline(2049):
            if len(line) > 2048 or not line.endswith(b"\n"):
                raise ValueError("delivery asset plan record exceeds byte limit")
            row = decode(line)
            if (
                not isinstance(row, dict)
                or set(row) != {"location", "sha256", "length"}
                or not isinstance(row["location"], dict)
                or set(row["location"]) != {"tag", "asset"}
            ):
                raise ValueError("delivery asset plan record invalid")
            target = row["location"]
            if (
                not isinstance(target["tag"], str)
                or not isinstance(target["asset"], str)
                or type(row["length"]) is not int
            ):
                raise ValueError("delivery asset plan field types invalid")
            key = (target["tag"], target["asset"])
            if key not in required or key in found:
                raise ValueError("delivery asset plan includes unbound or duplicate data")
            if expected[key]["kind"] == "container":
                if not 0 < row["length"] <= maximum(target["asset"]):
                    raise ValueError("delivery container plan exceeds byte limit")
            elif any(row[field] != expected[key][field] for field in ("sha256", "length")):
                raise ValueError("delivery asset plan differs from authenticated reference")
            data = read_bytes(directory / "assets" / target["tag"] / target["asset"], limit=row["length"])
            if len(data) != row["length"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
                raise ValueError("delivery asset bytes differ from authenticated references")
            if expected[key]["kind"] == "container":
                verify_inventory(data, target["asset"], expected[key]["members"])
            found.add(key)
            rows.append(row)
    if found != required:
        raise ValueError("delivery asset plan is incomplete")
    return rows
