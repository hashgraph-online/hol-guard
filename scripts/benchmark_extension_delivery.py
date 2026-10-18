"""Measure valid unique offline publication builds, not runtime qualification."""

from __future__ import annotations

import argparse
import json
import resource
import shutil
import sys
import tempfile
import time
from pathlib import Path

import build_extension_delivery as delivery
from command_pack_store import PackReader
from extension_delivery_assets import AssetPlan
from extension_delivery_inventory import prepared_inventory, read_plan
from extension_delivery_located_store import LocatedStore
from extension_delivery_objects import encoded, entries


def source_tree(root, target, count):
    for name in ("command-sources", "mcp-servers", "extensions", "extension-listings"):
        shutil.copytree(root / "contributions" / name, target / "contributions" / name)
    for name in ("extensions/trust", "catalog-delivery"):
        shutil.copytree(root / "contracts" / name, target / "contracts" / name)
    baseline = len(tuple((target / "contributions/command-sources").glob("command.*.json")))
    baseline += len(tuple((target / "contributions/mcp-servers").glob("mcp.*.json")))
    template = (root / "rust/crates/guard-command/tests/fixtures/command-source-example.v1.json").read_text()
    for index in range(count - baseline):
        identity = f"command.scale-{index}"
        raw = template.replace("command.example-cli", identity).replace("example-cli", f"scale-{index}").encode()
        (target / "contributions/command-sources" / (identity + ".json")).write_bytes(raw)
        (target / "contracts/extensions/trust" / (identity + ".v1.json")).write_bytes(
            encoded(
                {
                    "schemaVersion": "guard.extension-trust-binding.v1",
                    "extension": identity,
                    "trustClass": "external",
                }
            )
        )


def public_records(source, policy, native):
    reader = PackReader(policy / "objects")
    for identity, reference in entries(reader, native["index"], native["extensions"]):
        if identity.startswith("command.scale-"):
            manifest = reader.json(reference)
            descriptor = reader.json(manifest["descriptors"])[0]
            (source / "contributions/extensions" / (identity + ".json")).write_bytes(
                delivery.packs.legacy.canonical_bytes(descriptor)
            )


def build(source, output, compiler, *, previous=None, compile_sources=True):
    started = time.perf_counter()
    policy = output.parent / "compiled-policy"
    compilation = delivery.packs.stage(compiler, policy, source_root=source) if compile_sources else None
    native = json.loads((policy / "release.json").read_bytes())
    public_records(source, policy, native)
    publication = {"cold": "0.1", "unchanged": "0.2", "changed": "0.3"}[output.name]
    plan = AssetPlan(output / "assets", "f" * 40, existing=previous, publication_id=publication)
    store = LocatedStore(output / "metadata", publisher=plan)
    try:
        root = delivery.build_from_packs(source, policy, native, plan, store, "f" * 40)
    finally:
        plan.finish()
    output.mkdir(parents=True, exist_ok=True)
    (output / "asset-plan.jsonl").write_bytes(b"".join(encoded(row) + b"\n" for row in plan.pending))
    assets = prepared_inventory(output, root, source, policy_directory=policy)
    read_plan(output, assets, "f" * 40, publication)
    payload = encoded(root)
    (output / "prepared-root.json").write_bytes(payload)
    parent_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    child_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    scale = 1 if sys.platform == "darwin" else 1024
    return (
        root,
        {**(previous or {}), **plan.locations},
        {
            "extensions": native["extensions"],
            "engine": native["engine"],
            "seconds": time.perf_counter() - started,
            "root_bytes": len(payload),
            "new_assets": len(plan.pending),
            "new_transfer_bytes": sum(row["length"] for row in plan.pending),
            "max_transfer_bytes": max((row["length"] for row in plan.pending), default=0),
            "metadata_objects": len(tuple(store.directory.glob("*.json"))),
            "largest_metadata_object": max(path.stat().st_size for path in store.directory.glob("*.json")),
            "process_cumulative_peak_rss_bytes": parent_rss * scale,
            "children_cumulative_peak_rss_bytes": child_rss * scale,
            "compilation": compilation,
        },
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--factors", type=int, nargs="+", default=[1, 10, 100])
    args = parser.parse_args()
    root = delivery.ROOT
    baseline = len(tuple((root / "contributions/command-sources").glob("command.*.json")))
    baseline += len(tuple((root / "contributions/mcp-servers").glob("mcp.*.json")))
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    for factor in args.factors:
        if factor not in {1, 10, 100}:
            parser.error("supported factors are 1, 10, 100")
        with tempfile.TemporaryDirectory(prefix="extension-delivery-benchmark-") as temporary:
            source = Path(temporary).resolve() / "source"
            source_tree(root, source, baseline * factor)
            output = args.output / str(factor)
            cold, locations, report = build(source, output / "cold", args.compiler)
            assert report["extensions"] == baseline * factor
            assert report["largest_metadata_object"] <= 65536
            report["factor"] = factor
            if factor == 1:
                unchanged, reused, warm = build(
                    source, output / "unchanged", args.compiler, previous=locations, compile_sources=False
                )
                assert unchanged == cold and warm["new_assets"] == 0
                path = source / "contributions/command-sources/command.agentbridge.json"
                value = json.loads(path.read_bytes())
                value["extension"]["description"] += " Offline incrementality benchmark."
                path.write_bytes(encoded(value))
                delivery.packs.stage(args.compiler, output / "compiled-policy", source_root=source)
                native = json.loads((output / "compiled-policy/release.json").read_bytes())
                reader = PackReader(output / "compiled-policy/objects")
                manifest = reader.json(
                    dict(entries(reader, native["index"], native["extensions"]))["command.agentbridge"]
                )
                (source / "contributions/extensions/command.agentbridge.json").write_bytes(
                    delivery.packs.legacy.canonical_bytes(reader.json(manifest["descriptors"])[0])
                )
                changed, _, delta = build(
                    source, output / "changed", args.compiler, previous=reused, compile_sources=False
                )
                assert changed["policy"]["defaults"] == cold["policy"]["defaults"]
                assert delta["new_transfer_bytes"] < report["new_transfer_bytes"] / 10
                report.update(unchanged=warm, one_extension_change=delta)
            results.append(report)
            print(json.dumps(report), flush=True)
    (args.output / "report.json").write_text(
        json.dumps(
            {
                "scope": (
                    "offline unsigned build integrity and transfer cost; "
                    "no publication, activation or hook qualification"
                ),
                "results": results,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
