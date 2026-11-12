"""Build bounded policy data for the normal installed release artifact.

This is package input, not a remotely authenticated update. Native wheel
assembly must bind the resulting root to its verified compiler and source.
Contributor commands and authored records are unchanged.
"""

# pyright: reportImplicitRelativeImport=false

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path

# Isolated Hatch subprocesses have no installed application dependency.
# The package initializers are lazy; only bounded delivery primitives load.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import build_native_command_packs as packs
from command_pack_store import PackReader, durable_directory
from extension_delivery_assets import AssetPlan
from extension_delivery_located_store import LocatedStore
from extension_delivery_objects import encoded, entries
from extension_delivery_revocations import build as build_revocations
from extension_policy_delivery import build_policy
from installed_bundle_assets import default_assets, publication_plan, stage_assets

from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import validate, validate_compatibility

SCHEMA = "guard.command-pack-bundle.v1"
MANIFEST = "command-pack-bundle.v1.json"
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_FILES = 8192


def build_compatibility(source_root, compiled, native_root, store, *, compiler):
    """Copy public metadata only after the complete native inventory validates."""
    reader = PackReader(compiled / "objects")
    commands, mcp, expected_mcp = {}, {}, set()
    for identity, reference in entries(reader, native_root["index"], native_root["extensions"]):
        manifest = reader.json(reference)
        descriptors = reader.json(manifest["descriptors"])
        if not isinstance(descriptors, list) or len(descriptors) > 1:
            raise ValueError("native public descriptor inventory invalid")
        if not descriptors:
            if not identity.startswith("command.mcp-"):
                raise ValueError("native command public descriptor missing")
            expected_mcp.add("mcp." + identity.removeprefix("command.mcp-"))
        for payload in descriptors:
            if not isinstance(payload, dict) or payload.get("id") != identity or identity in commands:
                raise ValueError("native public descriptor identity invalid")
            commands[identity] = store.put_json(payload)
    for path in sorted((source_root / "contributions/mcp-servers").glob("*.json")):
        if path.name == "migration-manifest.json":
            continue
        payload = packs.legacy.source_object(packs.legacy.read_source_bytes(path, root=source_root), path)
        identity = payload.get("id")
        if not isinstance(identity, str) or path.stem != identity or identity in mcp:
            raise ValueError("authored MCP metadata identity invalid")
        mcp[identity] = store.put_json(payload)
    result = {
        family: {"count": len(rows), "index": store.index(rows) if rows else None}
        for family, rows in (("commands", commands), ("mcp", mcp))
    }
    if sum(reference["expanded_length"] for rows in (commands, mcp) for reference in rows.values()) > MAX_BUNDLE_BYTES:
        raise ValueError("public compatibility metadata exceeds expanded byte budget")
    validate_compatibility(result, native_root["extensions"], compiler=compiler)
    if set(mcp) != expected_mcp or len(commands) + len(mcp) != native_root["extensions"]:
        raise ValueError("public compatibility inventory differs from native inventory")
    return result


def core_defaults_evidence(source_root):
    """Read optional reviewed evidence; native code admits the selected defaults."""
    path = source_root / "contracts/extensions/core-defaults.v1.json"
    if not path.exists() and not path.is_symlink():
        return {}  # Older source archives have no separate core representation.
    return {"core_defaults": packs.legacy.read_object(path, root=source_root)}


def build(compiler, output, source_sha, *, source_root, assets_output=None, offline=False):
    if not isinstance(source_sha, str) or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise ValueError("bundle source identity invalid")
    if output.exists() or output.is_symlink():
        raise ValueError("bundle output must be a fresh directory")
    packs.safe_directory(output)
    with tempfile.TemporaryDirectory(prefix="guard-command-pack-bundle-") as temporary:
        temporary = Path(temporary).resolve()
        compiled = temporary / "compiled"
        report = packs.stage(compiler, compiled, source_root=source_root)
        native_root = json.loads((compiled / "release.json").read_bytes())
        asset_directory = assets_output if assets_output is not None else temporary / "publication-assets"
        if asset_directory.exists() or asset_directory.is_symlink():
            raise ValueError("publication asset output must be a fresh directory")
        plan = AssetPlan(asset_directory, source_sha, standalone_policy=not offline)
        store = LocatedStore(temporary / "metadata", publisher=plan)
        try:
            policy = build_policy(
                compiled, native_root, plan, store, compiler=compiler, **core_defaults_evidence(source_root)
            )
            epoch, revocations = build_revocations(source_root, store)
            policy["revocations"] = revocations
            compatibility = build_compatibility(source_root, compiled, native_root, store, compiler=compiler)
            bundled = default_assets(policy, store) if not offline else set()
        finally:
            plan.finish()
        assets = plan.pending
        total = sum(asset["length"] for asset in assets)
        root = {
            "schema": SCHEMA,
            "source_sha": source_sha,
            "engine": native_root["engine"],
            "authority_epoch": epoch,
            "publication_id": "0.0",
            "policy": policy,
            "compatibility": compatibility,
        }
        data = encoded(root)
        validate(data, source_sha=source_sha, engine=native_root["engine"], compiler=compiler)
        if len(data) > 65536:
            raise ValueError("installed policy bundle root exceeds byte budget")
        installed_count, installed_bytes = stage_assets(
            asset_directory, output / "assets", assets, bundled, source_sha=source_sha, offline=offline
        )
        if installed_count > MAX_BUNDLE_FILES or installed_bytes > MAX_BUNDLE_BYTES:
            raise ValueError("installed policy bundle exceeds package budget")
        publication_plan(asset_directory, data, source_sha, assets)
        with (output / MANIFEST).open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        durable_directory(output)
    return {
        "extensions": native_root["extensions"],
        "engine": native_root["engine"],
        "assets": len(assets),
        "asset_bytes": total,
        "installed_assets": installed_count,
        "installed_asset_bytes": installed_bytes,
        "profile": "complete-offline" if offline else "normal",
        "compiled": report,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--assets-output", type=Path)
    parser.add_argument(
        "--offline-bundle", action="store_true", help="Explicit complete offline artifact; not a normal install"
    )
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    print(
        json.dumps(
            build(
                arguments.compiler,
                arguments.output,
                arguments.source_sha,
                source_root=arguments.source_root,
                assets_output=arguments.assets_output,
                offline=arguments.offline_bundle,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
