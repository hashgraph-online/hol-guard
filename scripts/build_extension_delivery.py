"""Build separate bounded public metadata and policy delivery artifacts.

Only authenticated publication may grant a root publisher authority. This
maintainer operation does not install policy or change extension controls.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

import build_native_command_packs as packs
from command_pack_store import MAX_OBJECT_BYTES, PackReader, durable_directory
from extension_delivery_assets import AssetPlan
from extension_delivery_legacy import prepare as prepare_legacy
from extension_delivery_located_store import LocatedStore
from extension_delivery_objects import encoded, entries
from extension_delivery_revocations import build as build_revocations
from extension_delivery_source import verify_sources
from extension_pack_directory import public_entry
from extension_policy_delivery import build_policy
from extension_policy_delivery import policy_transport as policy_transport

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "guard.extension-distribution.v2"
MANIFEST = "extension-distribution.v2.json"


def claim_context(root, public, commit):
    """Reuse one batched source history while retaining existing eligibility rules."""
    from extension_claim_github_history import SnapshotClaimHistory
    from notify_merged_extension_claimants import GitHubApi

    client = GitHubApi(os.environ.get("GH_TOKEN", ""), "hashgraph-online/hol-guard", source_root=root)
    paths = []
    for entry in public.values():
        paths.append(entry["sourcePath"])
        if entry["kind"] == "command":
            paths.append(f"contributions/command-sources/{entry['id']}.json")
    return SnapshotClaimHistory(client, paths, commit)


def enrich_entry(root, entry, commit, history):
    from extension_claim_provenance import populate_snapshot_claimants

    files = {
        "docs/guard/extensions/catalog.v1.json": encoded({"entries": [entry]}),
        "docs/guard/extensions/catalog.v2.json": encoded({"entries": [entry]}),
    }
    names = [entry["sourcePath"], f"contributions/extension-listings/{entry['id']}.json"]
    if entry["kind"] == "command":
        names.append(f"contributions/command-sources/{entry['id']}.json")
    for name in names:
        path = root / name
        if path.exists():
            files[name] = packs.legacy.read_source_bytes(path)
    claimants = populate_snapshot_claimants(files, history, commit, batch_history=lambda *args: history)
    claimant = claimants.get(entry["id"])
    invitation = (
        None
        if claimant is None
        else {
            "extensionId": entry["id"],
            "githubId": claimant.github_id,
            "pullRequest": claimant.pull_request,
        }
    )
    return json.loads(files["docs/guard/extensions/catalog.v2.json"])["entries"][0], invitation


def build_from_packs(root, pack_directory, native_root, plan, store, commit, *, resolve_claimants=False, compiler=None):
    reader = PackReader(pack_directory / "objects")
    inventory = dict(entries(reader, native_root["index"], native_root["extensions"]))
    public = {}
    for identity, reference in sorted(inventory.items()):
        manifest = reader.json(reference)
        entry = public_entry(root, reader.json(manifest["catalog"]))
        if entry["runtimeExtensionId"] != identity:
            raise ValueError("public metadata differs from native pack identity")
        public[identity] = entry
    history = claim_context(root, public, commit) if resolve_claimants else None
    policy = build_policy(pack_directory, native_root, plan, store, compiler=compiler)
    directory, claims = {}, {}
    for identity in sorted(inventory):
        entry, invitation = (
            enrich_entry(root, public[identity], commit, history) if history is not None else (public[identity], None)
        )
        directory[entry["id"]] = store.put_json(entry)
        if invitation is not None:
            claims[entry["id"]] = store.put_json(invitation)
    if len(directory) != native_root["extensions"]:
        raise ValueError("public directory ownership is incomplete")
    authority_epoch, revocations = build_revocations(root, store)
    policy["revocations"] = revocations
    return {
        "schema": SCHEMA,
        "source_sha": commit,
        "engine": native_root["engine"],
        "authority_epoch": authority_epoch,
        "directory": {
            "count": len(directory),
            "index": store.index(directory),
            "claims": {"count": len(claims), "index": store.index(claims) if claims else None},
        },
        "policy": policy,
        "claim_provenance": "resolved" if history is not None else "not-resolved",
        "legacy": {"status": "not-generated"},
    }


def create_distribution(
    compiler,
    output,
    commit,
    *,
    resolve_claimants=False,
    existing_locations=None,
    publication_id="0.0",
    reuse_published_legacy=False,
    compiled_reuse=None,
):
    verify_sources(ROOT, commit)
    packs.safe_directory(output)
    policy = output / "compiled-policy"
    report = packs.stage(compiler, policy, reuse=compiled_reuse)
    native_root = json.loads((policy / "release.json").read_bytes())
    plan = AssetPlan(output / "assets", commit, existing=existing_locations, publication_id=publication_id)
    store = LocatedStore(output / "metadata", publisher=plan)
    try:
        root = build_from_packs(
            ROOT, policy, native_root, plan, store, commit, resolve_claimants=resolve_claimants, compiler=compiler
        )
    finally:
        plan.finish()
    root["legacy"] = prepare_legacy(
        ROOT,
        output,
        policy,
        native_root,
        compiler,
        commit,
        resolve_claimants=resolve_claimants,
        reuse_published=reuse_published_legacy,
    )
    issued = int(time.time())
    root.update(publication_id=publication_id, issued_at=issued, expires_at=issued + 7 * 24 * 60 * 60)
    verify_sources(ROOT, commit, generated=True)
    data = encoded(root)
    if len(data) > MAX_OBJECT_BYTES:
        raise ValueError("delivery root exceeds byte limit")
    with (output / "compilation-report.json").open("xb") as stream:
        stream.write(encoded(report))
    path = output / MANIFEST
    if path.is_symlink():
        raise ValueError("delivery root must not be a symlink")
    # This is a prepared artifact. Publication must finish legacy compatibility
    # handling and verify provenance before exposing it as an available release.
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    with (output / "asset-plan.jsonl").open("x") as stream:
        for asset in plan.pending:
            stream.write(encoded(asset).decode() + "\n")
    durable_directory(output)
    return root


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resolve-claimants", action="store_true")
    parser.add_argument("--publication-id", default="0.0")
    parser.add_argument("--reuse-current", action="store_true")
    parser.add_argument("--metadata-cache", type=Path)
    args = parser.parse_args()
    existing = None
    compiled_reuse = None
    if args.reuse_current:
        from extension_delivery_reuse import locations

        from codex_plugin_scanner.guard.catalog_delivery.authority import ExpiredDistributionError
        from codex_plugin_scanner.guard.catalog_delivery.transport import MissingReleaseError, fetch_root, selected

        try:
            selection = selected()
        except MissingReleaseError:
            selection = None
        if selection is not None:
            try:
                previous = fetch_root(now=int(time.time()), selection=selection)
            except (ExpiredDistributionError, MissingReleaseError):
                # Unavailable or expired data cannot seed location reuse.
                # Current sources are compiled independently for this release.
                previous = None
            if previous is not None:
                from extension_delivery_compiler_reuse import prepare as prepare_compiler_reuse

                cache = args.metadata_cache or args.output / "previous-metadata"
                existing = locations(previous, cache)
                compiled_reuse = prepare_compiler_reuse(previous, cache, packs.legacy.implementation_digest())
    root = create_distribution(
        args.compiler.resolve() if args.compiler else packs.bootstrap_compiler(),
        args.output,
        args.source_sha,
        resolve_claimants=args.resolve_claimants,
        publication_id=args.publication_id,
        existing_locations=existing,
        reuse_published_legacy=args.reuse_current,
        compiled_reuse=compiled_reuse,
    )
    print(json.dumps({"schema": SCHEMA, "source_sha": root["source_sha"], "extensions": root["directory"]["count"]}))


if __name__ == "__main__":
    main()
