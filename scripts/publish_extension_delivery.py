"""Publish authenticated immutable data completely before advancing its pointer."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections import defaultdict
from pathlib import Path

import extension_artifact_bundle as legacy
import extension_delivery_github as provider
from extension_delivery_containers import maximum
from extension_delivery_inventory import publication_inventory, read_plan
from extension_delivery_legacy import UNAVAILABLE, unavailable_marker
from extension_delivery_runtime import pinned_runtime
from extension_delivery_selector import select
from extension_delivery_source import verify_sources

from codex_plugin_scanner.guard.catalog_delivery.authority import (
    MAX_PROVENANCE_BYTES,
    _verify_attested_digest,
    decode,
    verify_distribution,
)
from codex_plugin_scanner.guard.catalog_delivery.selection import root_tag
from codex_plugin_scanner.guard.catalog_delivery.transport import PROVENANCE_ASSET, ROOT_ASSET
from codex_plugin_scanner.guard.extension_builder.io import read_bytes


def spec(path, maximum):
    data = read_bytes(path, limit=maximum)
    return {"sha256": hashlib.sha256(data).hexdigest(), "length": len(data)}


def publish_legacy(directory, root, source):
    state = root["legacy"]
    directory = directory / "legacy"
    available = state["status"] == "available"
    if available:
        legacy.verify_bundle(directory, source)
        names = (legacy.MANIFEST, legacy.ARCHIVE)
    else:
        marker = decode(read_bytes(directory / UNAVAILABLE, limit=16384))
        if marker != unavailable_marker(source, state["code"]):
            raise ValueError("legacy unavailability marker differs from authenticated status")
        names = (UNAVAILABLE,)
    provenance = read_bytes(directory / "extension-artifacts.intoto.jsonl", limit=MAX_PROVENANCE_BYTES)
    paths = {name: directory / name for name in (*names, "extension-artifacts.intoto.jsonl")}
    expected = {
        name: spec(path, MAX_PROVENANCE_BYTES if name.endswith(".intoto.jsonl") else legacy.MAX_BYTES)
        for name, path in paths.items()
    }
    if available and (
        expected[legacy.MANIFEST]["sha256"] != state["manifest_sha256"]
        or expected[legacy.ARCHIVE]["sha256"] != state["archive_sha256"]
    ):
        raise ValueError("legacy compatibility artifacts differ from authenticated root")

    def verify(bundle):
        for name in names:
            _verify_attested_digest(expected[name]["sha256"], bundle, name, source)

    verify(provenance)
    provider.publish_assets("extension-artifacts-" + source, source, paths, expected, verify_existing_provenance=verify)


def publish(directory, source, publication):
    data = read_bytes(directory / ROOT_ASSET, limit=65536)
    provenance = read_bytes(directory / PROVENANCE_ASSET, limit=MAX_PROVENANCE_BYTES)
    verified = verify_distribution(data, provenance, expected_source_sha=source, now=int(time.time()))
    root = verified.manifest()
    if root["publication_id"] != publication or tuple(map(int, publication.split("."))) == (0, 0):
        raise ValueError("publication identity differs or is local-only")
    verify_sources(Path(__file__).resolve().parents[1], source, generated=True)
    assets = publication_inventory(directory, verified, Path(__file__).resolve().parents[1])
    rows = read_plan(directory, assets, source, publication)
    # Every release carries the signed distribution root, which already binds
    # each data asset in it by digest. Reusing the attested root bundle keeps
    # the published evidence verifiable under the authority subject bounds,
    # the way the legacy compatibility release already reuses it.
    anchor = {name: directory / name for name in (ROOT_ASSET, PROVENANCE_ASSET)}
    anchor_specs = {
        name: spec(path, MAX_PROVENANCE_BYTES if name == PROVENANCE_ASSET else 65536) for name, path in anchor.items()
    }

    def verify(bundle):
        verify_distribution(data, bundle, expected_source_sha=source, now=int(time.time()))

    provider.verify_repository()
    pending = defaultdict(dict)
    for row in rows:
        pending[row["location"]["tag"]][row["location"]["asset"]] = row
    old = defaultdict(dict)
    for (tag, name), row in assets.items():
        if tag not in pending:
            old[tag][name] = row
    # Old immutable locations must still be complete public releases. No root
    # becomes selected while an object is stranded in a draft or missing.
    for tag, expected in sorted(old.items()):
        release = provider.release(tag)
        if release is None or release.get("draft") is not False or release.get("tag_name") != tag:
            raise ValueError("reused data release is unavailable")
        provider.verify_tag(tag, tag.split("-")[2])
        remote = provider.asset_inventory(release["id"])
        for name, row in expected.items():
            if name not in remote:
                raise ValueError("reused release asset is missing")
            if row["kind"] == "container":
                size = remote[name].get("size")
                if type(size) is not int or not 0 < size <= maximum(name) or remote[name].get("state") != "uploaded":
                    raise ValueError("reused transfer container is unavailable or oversized")
                # Every selected member is separately digest-bound by the signed
                # root. Avoid downloading all inactive policy to check presence.
            else:
                provider.verify_asset(remote[name], row)
    for tag, expected in sorted(pending.items()):
        if set(anchor) & set(expected):
            raise ValueError("data release inventory collides with the distribution root")
        paths = {name: directory / "assets" / tag / name for name in expected}
        provider.publish_assets(
            tag, source, {**paths, **anchor}, {**expected, **anchor_specs}, verify_existing_provenance=verify
        )
    publish_legacy(directory, root, source)
    provider.publish_assets(
        root_tag(source, publication), source, anchor, anchor_specs, verify_existing_provenance=verify
    )
    selected = select(
        {
            "schema": "guard.extension-distribution-selector.v2",
            "source_sha": source,
            "publication_id": publication,
            "root_sha256": verified.digest,
        }
    )
    return {"selected": selected, "source_sha": source, "publication_id": publication, "root_sha256": verified.digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--publication-id", required=True)
    args = parser.parse_args()
    print(json.dumps(publish(args.directory, args.source_sha, args.publication_id), sort_keys=True))


if __name__ == "__main__":
    with pinned_runtime():
        main()
