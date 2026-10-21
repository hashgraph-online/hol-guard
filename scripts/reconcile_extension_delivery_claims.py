"""Plan existing claim notices from authenticated paged public metadata."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from extension_delivery_located_store import LocatedStore
from extension_delivery_objects import entries, lookup_entry
from notify_merged_extension_claimants import GitHubApi
from reconcile_extension_claim_notices import pending_entries

from codex_plugin_scanner.guard.catalog_delivery.authority import MAX_PROVENANCE_BYTES, verify_distribution
from codex_plugin_scanner.guard.catalog_delivery.transport import PROVENANCE_ASSET, ROOT_ASSET, cached_fetcher
from codex_plugin_scanner.guard.extension_builder.io import read_bytes


def invitation_entries(verified, store):
    root = verified.manifest()
    directory = root["directory"]
    claims = directory["claims"]
    result = []
    for identity, reference in entries(store, claims["index"], claims["count"]) if claims["count"] else ():
        row = store.json(reference)
        if (
            not isinstance(row, dict)
            or set(row) != {"extensionId", "githubId", "pullRequest"}
            or row["extensionId"] != identity
            or not isinstance(row["githubId"], str)
            or not row["githubId"].isascii()
            or not row["githubId"].isdecimal()
            or type(row["pullRequest"]) is not int
            or row["pullRequest"] <= 0
        ):
            raise ValueError("claim invitation entry invalid")
        target = lookup_entry(store, directory["index"], directory["count"], identity)
        entry = store.json(target) if target is not None else None
        if (
            not isinstance(entry, dict)
            or entry.get("id") != identity
            or entry.get("trustClass") != "external"
            or entry.get("claimPolicy") != "provenance"
            or row["githubId"] not in entry.get("maintainerGithubIds", [])
        ):
            raise ValueError("claim invitation differs from authenticated public authority")
        result.append(row)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    verified = verify_distribution(
        read_bytes(args.directory / ROOT_ASSET, limit=65536),
        read_bytes(args.directory / PROVENANCE_ASSET, limit=MAX_PROVENANCE_BYTES),
        expected_source_sha=args.source_sha,
        now=int(time.time()),
    )
    store = LocatedStore(args.directory / "claim-metadata", fetch=cached_fetcher(args.directory / "claim-transfers"))
    rows = invitation_entries(verified, store)
    client = GitHubApi(os.environ.get("GH_TOKEN", ""), "hashgraph-online/hol-guard")
    print(json.dumps(pending_entries(client, rows, sorted({row["pullRequest"] for row in rows}))))


if __name__ == "__main__":
    main()
