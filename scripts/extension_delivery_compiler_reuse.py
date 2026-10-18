"""Materialize prior compiler inputs only from a verified publication.

This is maintainer build reuse, not runtime activation or a new trust source.
The native compiler rechecks the current source inventory, cache keys, Merkle
proofs and compiled IR; no cache-owned receipt can grant authenticity.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from build_native_command_packs import safe_directory
from command_pack_store import durable_directory, publish_object, read_object
from extension_delivery_located_store import LocatedStore
from extension_delivery_objects import encoded
from extension_delivery_policy_lookup import read_transport_page, validate_record
from extension_pack_archives import ingest

from codex_plugin_scanner.guard.catalog_delivery.authority import VerifiedDistribution
from codex_plugin_scanner.guard.catalog_delivery.transport import cached_fetcher


@dataclass(frozen=True, init=False)
class VerifiedCompilerReuse:
    directory: Path
    root_digest: str

    def arguments(self):
        return ["compile-packs-reuse", str(self.directory), self.root_digest]


def prepare(verified, directory: Path, engine: str):
    if not isinstance(verified, VerifiedDistribution):
        raise ValueError("compiler reuse requires an authenticated publication")
    publication = verified.manifest()
    root = publication["policy"]["root"]
    if root["engine"] != engine:
        return None
    data = encoded(root)
    digest = hashlib.sha256(data).hexdigest()
    destination = directory / "compiler-inputs" / digest
    safe_directory(destination)
    objects = destination / "objects"
    safe_directory(objects)
    fetch = cached_fetcher(directory / "transfers")
    store = LocatedStore(directory / "metadata", fetch=fetch)

    def walk(transport, expected, count, prefix=""):
        wrapper, page = read_transport_page(store, transport, expected, count, prefix)
        # Native index objects retain their own exact digest and byte proof.
        publish_object(objects, expected["sha256"], store.blob(wrapper["native"]))
        if page["kind"] == "branch":
            for index, (key, child_count, target) in enumerate(page["children"]):
                walk(wrapper["children"][index][2], target, child_count, key)
        else:
            for index, (identity, manifest) in enumerate(page["entries"]):
                record = validate_record(store.json(wrapper["records"][index][1]), identity, manifest)
                for archive in record["archives"]:
                    ingest(fetch(archive["location"], archive["length"]), archive["sha256"], archive["length"], objects)

    walk(publication["policy"]["transport"], root["index"], root["extensions"])
    path = destination / "release.json"
    publish_object(destination, digest, data)
    try:
        os.link(destination / (digest + ".json"), path)
    except FileExistsError:
        if path.is_symlink() or read_object(path) != data:
            raise ValueError("compiler reuse root differs from authenticated publication") from None
    durable_directory(destination)
    result = object.__new__(VerifiedCompilerReuse)
    object.__setattr__(result, "directory", destination)
    object.__setattr__(result, "root_digest", digest)
    return result
