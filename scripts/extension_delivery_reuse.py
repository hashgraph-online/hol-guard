"""Reuse immutable locations only after verifying a current published root."""

from __future__ import annotations

from extension_delivery_fetch import cached_fetcher
from extension_delivery_located_store import LocatedStore
from extension_delivery_objects import entries
from extension_delivery_policy_lookup import read_transport_page, validate_record

from codex_plugin_scanner.guard.catalog_delivery.authority import VerifiedDistribution


class ReuseStore(LocatedStore):
    def __init__(self, directory):
        super().__init__(directory, fetch=cached_fetcher(directory / "transfers"))
        self.locations = {}

    def blob(self, reference, depth=0):
        result = super().blob(reference, depth)
        self.locations["object:" + reference["sha256"]] = reference["location"]
        return result


def locations(verified, directory):
    if not isinstance(verified, VerifiedDistribution):
        raise ValueError("location reuse requires an authenticated release root")
    root = verified.manifest()
    store = ReuseStore(directory)
    for index in (
        root["directory"],
        root["directory"]["claims"],
        root["policy"]["defaults"],
        root["policy"]["revocations"],
    ):
        for _, reference in entries(store, index["index"], index["count"]) if index["count"] else ():
            store.json(reference)

    def walk(reference, expected, count, prefix=""):
        wrapper, page = read_transport_page(store, reference, expected, count, prefix)
        if page["kind"] == "branch":
            for index, (key, child_count, target) in enumerate(page["children"]):
                walk(wrapper["children"][index][2], target, child_count, key)
        else:
            for index, (identity, manifest) in enumerate(page["entries"]):
                record = validate_record(store.json(wrapper["records"][index][1]), identity, manifest)
                store.json(record["catalog_metadata"])
                for archive in record["archives"]:
                    store.locations["pack:" + archive["sha256"]] = archive["location"]

    native = root["policy"]["root"]
    walk(root["policy"]["transport"], native["index"], native["extensions"])
    return store.locations
