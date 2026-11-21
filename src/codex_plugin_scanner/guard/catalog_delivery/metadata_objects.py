"""Bounded metadata objects and indexes. Integrity alone grants no authority."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .containers import location
from .pack_store import MAX_BLOB_BYTES, MAX_OBJECT_BYTES, PackReader, digest, publish_object


def encoded(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


class ObjectStore(PackReader):
    def __init__(self, directory: Path):
        super().__init__(directory)
        for parent in (directory, *directory.parents):
            if parent.is_symlink():
                raise ValueError("delivery object directory traverses a symlink")
        directory.mkdir(parents=True, exist_ok=True)

    def put(self, data: bytes, kind="data", expanded_length=None) -> dict[str, Any]:
        if not 0 < len(data) <= MAX_OBJECT_BYTES:
            raise ValueError("delivery object exceeds byte limit")
        sha = hashlib.sha256(data).hexdigest()
        expanded_length = len(data) if expanded_length is None else expanded_length
        if (
            kind not in {"data", "concat"}
            or type(expanded_length) is not int
            or not 0 < expanded_length <= MAX_BLOB_BYTES
            or (kind == "data" and expanded_length != len(data))
        ):
            raise ValueError("delivery expansion length invalid")
        publish_object(self.directory, sha, data)
        return {"sha256": sha, "length": len(data), "kind": kind, "expanded_length": expanded_length}

    def put_json(self, value) -> dict[str, Any]:
        data = encoded(value)
        if not 0 < len(data) <= MAX_BLOB_BYTES:
            raise ValueError("delivery metadata exceeds assembled byte limit")
        refs = [self.put(data[index : index + MAX_OBJECT_BYTES]) for index in range(0, len(data), MAX_OBJECT_BYTES)]
        while len(refs) > 1:
            refs = [
                self.put(
                    encoded({"schema": "guard.pack-concat.v1", "parts": parts}),
                    "concat",
                    sum(part["expanded_length"] for part in parts),
                )
                for offset in range(0, len(refs), 64)
                if (parts := refs[offset : offset + 64])
            ]
        return refs[0]

    def index(self, entries: dict[str, dict[str, Any]], prefix="") -> dict[str, Any]:
        if not entries or len(prefix) > 64:
            raise ValueError("delivery index is empty or too deep")
        if any(not isinstance(key, str) or not key.isascii() or not 0 < len(key) <= 256 for key in entries):
            raise ValueError("delivery index identity invalid")
        if len(entries) <= 64:
            return self.put_json(
                {"schema": "guard.pack-index.v1", "kind": "leaf", "prefix": prefix, "entries": sorted(entries.items())}
            )
        if len(prefix) == 64:
            raise ValueError("delivery index hash collision")
        groups = defaultdict(dict)
        for key, value in entries.items():
            groups[hashlib.sha256(key.encode()).hexdigest()[: len(prefix) + 1]][key] = value
        children = [[key, len(values), self.index(values, key)] for key, values in sorted(groups.items())]
        return self.put_json(
            {"schema": "guard.pack-index.v1", "kind": "branch", "prefix": prefix, "children": children}
        )


def validate_reference(value):
    fields = {"sha256", "length", "expanded_length", "kind"}
    if (
        not isinstance(value, dict)
        or set(value) not in (fields, fields | {"location"})
        or not digest(value["sha256"])
        or type(value["length"]) is not int
        or not 0 < value["length"] <= MAX_OBJECT_BYTES
        or type(value["expanded_length"]) is not int
        or not 0 < value["expanded_length"] <= MAX_BLOB_BYTES
        or value["kind"] not in ("data", "concat")
        or (value["kind"] == "data" and value["length"] != value["expanded_length"])
    ):
        raise ValueError("delivery index object reference invalid")
    if "location" in value:
        location(value["location"], value["sha256"], "object")
