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


def read_index_page(reader: PackReader, reference: dict[str, Any], count: int, prefix=""):
    """Validate one complete page without loading unrelated child payloads."""
    if type(count) is not int or count <= 0 or len(prefix) > 64:
        raise ValueError("delivery index count or depth invalid")
    validate_reference(reference)
    if (
        not isinstance(reference, dict)
        or type(reference.get("expanded_length")) is not int
        or not 0 < reference["expanded_length"] <= MAX_OBJECT_BYTES
    ):
        raise ValueError("delivery index page exceeds byte limit")
    value = reader.json(reference)
    if not isinstance(value, dict) or value.get("schema") != "guard.pack-index.v1" or value.get("prefix") != prefix:
        raise ValueError("delivery index identity invalid")
    if value.get("kind") == "leaf":
        rows = value.get("entries")
        if (
            set(value) != {"schema", "kind", "prefix", "entries"}
            or not isinstance(rows, list)
            or not 0 < len(rows) <= 64
            or len(rows) != count
        ):
            raise ValueError("delivery index leaf count invalid")
        previous = ""
        for row in rows:
            if not isinstance(row, list) or len(row) != 2:
                raise ValueError("delivery index entry invalid")
            identity, target = row
            if (
                not isinstance(identity, str)
                or not identity.isascii()
                or not 0 < len(identity) <= 256
                or identity <= previous
                or not hashlib.sha256(identity.encode()).hexdigest().startswith(prefix)
            ):
                raise ValueError("delivery index ownership invalid")
            previous = identity
            validate_reference(target)
        return value
    children = value.get("children")
    if (
        set(value) != {"schema", "kind", "prefix", "children"}
        or value.get("kind") != "branch"
        or not isinstance(children, list)
        or not 0 < len(children) <= 16
    ):
        raise ValueError("delivery index branch invalid")
    previous = ""
    total = 0
    for child in children:
        if not isinstance(child, list) or len(child) != 3:
            raise ValueError("delivery index child invalid")
        key, child_count, target = child
        if (
            not isinstance(key, str)
            or len(key) != len(prefix) + 1
            or not key.startswith(prefix)
            or key <= previous
            or any(char not in "0123456789abcdef" for char in key)
            or type(child_count) is not int
            or child_count <= 0
        ):
            raise ValueError("delivery index routing invalid")
        previous = key
        validate_reference(target)
        total += child_count
        if total > count:
            raise ValueError("delivery index count invalid")
    if total != count:
        raise ValueError("delivery index count invalid")
    return value


def lookup_entry(reader, reference, count, identity, prefix=""):
    """Return one entry or a complete absence proof without fetching siblings."""
    if not isinstance(identity, str) or not identity.isascii() or not 0 < len(identity) <= 256:
        raise ValueError("delivery lookup identity invalid")
    hashed = hashlib.sha256(identity.encode()).hexdigest()
    while True:
        page = read_index_page(reader, reference, count, prefix)
        if page["kind"] == "leaf":
            return next((target for key, target in page["entries"] if key == identity), None)
        key = hashed[: len(prefix) + 1]
        match = next((row for row in page["children"] if row[0] == key), None)
        if match is None:
            return None
        prefix, count, reference = match


def entries(reader: PackReader, reference: dict[str, Any], count: int, prefix=""):
    """Walk a complete verified index; each page retains the native bounds."""
    value = read_index_page(reader, reference, count, prefix)
    if value["kind"] == "leaf":
        yield from value["entries"]
    else:
        for key, child_count, target in value["children"]:
            yield from entries(reader, target, child_count, key)
