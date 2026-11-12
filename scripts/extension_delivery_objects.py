"""Build-time readers for bounded delivery indexes. Integrity alone grants no authority."""

from __future__ import annotations

import hashlib
from typing import Any

from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import (
    ObjectStore as ObjectStore,
)
from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import (
    encoded as encoded,
)
from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import (
    validate_reference as validate_reference,
)
from codex_plugin_scanner.guard.catalog_delivery.object_native import sessioned
from codex_plugin_scanner.guard.catalog_delivery.pack_store import MAX_OBJECT_BYTES, PackReader


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


@sessioned
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
