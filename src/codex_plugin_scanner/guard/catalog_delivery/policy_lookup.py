"""Integrity-bound policy availability lookup; never activates an extension."""

from __future__ import annotations

import hashlib

from .containers import location
from .metadata_objects import read_index_page, validate_reference
from .pack_archives import MAX_ARCHIVE_BYTES, MAX_PARTS
from .pack_store import MAX_OBJECT_BYTES, digest


def validate_record(record, identity, manifest):
    fields = {
        "schema",
        "extension_id",
        "manifest",
        "catalog_metadata",
        "archives",
        "dependencies",
        "related_interfaces",
        "required",
        "activation",
        "trust_class",
    }
    if (
        not isinstance(record, dict)
        or set(record) != fields
        or record.get("schema") != "guard.policy-delivery.v2"
        or record.get("extension_id") != identity
        or record.get("manifest") != manifest
    ):
        raise ValueError("policy delivery differs from native index")
    validate_reference(record["catalog_metadata"])
    if "location" not in record["catalog_metadata"]:
        raise ValueError("policy catalog metadata has no location")
    archives = record["archives"]
    if not isinstance(archives, list) or not 0 < len(archives) <= MAX_PARTS:
        raise ValueError("policy archive count invalid")
    seen = set()
    for archive in archives:
        if (
            not isinstance(archive, dict)
            or set(archive) != {"sha256", "length", "location"}
            or not digest(archive.get("sha256"))
            or type(archive["length"]) is not int
            or not 0 < archive["length"] <= MAX_ARCHIVE_BYTES
            or archive["sha256"] in seen
        ):
            raise ValueError("policy archive reference invalid")
        location(archive["location"], archive["sha256"], "pack")
        seen.add(archive["sha256"])
    if (
        type(record["required"]) is not bool
        or record["activation"] not in ("opt-in", "default-on")
        or record["trust_class"] not in ("external", "trusted-library", "first-party")
    ):
        raise ValueError("policy availability metadata invalid")
    for field in ("dependencies", "related_interfaces"):
        values = record[field]
        if (
            not isinstance(values, list)
            or any(not isinstance(item, str) or not item.isascii() or not 0 < len(item) <= 256 for item in values)
            or len(set(values)) != len(values)
        ):
            raise ValueError("policy interface metadata invalid")
    # These fields describe availability. Native admission must compare them to
    # the compiled payload before any controls or dependency activation change.
    return record


def read_transport_page(store, transport, expected, count, prefix):
    validate_reference(transport)
    if transport["kind"] != "data" or transport["expanded_length"] > MAX_OBJECT_BYTES:
        raise ValueError("policy transport page exceeds byte limit")
    wrapper = store.json(transport)
    if not isinstance(wrapper, dict) or wrapper.get("schema") != "guard.policy-transport.v2":
        raise ValueError("policy transport schema invalid")
    native = wrapper.get("native")
    if not isinstance(native, dict) or {key: value for key, value in native.items() if key != "location"} != expected:
        raise ValueError("policy transport does not match native root")
    page = read_index_page(store, native, count, prefix)
    if wrapper.get("kind") != page["kind"]:
        raise ValueError("policy transport kind differs")
    if page["kind"] == "leaf":
        rows = wrapper.get("records")
        if (
            set(wrapper) != {"schema", "kind", "native", "records"}
            or not isinstance(rows, list)
            or any(not isinstance(row, list) or len(row) != 2 for row in rows)
            or [row[0] for row in rows] != [row[0] for row in page["entries"]]
        ):
            raise ValueError("policy transport leaf is incomplete")
        targets = [row[1] for row in rows]
    else:
        rows = wrapper.get("children")
        if (
            set(wrapper) != {"schema", "kind", "native", "children"}
            or not isinstance(rows, list)
            or any(not isinstance(row, list) or len(row) != 3 for row in rows)
            or [row[:2] for row in rows] != [row[:2] for row in page["children"]]
        ):
            raise ValueError("policy transport branch is incomplete")
        targets = [row[2] for row in rows]
    for target in targets:
        validate_reference(target)
        if "location" not in target:
            raise ValueError("policy transport child has no location")
    return wrapper, page


def lookup(store, native_root, transport, identity, *, expected_reference=None):
    """Caller supplies one authenticated root; this checks its byte proofs only."""
    if not isinstance(identity, str) or not identity.isascii() or not 0 < len(identity) <= 256:
        raise ValueError("policy lookup identity invalid")
    if (
        not isinstance(native_root, dict)
        or native_root.get("schema") != "guard.command-pack-release.v1"
        or not digest(native_root.get("engine"))
        or type(native_root.get("extensions")) is not int
        or native_root["extensions"] <= 0
    ):
        raise ValueError("native policy root invalid")
    expected = native_root["index"]
    count = native_root["extensions"]
    prefix = ""
    hashed = hashlib.sha256(identity.encode()).hexdigest()
    for _ in range(65):
        wrapper, page = read_transport_page(store, transport, expected, count, prefix)
        if page["kind"] == "leaf":
            target = next((row for row in page["entries"] if row[0] == identity), None)
            if target is None:
                return None
            reference = next(row[1] for row in wrapper["records"] if row[0] == identity)
            if expected_reference is not None and reference != expected_reference:
                raise ValueError("default policy reference differs from authenticated transport")
            return validate_record(store.json(reference), identity, target[1])
        selected = next((index for index, row in enumerate(page["children"]) if hashed.startswith(row[0])), None)
        if selected is None:
            return None
        prefix, count, expected = page["children"][selected]
        transport = wrapper["children"][selected][2]
    raise ValueError("policy transport depth invalid")
