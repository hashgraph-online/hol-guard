"""Deterministic bounded pack transfer archives with no activation effect."""

from __future__ import annotations

import hashlib
import io
import re
import stat
import struct
import zipfile
from pathlib import Path
from typing import Any

from .pack_store import MAX_OBJECT_BYTES, PackReader, publish_object, read_object

MAX_FILES = 2048
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_PARTS = 64
MEMBER = re.compile(r"[0-9a-f]{64}\.json")


def pack_objects(reader: PackReader, manifest_ref: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
    """Collect only the objects referenced by one policy pack."""
    manifest = reader.json(manifest_ref)
    if manifest.get("schema") != "guard.command-policy-pack.v1":
        raise ValueError("policy pack manifest is invalid")
    program = reader.json(manifest["program"])
    for reference in program["nodes"].values():
        reader.json(reference)
    for field in ("catalog", "descriptors"):
        reader.json(manifest[field])
    return manifest, reader.reads.copy()


def archive_bytes(objects: Path, identities: list[str]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for identity in identities:
            name = identity + ".json"
            if MEMBER.fullmatch(name) is None:
                raise ValueError("pack archive object name invalid")
            data = read_object(objects / name)
            if hashlib.sha256(data).hexdigest() != identity:
                raise ValueError("pack archive object integrity invalid")
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
    result = output.getvalue()
    if not 0 < len(result) <= MAX_ARCHIVE_BYTES:
        raise ValueError("pack archive exceeds byte limit")
    return result


def parts(objects: Path, identities: set[str]):
    current = []
    size = 22
    count = 0
    for identity in sorted(identities):
        data = read_object(objects / f"{identity}.json")
        # Stored members have no expansion or deflate overhead. Reserve more
        # than both ZIP headers, filename copies and the end-of-directory row.
        required = len(data) + 256
        if current and (len(current) == MAX_FILES or size + required > MAX_ARCHIVE_BYTES):
            count += 1
            if count > MAX_PARTS:
                raise ValueError("pack needs too many archive parts")
            yield archive_bytes(objects, current)
            current, size = [], 22
        current.append(identity)
        size += required
    if current:
        if count + 1 > MAX_PARTS:
            raise ValueError("pack needs too many archive parts")
        yield archive_bytes(objects, current)


def ingest(data: bytes, expected_sha: str, expected_length: int, destination: Path) -> int:
    """Store verified bytes only. Caller must authenticate and pin the root."""
    if type(expected_length) is not int or not 0 < expected_length <= MAX_ARCHIVE_BYTES:
        raise ValueError("pack transfer length invalid")
    if len(data) != expected_length or hashlib.sha256(data).hexdigest() != expected_sha:
        raise ValueError("pack transfer integrity invalid")
    # This format deliberately excludes ZIP64, comments and extra fields.
    # Bound central-directory allocation before the standard ZIP parser opens it.
    if len(data) < 22 or data[-22:-18] != b"PK\x05\x06":
        raise ValueError("pack archive directory invalid")
    _, disk, central_disk, count, total, size, offset, comment = struct.unpack("<4s4H2LH", data[-22:])
    if (
        disk
        or central_disk
        or count != total
        or not 0 < total <= MAX_FILES
        or comment
        or size != total * 115
        or offset + size != len(data) - 22
    ):
        raise ValueError("pack archive directory bounds invalid")
    for parent in (destination, *destination.parents):
        if parent.is_symlink():
            raise ValueError("pack object directory traverses a symlink")
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        rows = archive.infolist()
        names = [row.filename for row in rows]
        if not 0 < len(rows) <= MAX_FILES or len(set(names)) != len(names):
            raise ValueError("pack archive inventory invalid")
        if sum(row.file_size for row in rows) > MAX_ARCHIVE_BYTES:
            raise ValueError("pack archive expanded size invalid")
        for row in rows:
            if (
                MEMBER.fullmatch(row.filename) is None
                or not stat.S_ISREG(row.external_attr >> 16)
                or row.compress_type != zipfile.ZIP_STORED
                or row.flag_bits & 1
                or row.file_size != row.compress_size
                or row.extra
                or row.comment
                or not 0 < row.file_size <= MAX_OBJECT_BYTES
            ):
                raise ValueError("pack archive member invalid")
            content = archive.read(row)
            identity = row.filename.removesuffix(".json")
            if len(content) != row.file_size or hashlib.sha256(content).hexdigest() != identity:
                raise ValueError("pack archive object integrity invalid")
            # Failed later members can leave unreferenced immutable objects.
            # Only complete native admission may commit an activation snapshot.
            publish_object(destination, identity, content)
    return len(rows)
