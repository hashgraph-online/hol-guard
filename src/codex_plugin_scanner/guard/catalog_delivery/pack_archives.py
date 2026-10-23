"""Deterministic bounded pack transfer archives with no activation effect.

The runtime admits received archives only through the native pack lifecycle
(``cache_io.stage_archive``); this module only writes them.
"""

from __future__ import annotations

import hashlib
import io
import re
import stat
import zipfile
from pathlib import Path
from typing import Any

from .object_native import sessioned
from .pack_store import PackReader, read_object

MAX_FILES = 2048
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_PARTS = 64
MEMBER = re.compile(r"[0-9a-f]{64}\.json")


@sessioned
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
