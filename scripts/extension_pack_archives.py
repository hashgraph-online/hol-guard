"""Maintainer pack archive tooling.

Writers are shared with the installed delivery package. ``ingest`` is build
tooling for compiler reuse only: the runtime admits received archives through
the native pack lifecycle, never through this parser.
"""

from __future__ import annotations

import hashlib
import io
import stat
import struct
import zipfile
from pathlib import Path

from codex_plugin_scanner.guard.catalog_delivery.pack_archives import (
    MAX_ARCHIVE_BYTES as MAX_ARCHIVE_BYTES,
)
from codex_plugin_scanner.guard.catalog_delivery.pack_archives import (
    MAX_FILES as MAX_FILES,
)
from codex_plugin_scanner.guard.catalog_delivery.pack_archives import (
    MAX_PARTS as MAX_PARTS,
)
from codex_plugin_scanner.guard.catalog_delivery.pack_archives import (
    MEMBER as MEMBER,
)
from codex_plugin_scanner.guard.catalog_delivery.pack_archives import (
    archive_bytes as archive_bytes,
)
from codex_plugin_scanner.guard.catalog_delivery.pack_archives import (
    pack_objects as pack_objects,
)
from codex_plugin_scanner.guard.catalog_delivery.pack_archives import (
    parts as parts,
)
from codex_plugin_scanner.guard.catalog_delivery.pack_store import MAX_OBJECT_BYTES, publish_object


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
