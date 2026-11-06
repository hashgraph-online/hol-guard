"""Build-time transfer container checks.

Publishing and regeneration run without the native runtime installed, so the
inventory and member checks they need live here. The installed runtime checks
the same containers natively on every fetch.
"""

import hashlib
import io
import re
import stat
import struct
import zipfile

from codex_plugin_scanner.guard.catalog_delivery.containers import CONTAINER, location
from codex_plugin_scanner.guard.catalog_delivery.selection import DIGEST

MAX_MEMBERS = 256
METADATA_BYTES = 8 * 1024 * 1024
POLICY_BYTES = 32 * 1024 * 1024


def maximum(asset):
    match = CONTAINER.fullmatch(asset) if isinstance(asset, str) else None
    if match is None:
        raise ValueError("delivery container name invalid")
    return METADATA_BYTES if match[1] == "objects" else POLICY_BYTES


def inspect(data, asset):
    bound = maximum(asset)
    if not 22 <= len(data) <= bound or data[-22:-18] != b"PK\x05\x06":
        raise ValueError("delivery container size or terminator invalid")
    _, disk, start_disk, count_disk, count, central_size, offset, comment = struct.unpack("<4s4H2LH", data[-22:])
    if (
        disk
        or start_disk
        or count_disk != count
        or not 1 <= count <= MAX_MEMBERS
        or comment
        or central_size > count * 256
        or offset + central_size != len(data) - 22
    ):
        raise ValueError("delivery container central directory exceeds bounds")
    prefix, suffix, member_limit = (
        ("object-", ".json", 65536) if asset.startswith("objects-") else ("pack-", ".zip", POLICY_BYTES)
    )
    archive = zipfile.ZipFile(io.BytesIO(data))
    try:
        members = archive.infolist()
        names = set()
        total = 0
        for info in members:
            name = info.filename
            digest = name[len(prefix) : -len(suffix)] if name.startswith(prefix) and name.endswith(suffix) else ""
            total += info.file_size
            if (
                name in names
                or DIGEST.fullmatch(digest) is None
                or info.compress_type != zipfile.ZIP_STORED
                or info.compress_size != info.file_size
                or not 0 < info.file_size <= member_limit
                or info.flag_bits & ~0x800
                or info.extra
                or info.comment
                or not stat.S_ISREG(info.external_attr >> 16)
                or total > bound
            ):
                raise ValueError("delivery container member invalid")
            names.add(name)
        if len(members) != count:
            raise ValueError("delivery container member count differs")
        return archive, members
    except BaseException:
        archive.close()
        raise


def member(data, asset, name, length):
    archive, _ = inspect(data, asset)
    with archive:
        try:
            info = archive.getinfo(name)
        except KeyError as error:
            raise ValueError("delivery container member missing") from error
        if info.file_size != length:
            raise ValueError("delivery container member length differs")
        value = archive.read(info)
        digest = name.split("-", 1)[1].split(".", 1)[0]
        if hashlib.sha256(value).hexdigest() != digest:
            raise ValueError("delivery container member integrity invalid")
        return value


def verify_inventory(data, asset, expected):
    archive, infos = inspect(data, asset)
    with archive:
        if {info.filename for info in infos} != set(expected):
            raise ValueError("new delivery container includes unbound or missing members")
        for info in infos:
            spec = expected[info.filename]
            value = archive.read(info)
            if len(value) != spec["length"] or hashlib.sha256(value).hexdigest() != spec["sha256"]:
                raise ValueError("new delivery container member differs from authenticated reference")


def target(value, *, source_sha):
    # These checks constrain local IO paths; Root and policy admission are native.
    if not isinstance(value, dict):
        raise ValueError("installed bundle location invalid")
    name = value.get("member", value.get("asset", ""))
    match = re.fullmatch(r"(object|pack)-([0-9a-f]{64})\.(json|zip)", name) if isinstance(name, str) else None
    if match is None or match[3] != ("json" if match[1] == "object" else "zip"):
        raise ValueError("installed bundle asset invalid")
    location(value, match[2], match[1])
    if not value["tag"].startswith("extension-data-" + source_sha + "-0.0-"):
        raise ValueError("installed bundle asset source differs")
    return name, match[2], match[1]
