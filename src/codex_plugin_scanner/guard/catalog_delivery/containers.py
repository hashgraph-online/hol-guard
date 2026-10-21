"""Bounded transfer containers; each selected member retains its own digest."""

from __future__ import annotations

import hashlib
import io
import re
import stat
import struct
import zipfile

from .selection import DIGEST

TAG = re.compile(r"extension-data-[0-9a-f]{40}-[0-9]{1,20}\.[0-9]{1,10}-[0-9]{6}")
CONTAINER = re.compile(r"(objects|packs)-[0-9]{6}\.zip")
MAX_MEMBERS = 256
METADATA_BYTES = 8 * 1024 * 1024
POLICY_BYTES = 32 * 1024 * 1024


def location(value, digest, kind):
    suffix = ".json" if kind == "object" else ".zip"
    if (
        kind not in {"object", "pack"}
        or not isinstance(digest, str)
        or DIGEST.fullmatch(digest) is None
        or not isinstance(value, dict)
        or set(value) not in ({"tag", "asset"}, {"tag", "asset", "member"})
        or not isinstance(value["tag"], str)
        or TAG.fullmatch(value["tag"]) is None
    ):
        raise ValueError("delivery asset location invalid")
    member = kind + "-" + digest + suffix
    if "member" not in value:
        if value["asset"] != member:
            raise ValueError("delivery asset identity invalid")
    elif (
        value["member"] != member
        or not isinstance(value["asset"], str)
        or CONTAINER.fullmatch(value["asset"]) is None
        or not value["asset"].startswith("objects-" if kind == "object" else "packs-")
    ):
        raise ValueError("delivery container location invalid")
    return value


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
