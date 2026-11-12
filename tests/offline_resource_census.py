"""Read-only publication census, not a complete native cache or tmpfs bound.

Models the offline=False fixture: standalone packs and object containers expand
once; their members (including ZIP-looking bytes) are opaque object payloads.
Counts every planned asset and each declared ZIP's members. Duplicate records and
parent directories deliberately overcount. Reserves are explicit caller inputs;
their adequacy and native-created files/sets/leases/transients remain unproved.
Only ordinary ZIP32 stored/deflate archives without descriptors/extras are accepted.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import zipfile
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

CHUNK = 65536
METADATA = ("asset-plan.jsonl", "installed-bundle-assets.v1.json")
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class Limits:
    plan_rows: int = 4096
    asset_bytes: int = 64 * 1024 * 1024
    total_asset_bytes: int = 512 * 1024 * 1024
    zip_members: int = 4096
    total_zip_members: int = 100000
    zip_directory_bytes: int = 8 * 1024 * 1024
    member_bytes: int = 64 * 1024 * 1024
    expanded_bytes: int = 2 * 1024 * 1024 * 1024


def _integer(value, name, *, positive=False):
    if type(value) is not int or value < int(positive):
        raise ValueError(f"invalid {name}")
    return value


def _json(data):
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError("duplicate JSON key")
            result[name] = value
        return result

    return json.loads(data, object_pairs_hook=pairs)


def _name(value):
    if not isinstance(value, str) or NAME.fullmatch(value) is None or value in (".", ".."):
        raise ValueError("unsafe local asset name")
    return value


@contextmanager
def _file(root, parts):
    """Open beneath a pinned root, refusing symlinks in every relative component."""
    directory = os.dup(root)
    try:
        for part in parts[:-1]:
            child = os.open(_name(part), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(_name(parts[-1]), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("asset is not a regular file")
            yield stream
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise ValueError("input changed during census")
    finally:
        os.close(directory)


def _read(stream, size):
    value = stream.read(size)
    if len(value) != size:
        raise ValueError("truncated input")
    return value


def _metadata(root, limits):
    records, plan_digest, size = [], hashlib.sha256(), 0
    with _file(root, (METADATA[0],)) as stream:
        while line := stream.readline(2049):
            if len(line) > 2048 or not line.endswith(b"\n") or len(records) >= limits.plan_rows:
                raise ValueError("asset plan exceeds row bounds")
            plan_digest.update(line)
            size += len(line)
            row = _json(line)
            if not isinstance(row, dict) or set(row) != {"location", "sha256", "length"}:
                raise ValueError("invalid asset record")
            location = row["location"]
            if not isinstance(location, dict) or set(location) != {"tag", "asset"}:
                raise ValueError("invalid local asset location")
            parts = (_name(location["tag"]), _name(location["asset"]))
            if not isinstance(row["sha256"], str) or DIGEST.fullmatch(row["sha256"]) is None:
                raise ValueError("invalid asset digest")
            length = _integer(row["length"], "asset length", positive=True)
            if length > limits.asset_bytes:
                raise ValueError("asset exceeds byte bound")
            records.append((parts, row["sha256"], length))
    with _file(root, (METADATA[1],)) as stream:
        data = stream.read(65537)
        if len(data) > 65536:
            raise ValueError("publication metadata exceeds bound")
        manifest = _json(data)
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema", "source_sha", "root_sha256", "asset_count"}
        or manifest["schema"] != "guard.installed-bundle-assets.v1"
        or not isinstance(manifest["source_sha"], str)
        or re.fullmatch(r"[0-9a-f]{40}", manifest["source_sha"]) is None
        or not isinstance(manifest["root_sha256"], str)
        or DIGEST.fullmatch(manifest["root_sha256"]) is None
        or type(manifest["asset_count"]) is not int
        or manifest["asset_count"] != len(records)
        or not records
    ):
        raise ValueError("publication metadata does not match plan")
    return records, manifest, (size, len(data)), plan_digest.hexdigest()


def _inventory(root, records):
    expected = {parts for parts, _, _ in records}
    seen = set()
    tags = {parts[0] for parts in expected}
    with os.scandir(root) as entries:
        for index, entry in enumerate(entries):
            if index >= len(tags) + len(METADATA):
                raise ValueError("unlisted publication entry")
            if entry.name in METADATA and entry.is_file(follow_symlinks=False):
                continue
            if entry.name not in tags or not entry.is_dir(follow_symlinks=False):
                raise ValueError("unlisted or unsafe publication entry")
            directory = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            try:
                with os.scandir(directory) as assets:
                    for child in assets:
                        key = (entry.name, child.name)
                        if key not in expected or not child.is_file(follow_symlinks=False):
                            raise ValueError("unlisted or unsafe asset")
                        seen.add(key)
            finally:
                os.close(directory)
    if seen != expected:
        raise ValueError("publication inventory differs from plan")


def _payload(stream, info, limit):
    """Verify actual output length/CRC, including understated ZIP size claims."""
    remaining, count, crc = info.compress_size, 0, 0
    decoder = zlib.decompressobj(-15) if info.compress_type == zipfile.ZIP_DEFLATED else None

    def consume(data):
        nonlocal count, crc
        count += len(data)
        if count > min(info.file_size, limit):
            raise ValueError("ZIP payload exceeds declared or configured bound")
        crc = zlib.crc32(data, crc)

    while remaining:
        data = _read(stream, min(CHUNK, remaining))
        remaining -= len(data)
        if decoder is None:
            consume(data)
        else:
            while data:
                consume(decoder.decompress(data, CHUNK))
                data = decoder.unconsumed_tail
                if decoder.unused_data:
                    raise ValueError("trailing compressed data")
    if decoder is not None:
        while data := decoder.decompress(b"", CHUNK):
            consume(data)
        if not decoder.eof:
            raise ValueError("truncated deflate stream")
    if count != info.file_size or crc != info.CRC:
        raise ValueError("ZIP payload length or CRC mismatch")


def _zip(stream, size, limits, rounded):
    if size < 22:
        raise ValueError("truncated ZIP")
    stream.seek(size - 22)
    signature, disk, start, disk_count, count, directory_size, offset, comment = struct.unpack(
        "<4s4H2LH", _read(stream, 22)
    )
    if (
        signature != b"PK\x05\x06"
        or disk
        or start
        or disk_count != count
        or comment
        or not 0 < count <= limits.zip_members
        or count == 65535
        or directory_size > limits.zip_directory_bytes
        or offset + directory_size != size - 22
    ):
        raise ValueError("unsupported or unbounded ZIP directory")
    files = expanded = pages = previous = 0
    directories = 1  # A separate expansion root; repeated parents deliberately overcount.
    with zipfile.ZipFile(stream) as archive:
        members = archive.infolist()
        if len(members) != count:
            raise ValueError("ZIP member count mismatch")
        for info in sorted(members, key=lambda member: member.header_offset):
            name = info.orig_filename
            parts = name.removesuffix("/").split("/")
            for part in parts:
                _name(part)
            mode = stat.S_IFMT(info.external_attr >> 16)
            if (
                info.filename != name
                or info.flag_bits & ~0x800
                or info.extra
                or info.comment
                or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                or mode not in (0, stat.S_IFREG, stat.S_IFDIR)
                or (mode == stat.S_IFDIR and not info.is_dir())
                or info.header_offset != previous
            ):
                raise ValueError("unsupported or unsafe ZIP member")
            if info.file_size > limits.member_bytes:
                raise ValueError("ZIP member exceeds byte bound")
            stream.seek(info.header_offset)
            header = struct.unpack("<4s5H3I2H", _read(stream, 30))
            sig, _, flags, method, _, _, crc, compressed, length, name_size, extra_size = header
            if (
                sig != b"PK\x03\x04"
                or flags != info.flag_bits
                or method != info.compress_type
                or (crc, compressed, length) != (info.CRC, info.compress_size, info.file_size)
                or extra_size
                or name_size > 2048
            ):
                raise ValueError("ZIP local header mismatch")
            raw_name = _read(stream, name_size)
            if raw_name.decode("utf-8" if flags & 0x800 else "cp437") != name:
                raise ValueError("ZIP filename mismatch")
            previous = stream.tell() + compressed
            if previous > offset:
                raise ValueError("overlapping ZIP records")
            if info.is_dir():
                if length or compressed or crc or mode == stat.S_IFREG:
                    raise ValueError("nonempty or ambiguous ZIP directory")
                directories += len(parts)
            else:
                _payload(stream, info, limits.member_bytes)
                files += 1
                directories += len(parts) - 1
                expanded += length
                pages += rounded(length)
                if expanded > limits.expanded_bytes:
                    raise ValueError("ZIP expansion exceeds total bound")
        if previous != offset:
            raise ValueError("unaccounted ZIP data")
    return files, directories, expanded, pages, count


def census(
    publication: Path,
    *,
    page_size: int,
    metadata_reserve_bytes: int,
    transient_reserve_bytes: int,
    standalone_fixture: bool = False,
    limits: Limits | None = None,
) -> dict:
    """Count an existing publication; never extract, fetch, invoke native code or write."""
    if limits is None:
        limits = Limits()
    _integer(page_size, "page size", positive=True)
    if page_size & (page_size - 1):
        raise ValueError("page size must be a power of two")
    for name, value in vars(limits).items():
        _integer(value, name, positive=True)
    _integer(metadata_reserve_bytes, "metadata reserve")
    _integer(transient_reserve_bytes, "transient reserve")

    def rounded(value):
        return (value + page_size - 1) // page_size * page_size

    if publication.is_symlink():
        raise ValueError("publication root is a symlink")
    root = os.open(publication.resolve(strict=True), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        records, manifest, metadata_sizes, plan_digest = _metadata(root, limits)
        _inventory(root, records)
        asset_bytes = asset_pages = files = expanded = pages = members = zip_directories = 0
        directories = 1 + len(records)  # Publication root plus each asset's parent.
        for parts, digest, length in records:
            if (
                standalone_fixture
                and re.fullmatch(
                    r"(?:object-[0-9a-f]{64}\.json|pack-[0-9a-f]{64}\.zip|objects-[0-9]{6}\.zip)", parts[-1]
                )
                is None
            ):
                raise ValueError("asset is outside standalone fixture model")
            asset_bytes += length
            if asset_bytes > limits.total_asset_bytes:
                raise ValueError("publication exceeds total asset bound")
            asset_pages += rounded(length)
            with _file(root, parts) as stream:
                if os.fstat(stream.fileno()).st_size != length:
                    raise ValueError("asset length mismatch")
                actual = hashlib.sha256()
                for _ in range((length + CHUNK - 1) // CHUNK):
                    actual.update(_read(stream, min(CHUNK, length - stream.tell())))
                if actual.hexdigest() != digest:
                    raise ValueError("asset hash mismatch")
                if parts[-1].endswith(".zip"):
                    stream.seek(0)
                    f, d, b, p, n = _zip(stream, length, limits, rounded)
                    files += f
                    directories += d
                    zip_directories += d
                    expanded += b
                    pages += p
                    members += n
                    if expanded > limits.expanded_bytes or members > limits.total_zip_members:
                        raise ValueError("publication expansion exceeds total bound")
        _inventory(root, records)
        metadata_pages = sum(rounded(size) for size in metadata_sizes)
        counted = asset_pages + metadata_pages + pages
        return {
            "publication_source_sha": manifest["source_sha"],
            "publication_root_sha256": manifest["root_sha256"],
            "model": "standalone-pack-assets/one-level-opaque-members",
            "asset_plan_sha256": plan_digest,
            "page_size": page_size,
            "publication_files": len(records),
            "asset_bytes": asset_bytes,
            "asset_page_bytes": asset_pages,
            "metadata_files": len(METADATA),
            "metadata_file_bytes": sum(metadata_sizes),
            "metadata_file_page_bytes": metadata_pages,
            "zip_member_files": files,
            "zip_expanded_bytes": expanded,
            "zip_expanded_page_bytes": pages,
            "zip_expanded_directory_count": zip_directories,
            "counted_file_count": len(records) + len(METADATA) + files,
            "conservative_directory_count": directories,
            "counted_data_page_bytes": counted,
            "metadata_reserve_bytes": metadata_reserve_bytes,
            "transient_reserve_bytes": transient_reserve_bytes,
            "data_plus_reserve_page_bytes": counted
            + rounded(metadata_reserve_bytes)
            + rounded(transient_reserve_bytes),
            "complete_native_tree_bound": False,
            "reserve_adequacy_proved": False,
            "not_censused": [
                "native-derived/compiled selection sets",
                "root/lease/control and temporary files",
                "additional copies and simultaneously retained fixture trees",
                "SQLite isolated homes",
            ],
        }
    finally:
        os.close(root)
