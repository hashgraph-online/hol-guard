"""Bounded ELF dependency evidence for immutable executable-mapping exceptions."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import struct
from pathlib import Path

from .restricted_linux_landlock import LinuxContainmentUnavailableError

_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
_PROGRAM = struct.Struct("<IIQQQQQQ")
_DYNAMIC = struct.Struct("<qQ")
_MAX_FILE_BYTES = 256 * 1024 * 1024
_MAX_MAPPING_BYTES = 1024 * 1024 * 1024
_MAX_MAPPINGS = 1024


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    # UID mappings change across the private user namespace; content does not.
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_mode)


def _elf(stream, metadata, *, library: bool, system_library: bool = False) -> tuple[str | None, tuple[str, ...]]:
    stream.seek(0)
    header = stream.read(_HEADER.size)
    if len(header) != _HEADER.size:
        raise ValueError("Truncated ELF metadata.")
    fields = _HEADER.unpack(header)
    offset, width, count = fields[5], fields[9], fields[10]
    if (
        fields[0][:7] != b"\x7fELF\x02\x01\x01"
        or fields[1] not in {2, 3}
        or fields[2] not in {62, 183}
        or fields[3] != 1
        or offset < _HEADER.size
        or width != _PROGRAM.size
        or not 0 < count <= 128
        or offset + width * count > metadata.st_size
    ):
        raise ValueError("Unsupported ELF mapping layout.")
    stream.seek(offset)
    programs = [_PROGRAM.unpack(stream.read(width)) for _ in range(count)]
    loads = [p for p in programs if p[0] == 1]
    if not loads:
        raise ValueError("ELF mapping has no load segment.")
    dynamic = [p for p in programs if p[0] == 2]
    entries = []
    if dynamic:
        if len(dynamic) != 1 or dynamic[0][5] > 65536 or dynamic[0][5] % _DYNAMIC.size:
            raise ValueError("Invalid dynamic metadata budget.")
        segment = dynamic[0]
        if segment[2] + segment[5] > metadata.st_size:
            raise ValueError("Truncated dynamic metadata.")
        stream.seek(segment[2])
        for _ in range(segment[5] // _DYNAMIC.size):
            record = _DYNAMIC.unpack(stream.read(_DYNAMIC.size))
            if record[0] == 0:
                break
            entries.append(record)
    names = [entry for entry in entries if entry[0] in {1, 14}]
    soname, dependencies = None, []
    if names:
        addresses = [value for tag, value in entries if tag == 5]
        sizes = [value for tag, value in entries if tag == 10]
        if len(addresses) != 1 or len(sizes) != 1 or not 0 < sizes[0] <= metadata.st_size:
            raise ValueError("Invalid ELF string table.")
        locations = [
            p[2] + addresses[0] - p[3] for p in loads if p[3] <= addresses[0] and addresses[0] + sizes[0] <= p[3] + p[5]
        ]
        if len(locations) != 1 or locations[0] + sizes[0] > metadata.st_size:
            raise ValueError("Ambiguous ELF string table.")
        for tag, index in names:
            if index >= sizes[0]:
                raise ValueError("Invalid ELF dependency index.")
            stream.seek(locations[0] + index)
            name_bytes = stream.read(min(257, sizes[0] - index))
            end = name_bytes.find(b"\x00")
            if end < 0:
                raise ValueError("Unbounded ELF dependency name.")
            name = name_bytes[:end].decode("ascii")
            if not name or name in {".", ".."} or any(c in name for c in "/\\\n\r"):
                raise ValueError("Unapproved ELF dependency path.")
            if tag == 14:
                if soname is not None:
                    raise ValueError("Ambiguous ELF library name.")
                soname = name
            else:
                dependencies.append(name)
    if library:
        # e_entry is nonzero in real ARM/Rust DSOs, so it is not an image-type
        # discriminator. ELF's explicit PIE flag and PT_INTERP identify programs.
        trusted_system_dso = (
            system_library and soname is not None and metadata.st_uid == 0 and metadata.st_mode & 0o022 == 0
        )
        has_interpreter = any(p[0] == 3 for p in programs)
        is_pie = any(tag == 0x6FFFFFFB and value & 0x08000000 for tag, value in entries)
        if fields[1] != 3 or is_pie or (has_interpreter and not (trusted_system_dso and soname == "libc.so.6")):
            raise ValueError("Program image is not a shared-library mapping exception.")
    return soname, tuple(dependencies)


def collect_mapping_evidence(
    *,
    images: set[Path],
    read_files: set[Path],
    runtime_roots: tuple[Path, ...],
    workspace: Path,
) -> list[dict[str, object]]:
    """Select dependency closure, not every library installed on the machine."""
    parents = sorted({path.parent for path in read_files})
    optional = [
        path
        for path in sorted(read_files - images)
        if (path.is_relative_to(workspace) or any(path.is_relative_to(root) for root in runtime_roots))
        and (re.search(r"\.so(?:\.[0-9]+)*$", path.name) or path.suffix == ".node")
    ]
    cache, total = {}, 0

    class MissingDependencyError(ValueError):
        pass

    class InvalidImageError(ValueError):
        pass

    def inspect(path):
        nonlocal total
        if path in cache:
            return cache[path]
        if len(cache) >= _MAX_MAPPINGS:
            raise ValueError("Too many executable mappings.")
        library = path not in images
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= _MAX_FILE_BYTES:
                raise ValueError("Invalid executable mapping file.")
            prefix = stream.read(4)
            if prefix == b"\x7fELF":
                system_library = any(
                    path.is_relative_to(root)
                    for root in (Path("/usr/lib"), Path("/usr/lib64"), Path("/lib"), Path("/lib64"))
                )
                try:
                    _soname, dependencies = _elf(stream, before, library=library, system_library=system_library)
                except (ValueError, struct.error, UnicodeError) as error:
                    raise InvalidImageError("Unverified executable mapping.") from error
            elif not library and prefix.startswith(b"#!"):
                dependencies = ()
            else:
                raise InvalidImageError("Unverified executable mapping.")
            total += before.st_size
            if total > _MAX_MAPPING_BYTES:
                raise ValueError("Executable mapping memory budget exceeded.")
            stream.seek(0)
            hasher = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
            digest = hasher.hexdigest()
            if _identity(before) != _identity(os.fstat(stream.fileno())):
                raise ValueError("Executable mapping changed during inspection.")
        record = {"path": str(path), "identity": list(_identity(before)), "sha256": digest}
        cache[path] = record, dependencies
        return cache[path]

    def closure(seeds):
        pending, records = list(seeds), {}
        while pending:
            path = pending.pop()
            if path in records:
                continue
            record, dependencies = inspect(path)
            records[path] = record
            for name in dependencies:
                matches = set()
                for parent in parents:
                    try:
                        candidate = (parent / name).resolve(strict=True)
                    except (OSError, RuntimeError):
                        continue
                    if candidate in read_files or candidate in images:
                        matches.add(candidate)
                if not matches:
                    raise MissingDependencyError("An executable mapping dependency is unavailable.")
                pending.extend(matches)
        return records

    try:
        records = closure(sorted(images))
    except (OSError, ValueError, struct.error, UnicodeError) as error:
        raise LinuxContainmentUnavailableError("Linux executable mapping evidence could not be verified.") from error
    for module in optional:
        try:
            component = closure([module])
        except (OSError, ValueError, struct.error, UnicodeError):
            # Unverifiable optional modules remain noexec, not execution grants.
            continue
        records.update(component)
    return [records[path] for path in sorted(records)]
