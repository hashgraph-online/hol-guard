"""Resolve only the exact system ELF loader required by an approved image."""

from __future__ import annotations

import os
import stat
import struct
from pathlib import Path

from .restricted_linux_landlock import LinuxContainmentUnavailableError

_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
_PROGRAM = struct.Struct("<IIQQQQQQ")
_LOADERS = {
    62: frozenset({"/lib64/ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"}),
    183: frozenset({"/lib/ld-linux-aarch64.so.1", "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"}),
}


def resolve_linux_elf_loader(executable: Path) -> Path | None:
    """Parse bounded ELF metadata, never invoke ldd or a repository executable."""
    try:
        descriptor = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("nonregular image")
            header = stream.read(_HEADER.size)
            if len(header) != _HEADER.size:
                raise ValueError("truncated image")
            fields = _HEADER.unpack(header)
            identity, kind, machine, version = fields[:4]
            offset, entry_size, count = fields[5], fields[9], fields[10]
            if (
                identity[:7] != b"\x7fELF\x02\x01\x01"
                or kind not in {2, 3}
                or machine not in _LOADERS
                or version != 1
                or entry_size != _PROGRAM.size
                or not 0 < count <= 128
                or offset < _HEADER.size
                or offset + entry_size * count > metadata.st_size
            ):
                raise ValueError("unsupported ELF layout")
            stream.seek(offset)
            programs = [_PROGRAM.unpack(stream.read(entry_size)) for _ in range(count)]
            if not any(program[0] == 1 for program in programs):
                raise ValueError("missing load segment")
            interpreters = [program for program in programs if program[0] == 3]
            if not interpreters:
                return None
            if len(interpreters) != 1:
                raise ValueError("ambiguous interpreter")
            interpreter = interpreters[0]
            start, size = interpreter[2], interpreter[5]
            if not 1 < size <= 4096 or start + size > metadata.st_size:
                raise ValueError("invalid interpreter bounds")
            stream.seek(start)
            raw = stream.read(size)
            if not raw.endswith(b"\x00") or b"\x00" in raw[:-1]:
                raise ValueError("invalid interpreter encoding")
            name = raw[:-1].decode("ascii")
            if name not in _LOADERS[machine]:
                raise ValueError("unapproved interpreter")
        loader = Path(name).resolve(strict=True)
        roots = {Path("/lib").resolve(), Path("/lib64").resolve(), Path("/usr/lib")}
        if not any(loader.is_relative_to(root) for root in roots):
            raise ValueError("external interpreter")
        descriptor = os.open(loader, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError("untrusted interpreter")
            header = stream.read(_HEADER.size)
            if len(header) != _HEADER.size:
                raise ValueError("truncated interpreter")
            fields = _HEADER.unpack(header)
            if fields[0][:7] != b"\x7fELF\x02\x01\x01" or fields[1] != 3 or fields[2] != machine:
                raise ValueError("unexpected interpreter image")
        return loader
    except (OSError, ValueError, struct.error) as error:
        raise LinuxContainmentUnavailableError("The exact approved ELF loader could not be verified.") from error
