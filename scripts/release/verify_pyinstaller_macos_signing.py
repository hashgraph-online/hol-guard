#!/usr/bin/env python3
"""Verify that Mach-O binaries embedded in a PyInstaller onefile archive share one Apple Team ID."""

from __future__ import annotations

import argparse
import os
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path

COOKIE_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
COOKIE_FORMAT = "!8sIIII64s"
COOKIE_LENGTH = struct.calcsize(COOKIE_FORMAT)
TOC_FORMAT = "!IIIIBc"
TOC_HEADER_LENGTH = struct.calcsize(TOC_FORMAT)
BINARY_TYPE = "b"
MACHO_MAGICS = {
    b"\xce\xfa\xed\xfe",  # MH_MAGIC
    b"\xcf\xfa\xed\xfe",  # MH_MAGIC_64
    b"\xfe\xed\xfa\xce",  # MH_CIGAM
    b"\xfe\xed\xfa\xcf",  # MH_CIGAM_64
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC
    b"\xca\xfe\xba\xbf",  # FAT_MAGIC_64
    b"\xbe\xba\xfe\xca",  # FAT_CIGAM
    b"\xbf\xba\xfe\xca",  # FAT_CIGAM_64
}


def _find_cookie(handle) -> int:
    handle.seek(0, os.SEEK_END)
    end = handle.tell()
    chunk_size = 8192
    while end >= len(COOKIE_MAGIC):
        start = max(end - chunk_size, 0)
        handle.seek(start)
        chunk = handle.read(end - start)
        pos = chunk.rfind(COOKIE_MAGIC)
        if pos >= 0:
            return start + pos
        end = start + len(COOKIE_MAGIC) - 1
    raise ValueError("PyInstaller CArchive cookie was not found")


def _archive_layout(binary: Path) -> tuple[int, str, list[tuple[str, int, int, bool, str]]]:
    with binary.open("rb") as handle:
        cookie_offset = _find_cookie(handle)
        handle.seek(cookie_offset)
        cookie = handle.read(COOKIE_LENGTH)
        if len(cookie) != COOKIE_LENGTH:
            raise ValueError("Truncated PyInstaller CArchive cookie")
        magic, archive_length, toc_offset, toc_length, _pyvers, raw_pylib_name = struct.unpack(
            COOKIE_FORMAT, cookie
        )
        try:
            pylib_name = raw_pylib_name.rstrip(b"\0").decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("PyInstaller CArchive Python runtime name is not UTF-8") from exc
        if magic != COOKIE_MAGIC or not pylib_name:
            raise ValueError("Invalid PyInstaller CArchive cookie")

        archive_end = cookie_offset + COOKIE_LENGTH
        archive_start = archive_end - archive_length
        if archive_start < 0:
            raise ValueError("Invalid PyInstaller CArchive length")
        handle.seek(archive_start + toc_offset)
        toc = handle.read(toc_length)
        if len(toc) != toc_length:
            raise ValueError("Truncated PyInstaller CArchive TOC")

    entries: list[tuple[str, int, int, bool, str]] = []
    cursor = 0
    while cursor < len(toc):
        header = toc[cursor : cursor + TOC_HEADER_LENGTH]
        if len(header) != TOC_HEADER_LENGTH:
            raise ValueError("Truncated PyInstaller TOC header")
        entry_length, offset, length, _uncompressed, compressed, raw_typecode = struct.unpack(
            TOC_FORMAT, header
        )
        name_length = entry_length - TOC_HEADER_LENGTH
        if name_length <= 0 or cursor + entry_length > len(toc):
            raise ValueError("Invalid PyInstaller TOC entry length")
        raw_name = toc[
            cursor + TOC_HEADER_LENGTH : cursor + TOC_HEADER_LENGTH + name_length
        ]
        try:
            name = raw_name.rstrip(b"\0").decode("utf-8")
            typecode = raw_typecode.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("Invalid PyInstaller TOC text encoding") from exc
        if not name:
            raise ValueError("PyInstaller TOC entry has an empty name")
        entries.append((name, offset, length, bool(compressed), typecode))
        cursor += entry_length
    return archive_start, pylib_name, entries


def _entry_bytes(
    handle,
    archive_start: int,
    name: str,
    offset: int,
    length: int,
    compressed: bool,
) -> bytes:
    handle.seek(archive_start + offset)
    data = handle.read(length)
    if len(data) != length:
        raise ValueError(f"Truncated PyInstaller binary entry: {name}")
    return zlib.decompress(data) if compressed else data


def _team_id(path: Path) -> str:
    result = subprocess.run(
        ["codesign", "--display", "--verbose=4", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(f"Embedded Mach-O is not code signed: {path.name}: {result.stderr.strip()}")
    for line in result.stderr.splitlines():
        if line.startswith("TeamIdentifier="):
            return line.split("=", 1)[1]
    raise ValueError(f"Embedded Mach-O has no TeamIdentifier: {path.name}")


def verify(binary: Path, expected_team_id: str) -> None:
    archive_start, declared_runtime, entries = _archive_layout(binary)
    declared_entries = [entry for entry in entries if entry[0] == declared_runtime]
    if len(declared_entries) != 1:
        raise ValueError(
            f"Cookie-declared Python runtime {declared_runtime!r} must have exactly one TOC entry; "
            f"found {len(declared_entries)}"
        )
    if declared_entries[0][4] != BINARY_TYPE:
        raise ValueError(
            f"Cookie-declared Python runtime {declared_runtime!r} is not a binary TOC entry"
        )

    macho_count = 0
    declared_runtime_verified = False
    with binary.open("rb") as handle, tempfile.TemporaryDirectory(
        prefix="hol-guard-pyi-signing-"
    ) as tmp:
        root = Path(tmp)
        for index, (name, offset, length, compressed, typecode) in enumerate(entries):
            if typecode != BINARY_TYPE:
                continue
            data = _entry_bytes(handle, archive_start, name, offset, length, compressed)
            is_macho = data[:4] in MACHO_MAGICS
            if name == declared_runtime and not is_macho:
                raise ValueError(
                    f"Cookie-declared Python runtime {declared_runtime!r} is not Mach-O"
                )
            if not is_macho:
                continue

            macho_count += 1
            extracted = root / f"{index:04d}-{Path(name).name or 'binary'}"
            extracted.write_bytes(data)
            actual_team_id = _team_id(extracted)
            if actual_team_id != expected_team_id:
                raise ValueError(
                    f"Embedded Mach-O {name!r} has TeamIdentifier={actual_team_id!r}; "
                    f"expected {expected_team_id!r}"
                )
            if name == declared_runtime:
                declared_runtime_verified = True

    if macho_count == 0:
        raise ValueError("PyInstaller archive contained no Mach-O binary entries")
    if not declared_runtime_verified:
        raise ValueError(
            f"Cookie-declared Python runtime {declared_runtime!r} was not signature-verified"
        )
    print(
        f"verified {macho_count} embedded Mach-O binaries, including declared Python runtime "
        f"{declared_runtime!r}, with TeamIdentifier={expected_team_id}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--team-id", required=True)
    args = parser.parse_args()
    if not args.binary.is_file():
        raise SystemExit(f"Binary does not exist: {args.binary}")
    if not args.team_id or any(ch.isspace() for ch in args.team_id):
        raise SystemExit("team-id must be a non-empty token")
    try:
        verify(args.binary, args.team_id)
    except (OSError, ValueError, zlib.error) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
