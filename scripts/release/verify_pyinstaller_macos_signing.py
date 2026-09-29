#!/usr/bin/env python3
"""Verify that Mach-O binaries embedded in a PyInstaller onefile archive share one Apple Team ID."""

from __future__ import annotations

import argparse
import os
import re
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path, PurePosixPath

COOKIE_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
COOKIE_FORMAT = "!8sIIII64s"
COOKIE_LENGTH = struct.calcsize(COOKIE_FORMAT)
TOC_FORMAT = "!IIIIBc"
TOC_HEADER_LENGTH = struct.calcsize(TOC_FORMAT)
BINARY_TYPE = "b"
SYMLINK_TYPE = "n"
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


def _archive_toc(
    binary: Path,
) -> tuple[int, int, int, str, list[tuple[str, int, int, int, bool, str]]]:
    with binary.open("rb") as handle:
        cookie_offset = _find_cookie(handle)
        handle.seek(cookie_offset)
        cookie = handle.read(COOKIE_LENGTH)
        if len(cookie) != COOKIE_LENGTH:
            raise ValueError("Truncated PyInstaller CArchive cookie")
        magic, archive_length, toc_offset, toc_length, pyvers, raw_pylib_name = struct.unpack(COOKIE_FORMAT, cookie)
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

    entries: list[tuple[str, int, int, int, bool, str]] = []
    cursor = 0
    while cursor < len(toc):
        header = toc[cursor : cursor + TOC_HEADER_LENGTH]
        if len(header) != TOC_HEADER_LENGTH:
            raise ValueError("Truncated PyInstaller TOC header")
        entry_length, offset, length, uncompressed, compressed, raw_typecode = struct.unpack(TOC_FORMAT, header)
        name_length = entry_length - TOC_HEADER_LENGTH
        if name_length <= 0 or cursor + entry_length > len(toc):
            raise ValueError("Invalid PyInstaller TOC entry length")
        raw_name = toc[cursor + TOC_HEADER_LENGTH : cursor + TOC_HEADER_LENGTH + name_length]
        try:
            name = raw_name.rstrip(b"\0").decode("utf-8")
            typecode = raw_typecode.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("Invalid PyInstaller TOC text encoding") from exc
        if not name:
            raise ValueError("PyInstaller TOC entry has an empty name")
        if offset < 0 or length < 0 or uncompressed < 0:
            raise ValueError(f"PyInstaller TOC entry {name!r} has an invalid range")
        if offset > toc_offset or length > toc_offset - offset:
            raise ValueError(f"PyInstaller TOC entry {name!r} overlaps the archive TOC")
        entries.append((name, offset, length, uncompressed, bool(compressed), typecode))
        cursor += entry_length
    return archive_start, cookie_offset, pyvers, pylib_name, entries


def _archive_layout(binary: Path) -> tuple[int, str, list[tuple[str, int, int, bool, str]]]:
    archive_start, _cookie_offset, _pyvers, pylib_name, entries = _archive_toc(binary)
    return (
        archive_start,
        pylib_name,
        [
            (name, offset, length, compressed, typecode)
            for name, offset, length, _uncompressed, compressed, typecode in entries
        ],
    )


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


def _signature_info(path: Path) -> tuple[str, int]:
    result = subprocess.run(
        ["codesign", "--display", "--verbose=4", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(f"Mach-O is not code signed: {path.name}: {result.stderr.strip()}")
    team_id: str | None = None
    flags = 0
    for line in result.stderr.splitlines():
        if line.startswith("TeamIdentifier="):
            team_id = line.split("=", 1)[1]
        flags_match = re.match(r"CodeDirectory\b.*?\bflags=0x([0-9a-fA-F]+)", line)
        if flags_match is not None:
            flags = int(flags_match.group(1), 16)
    if team_id is None:
        raise ValueError(f"Mach-O has no TeamIdentifier: {path.name}")
    return team_id, flags


_CS_RUNTIME_FLAG = 0x10000


def _team_id(path: Path) -> str:
    team_id, _flags = _signature_info(path)
    return team_id


def _unique_entry(
    entries: list[tuple[str, int, int, bool, str]],
    name: str,
    *,
    role: str,
) -> tuple[str, int, int, bool, str]:
    matches = [entry for entry in entries if entry[0] == name]
    if len(matches) != 1:
        raise ValueError(f"{role} {name!r} must have exactly one TOC entry; found {len(matches)}")
    return matches[0]


def _archive_relative_name(name: str, *, role: str) -> str:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{role} {name!r} must be archive-relative")
    normalized = path.as_posix()
    if normalized in {"", ".", ".."}:
        raise ValueError(f"{role} {name!r} must be archive-relative")
    return normalized


def _normalized_symlink_target(source_name: str, target: str) -> str:
    source_name = _archive_relative_name(source_name, role="PyInstaller archive symlink source")
    target_path = PurePosixPath(target)
    if target_path.is_absolute():
        raise ValueError(f"PyInstaller archive symlink {source_name!r} has an absolute target")

    parts = list(PurePosixPath(source_name).parent.parts)
    for part in target_path.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                raise ValueError(f"PyInstaller archive symlink {source_name!r} escapes the archive root")
            parts.pop()
            continue
        parts.append(part)
    if not parts:
        raise ValueError(f"PyInstaller archive symlink {source_name!r} has an empty target")
    normalized = PurePosixPath(*parts).as_posix()
    return _archive_relative_name(normalized, role="PyInstaller archive symlink target")


def _resolve_declared_runtime(
    handle,
    archive_start: int,
    declared_runtime: str,
    entries: list[tuple[str, int, int, bool, str]],
) -> tuple[str, int, int, bool, str]:
    """Resolve PyInstaller's cookie runtime through archive-local symlinks to a binary entry."""

    current_name = _archive_relative_name(
        declared_runtime,
        role="Cookie-declared Python runtime",
    )
    seen: set[str] = set()
    for _ in range(8):
        if current_name in seen:
            raise ValueError(f"Cookie-declared Python runtime {declared_runtime!r} resolves through a symlink cycle")
        seen.add(current_name)
        entry = _unique_entry(entries, current_name, role="Cookie-declared Python runtime target")
        name, offset, length, compressed, typecode = entry
        if typecode == BINARY_TYPE:
            return entry
        if typecode != SYMLINK_TYPE:
            raise ValueError(
                f"Cookie-declared Python runtime {declared_runtime!r} resolves to unsupported TOC type {typecode!r}"
            )

        data = _entry_bytes(handle, archive_start, name, offset, length, compressed)
        if not data.endswith(b"\0") or b"\0" in data[:-1]:
            raise ValueError(f"PyInstaller archive symlink {name!r} has invalid target encoding")
        try:
            target = data[:-1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"PyInstaller archive symlink {name!r} target is not UTF-8") from exc
        if not target:
            raise ValueError(f"PyInstaller archive symlink {name!r} has an empty target")
        current_name = _normalized_symlink_target(name, target)

    raise ValueError(f"Cookie-declared Python runtime {declared_runtime!r} exceeds symlink resolution depth")


def verify(binary: Path, expected_team_id: str) -> None:
    archive_start, declared_runtime, entries = _archive_layout(binary)

    macho_count = 0
    declared_runtime_verified = False
    with binary.open("rb") as handle, tempfile.TemporaryDirectory(prefix="hol-guard-pyi-signing-") as tmp:
        runtime_entry = _resolve_declared_runtime(handle, archive_start, declared_runtime, entries)
        runtime_name = runtime_entry[0]
        root = Path(tmp)
        for index, (name, offset, length, compressed, typecode) in enumerate(entries):
            if typecode != BINARY_TYPE:
                continue
            data = _entry_bytes(handle, archive_start, name, offset, length, compressed)
            is_macho = data[:4] in MACHO_MAGICS
            if name == runtime_name and not is_macho:
                raise ValueError(
                    f"Cookie-declared Python runtime {declared_runtime!r} resolves to non-Mach-O binary {name!r}"
                )
            if not is_macho:
                continue

            macho_count += 1
            extracted = root / f"{index:04d}-{Path(name).name or 'binary'}"
            extracted.write_bytes(data)
            actual_team_id = _team_id(extracted)
            if actual_team_id != expected_team_id:
                raise ValueError(
                    f"Embedded Mach-O {name!r} has TeamIdentifier={actual_team_id!r}; expected {expected_team_id!r}"
                )
            if name == runtime_name:
                declared_runtime_verified = True

    if macho_count == 0:
        raise ValueError("PyInstaller archive contained no Mach-O binary entries")
    if not declared_runtime_verified:
        raise ValueError(f"Cookie-declared Python runtime {declared_runtime!r} was not signature-verified")
    print(
        f"verified {macho_count} embedded Mach-O binaries, including declared Python runtime "
        f"{declared_runtime!r}, with TeamIdentifier={expected_team_id}"
    )


def _is_macho_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) in MACHO_MAGICS
    except OSError:
        return False


def _sealed_bundle_output(launcher: Path) -> str:
    result = subprocess.run(
        ["codesign", "--display", "--verbose=4", str(launcher)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(f"Onedir launcher is not code signed: {result.stderr.strip()}")
    return result.stderr


def require_onedir_seal(tree: Path) -> None:
    """Require the onedir tree to be a codesign-sealed bundle (seals non-Mach-O files too)."""
    launcher = tree / "hol-guard"
    if not launcher.is_file():
        raise ValueError(f"Onedir tree is missing its launcher: {launcher}")
    if not (tree / "_CodeSignature" / "CodeResources").is_file():
        raise ValueError(f"Onedir tree is missing _CodeSignature/CodeResources: {tree}")
    display = _sealed_bundle_output(launcher)
    if "Format=app bundle" not in display:
        raise ValueError(f"Onedir launcher is not sealed as an app bundle: {launcher}")
    if "Sealed Resources version=2" not in display:
        raise ValueError(f"Onedir launcher does not declare sealed resources: {launcher}")
    result = subprocess.run(
        ["codesign", "--verify", "--strict", str(launcher)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(f"Onedir launcher failed sealed-resource verification: {result.stderr.strip()}")


def verify_onedir(tree: Path, expected_team_id: str) -> None:
    """Walk a PyInstaller onedir tree and require every Mach-O to share one Team ID."""
    if not tree.is_dir():
        raise ValueError(f"Onedir tree does not exist: {tree}")
    require_onedir_seal(tree)
    macho_paths = [
        path for path in sorted(tree.rglob("*")) if not path.is_symlink() and path.is_file() and _is_macho_file(path)
    ]
    if not macho_paths:
        raise ValueError("Onedir tree contained no Mach-O binaries")
    for path in macho_paths:
        team_id, flags = _signature_info(path)
        if team_id != expected_team_id:
            raise ValueError(
                f"Onedir Mach-O {path.relative_to(tree)!r} has TeamIdentifier={team_id!r}; "
                f"expected {expected_team_id!r}"
            )
        if not flags & _CS_RUNTIME_FLAG:
            raise ValueError(f"Onedir Mach-O {path.relative_to(tree)!r} lacks the hardened-runtime flag")
    print(
        f"verified {len(macho_paths)} onedir Mach-O binaries with TeamIdentifier={expected_team_id} "
        "and hardened runtime"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--onedir", type=Path)
    parser.add_argument("--team-id", required=True)
    args = parser.parse_args()
    if (args.binary is None) == (args.onedir is None):
        raise SystemExit("exactly one of --binary or --onedir is required")
    if args.binary is not None and not args.binary.is_file():
        raise SystemExit(f"Binary does not exist: {args.binary}")
    if not args.team_id or any(ch.isspace() for ch in args.team_id):
        raise SystemExit("team-id must be a non-empty token")
    try:
        if args.onedir is not None:
            verify_onedir(args.onedir, args.team_id)
        elif args.binary is not None:
            verify(args.binary, args.team_id)
    except (OSError, ValueError, zlib.error) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
