"""Bounded recognition of packaged Mach-O executables that the text scanner cannot read.

Recognition reads bounded headers and padding and never trusts a name or a magic number alone:
a file is a packaged binary only when its headers and load commands are structurally
consistent with the whole file. Recognition is not an assessment of safety. Code
signing is recorded as context and never lowers a finding.
"""

from __future__ import annotations

import os
import stat
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from ..models import CheckResult, Finding, Severity

MAX_FAT_ARCHES = 16
MAX_LOAD_COMMANDS = 4096
MAX_LOAD_COMMAND_BYTES = 256 * 1024
MAX_FAT_PADDING_BYTES = 64 * 1024

_THIN_MAGICS = {
    b"\xfe\xed\xfa\xce": (">", False),
    b"\xce\xfa\xed\xfe": ("<", False),
    b"\xfe\xed\xfa\xcf": (">", True),
    b"\xcf\xfa\xed\xfe": ("<", True),
}
_FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
_SUPPORTED_FILE_TYPES = {2, 6, 8}  # MH_EXECUTE, MH_DYLIB, MH_BUNDLE
_LC_SEGMENT = 0x1
_LC_SEGMENT_64 = 0x19
_LC_CODE_SIGNATURE = 0x1D


@dataclass(frozen=True, slots=True)
class PackagedBinary:
    """What header inspection established about a packaged executable."""

    format: str
    architectures: int
    code_signature_present: bool


@dataclass(frozen=True, slots=True)
class UninspectedBinary:
    """A recognized packaged binary whose content the scanner did not read."""

    path: Path
    size: int
    binary: PackagedBinary


def _read_exact(handle: BinaryIO, offset: int, length: int) -> bytes | None:
    handle.seek(offset)
    data = handle.read(length)
    return data if len(data) == length else None


def _inspect_thin(handle: BinaryIO, base: int, length: int) -> bool | None:
    """Return whether the slice carries a code signature, or None if it is not a consistent Mach-O."""
    magic = _read_exact(handle, base, 4)
    layout = _THIN_MAGICS.get(magic or b"")
    if layout is None:
        return None
    order, is_64 = layout
    header_size = 32 if is_64 else 28
    header = _read_exact(handle, base, header_size)
    if header is None:
        return None
    _, _, _, file_type, ncmds, sizeofcmds, _ = struct.unpack(f"{order}7I", header[:28])
    if file_type not in _SUPPORTED_FILE_TYPES:
        return None
    if not 0 < ncmds <= MAX_LOAD_COMMANDS or not 0 < sizeofcmds <= MAX_LOAD_COMMAND_BYTES:
        return None
    if header_size + sizeofcmds > length:
        return None
    commands = _read_exact(handle, base + header_size, sizeofcmds)
    if commands is None:
        return None

    cursor = 0
    ranges = [(0, header_size + sizeofcmds)]
    segments = 0
    signed = False
    alignment = 8 if is_64 else 4
    for _ in range(ncmds):
        if cursor + 8 > sizeofcmds:
            return None
        command, command_size = struct.unpack_from(f"{order}2I", commands, cursor)
        if command_size < 8 or command_size % alignment or cursor + command_size > sizeofcmds:
            return None
        if command == _LC_SEGMENT_64:
            if not is_64 or command_size < 72:
                return None
            (sections,) = struct.unpack_from(f"{order}I", commands, cursor + 64)
            if command_size != 72 + sections * 80:
                return None
            file_offset, file_size = struct.unpack_from(f"{order}2Q", commands, cursor + 40)
        elif command == _LC_SEGMENT:
            if is_64 or command_size < 56:
                return None
            (sections,) = struct.unpack_from(f"{order}I", commands, cursor + 48)
            if command_size != 56 + sections * 68:
                return None
            file_offset, file_size = struct.unpack_from(f"{order}2I", commands, cursor + 32)
        elif command == _LC_CODE_SIGNATURE:
            if command_size != 16:
                return None
            file_offset, file_size = struct.unpack_from(f"{order}2I", commands, cursor + 8)
            signed = signed or file_size > 0
        else:
            cursor += command_size
            continue
        if command != _LC_CODE_SIGNATURE:
            segments += 1
        if file_offset + file_size > length:
            return None
        if file_size:
            ranges.append((file_offset, file_offset + file_size))
        cursor += command_size
    if cursor != sizeofcmds or segments == 0:
        return None
    # The declarations must cover the entire slice, including gaps between regions.
    # These declarations are untrusted and establish no assurance about the contents.
    covered_end = 0
    for start, end in sorted(ranges):
        if start > covered_end:
            return None
        covered_end = max(covered_end, end)
    if covered_end != length:
        return None
    return signed


def _inspect_fat(handle: BinaryIO, length: int, *, order: str, wide: bool) -> PackagedBinary | None:
    header = _read_exact(handle, 0, 8)
    if header is None:
        return None
    (count,) = struct.unpack(f"{order}I", header[4:8])
    if not 0 < count <= MAX_FAT_ARCHES:
        return None
    entry_size = 32 if wide else 20
    table = _read_exact(handle, 8, count * entry_size)
    if table is None:
        return None
    slices: list[tuple[int, int, int]] = []
    for index in range(count):
        entry = table[index * entry_size : (index + 1) * entry_size]
        if wide:
            offset, size, alignment, reserved = struct.unpack(f"{order}QQII", entry[8:32])
            if reserved:
                return None
        else:
            offset, size, alignment = struct.unpack(f"{order}III", entry[8:20])
        if alignment > 16 or offset % (1 << alignment):
            return None
        slices.append((offset, size, alignment))
    slices.sort()
    floor = 8 + count * entry_size
    signed_slices = 0
    for offset, size, alignment in slices:
        if size == 0 or offset < floor or offset + size > length:
            return None
        gap = offset - floor
        if gap >= (1 << alignment) or gap > MAX_FAT_PADDING_BYTES:
            return None
        if gap:
            padding = _read_exact(handle, floor, gap)
            if padding is None or any(padding):
                return None
        signed = _inspect_thin(handle, offset, size)
        if signed is None:
            return None
        signed_slices += signed
        floor = offset + size
    if floor != length:
        return None
    return PackagedBinary("mach-o-universal", count, signed_slices == count)


def inspect_packaged_binary(path: Path) -> PackagedBinary | None:
    """Recognize a thin or universal Mach-O from bounded headers and alignment padding."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            return None
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            return None
        length = opened.st_size
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            magic = _read_exact(handle, 0, 4)
            fat_layout = _FAT_MAGICS.get(magic or b"")
            if fat_layout is not None:
                order, wide = fat_layout
                return _inspect_fat(handle, length, order=order, wide=wide)
            signed = _inspect_thin(handle, 0, length)
            if signed is None:
                return None
            return PackagedBinary("mach-o", 1, signed)
    except (OSError, struct.error):
        return None
    finally:
        os.close(descriptor)


def uninspected_binary_check(root: Path, binaries: list[UninspectedBinary]) -> CheckResult:
    """Report packaged binaries the scanner did not read, so they never read as a passed scan."""
    findings = []
    for item in sorted(binaries, key=lambda entry: entry.path):
        relative = item.path.relative_to(root).as_posix()
        signature = (
            "declares code-signature data (not verified and not evidence of safety)"
            if (item.binary.code_signature_present)
            else "does not declare code-signature data in every slice"
        )
        findings.append(
            Finding(
                rule_id="UNINSPECTED_PACKAGED_BINARY",
                severity=Severity.LOW,
                category="security",
                title="Packaged executable was not inspected",
                description=(
                    f"{relative} is a {item.size}-byte {item.binary.format} executable that {signature}. "
                    "Its content was not scanned: secret, approval-default and runtime-credential checks "
                    "covered only the other files. Header recognition does not show the binary is safe or "
                    "matches any source."
                ),
                remediation=(
                    "Publish the source or a reproducible build recipe, the release or commit it was built from, "
                    "and a checksum or provenance attestation for this file, and review it before trusting it. "
                    "See docs/rules/uninspected-packaged-binary.md."
                ),
                file_path=relative,
            )
        )
    return CheckResult(
        name="Packaged binaries not inspected",
        passed=False,
        points=0,
        max_points=0,
        message=(
            f"{len(binaries)} packaged executable(s) were not inspected; "
            "all other files were scanned and no assurance is given for these."
        ),
        findings=tuple(findings),
    )
