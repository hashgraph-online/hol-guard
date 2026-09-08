"""Shared package-evidence parsing and path validation helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import cast

_MAX_PACKAGE_JSON_BYTES = 16 * 1024 * 1024


_MAX_MANIFEST_JSON_BYTES = 16 * 1024 * 1024


def read_json_with_integrity(path: Path) -> tuple[dict[str, object] | None, str | None]:
    """Read a JSON manifest via a verified descriptor; return payload and sha256 digest.

    The descriptor is opened without following symlinks, the file must stay a
    regular single-linked file of bounded size, and the pre/post stat identity
    must match so a swapped file never parses.
    """

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > _MAX_MANIFEST_JSON_BYTES:
            return None, None
        content = bytearray()
        while chunk := os.read(descriptor, 1024 * 1024):
            content.extend(chunk)
            if len(content) > _MAX_MANIFEST_JSON_BYTES:
                return None, None
        after = os.fstat(descriptor)
    except OSError:
        return None, None
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        return None, None
    try:
        encoded = bytes(content)
        payload = cast(object, json.loads(encoded.decode("utf-8")))
    except (UnicodeDecodeError, ValueError):
        return None, None
    return object_mapping(payload), f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def object_mapping(value: object) -> dict[str, object] | None:
    """Return a str-keyed dict view, rejecting non-dicts and non-str keys."""

    if not isinstance(value, dict):
        return None
    raw = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw):
        return None
    return {str(key): item for key, item in raw.items()}


def require(condition: bool, reason: str, reasons: list[str]) -> None:
    if not condition:
        reasons.append(reason)


def version_spec_matches(
    specifier: str | None,
    version: str | None,
    *,
    version_re: re.Pattern[str],
    caret_pins_zero_major: bool,
) -> bool:
    """Compare an observed version against a ~/^ semver specifier.

    caret_pins_zero_major selects the stricter ^0.x policy that pins the
    minor (and patch for ^0.0.x); the loose policy keeps ^ scoped to the
    major even when it is zero.
    """

    if specifier is None or version is None:
        return False
    spec_match = version_re.fullmatch(specifier)
    version_match = version_re.fullmatch(version)
    if spec_match is None or version_match is None:
        return False
    spec_parts = tuple(int(value) for value in spec_match.groups())
    version_parts = tuple(int(value) for value in version_match.groups())
    if specifier.startswith("^"):
        if spec_parts[0] > 0:
            return version_parts >= spec_parts and version_parts[0] == spec_parts[0]
        if caret_pins_zero_major:
            if spec_parts[1] > 0:
                return version_parts >= spec_parts and version_parts[:2] == spec_parts[:2]
            return version_parts == spec_parts
        return version_parts >= spec_parts and version_parts[0] == spec_parts[0]
    if specifier.startswith("~"):
        return version_parts >= spec_parts and version_parts[:2] == spec_parts[:2]
    return version_parts == spec_parts


def valid_sha512_integrity(value: object) -> bool:
    """Return true for a syntactically valid 64-byte SRI SHA-512 digest."""

    if not isinstance(value, str) or not value.startswith("sha512-"):
        return False
    try:
        decoded = base64.b64decode(value.removeprefix("sha512-"), validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) == 64


def resolved_package_bin_target(package_root: Path, target: str | None) -> Path | None:
    """Resolve a relative package bin target without allowing root escape."""

    if target is None:
        return None
    portable = PurePosixPath(target.replace("\\", "/"))
    if portable.is_absolute() or not portable.parts or ".." in portable.parts:
        return None
    candidate = package_root.joinpath(*portable.parts).resolve(strict=False)
    try:
        _ = candidate.relative_to(package_root)
    except ValueError:
        return None
    return candidate


def read_package_json(path: Path) -> dict[str, object] | None:
    """Read a bounded, non-symlink package.json object without raising."""

    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_PACKAGE_JSON_BYTES:
            return None
        payload = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    typed = cast(dict[object, object], payload)
    return {key: value for key, value in typed.items() if isinstance(key, str)}
