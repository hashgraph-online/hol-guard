"""Shared package-evidence parsing and path validation helpers."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import cast

from .jsonc import loads_jsonc

_MAX_MANIFEST_JSON_BYTES = 16 * 1024 * 1024


def read_json_with_integrity(path: Path, *, allow_jsonc: bool = False) -> tuple[dict[str, object] | None, str | None]:
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
        decoded = encoded.decode("utf-8")
        payload = (
            loads_jsonc(decoded, object_pairs_hook=_unique_json_pairs)
            if allow_jsonc
            else cast(object, json.loads(decoded, object_pairs_hook=_unique_json_pairs))
        )
    except (UnicodeDecodeError, ValueError):
        return None, None
    return object_mapping(payload), f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _unique_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate package identity key")
        result[key] = value
    return result


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
