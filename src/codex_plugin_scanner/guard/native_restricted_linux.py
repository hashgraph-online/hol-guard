"""Bound resident transport for Linux containment preparation and typed indexes."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .native_restricted_pytest import restricted_native
from .runtime.restricted_linux_landlock import LinuxContainmentUnavailableError
from .runtime.restricted_pytest_model import RestrictedPytestError


def linux_native(operation: str, fields: Mapping[str, Any], expected: type | tuple[type, ...]) -> Any:
    try:
        return restricted_native(operation, fields, expected)
    except RestrictedPytestError as error:
        raise LinuxContainmentUnavailableError(str(error)) from error


def read_grants(root: Path, max_entries: int) -> list[dict[str, Any]]:
    """Decode native inode evidence through a bounded private transport file."""
    try:
        with tempfile.TemporaryDirectory(prefix="hol-guard-linux-index-") as directory:
            snapshot = Path(directory).resolve() / "linux-index.json"
            result = linux_native(
                "linux_read_grants",
                {"root": root, "max_entries": max_entries, "result_snapshot": snapshot},
                dict,
            )
            if (
                set(result) != {"decoded_bytes", "sha256"}
                or type(result["decoded_bytes"]) is not int
                or not 0 <= result["decoded_bytes"] <= 64 * 1024 * 1024
                or not isinstance(result["sha256"], str)
            ):
                raise ValueError("Invalid native index envelope.")
            descriptor = os.open(snapshot, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                status = os.fstat(stream.fileno())
                if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid() or status.st_mode & 0o077:
                    raise ValueError("Invalid native index snapshot.")
                raw = stream.read(result["decoded_bytes"] + 1)
            if len(raw) != result["decoded_bytes"] or hashlib.sha256(raw).hexdigest() != result["sha256"]:
                raise ValueError("Invalid native index envelope.")
            value = json.loads(raw)
            if not isinstance(value, list) or any(
                not isinstance(item, dict)
                or set(item) != {"path", "device", "inode"}
                or not isinstance(item["path"], str)
                or any(type(item[key]) is not int for key in ("device", "inode"))
                for item in value
            ):
                raise ValueError("Invalid native index reply.")
            return value
    except (OSError, ValueError, TypeError) as error:
        raise LinuxContainmentUnavailableError("Linux workspace index transport is unavailable.") from error
