"""Local record of untested-version warnings the user has acknowledged.

An acknowledgement only collapses the expanded warning. It is keyed by the
installation, exact version, coverage revision, and Guard build, so any change
to those makes the warning eligible again. It is never read by enforcement.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from ..durable_io import fsync_directory

ACKNOWLEDGEMENTS_FILENAME = "harness-version-acknowledgements.json"
STORE_VERSION = 1
MAX_ACKNOWLEDGEMENTS = 32
MAX_STORE_BYTES = 16 * 1024
_KEY = re.compile(r"^[0-9a-f]{64}$")
_HARNESS = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def _path(guard_home: Path) -> Path:
    return guard_home / ACKNOWLEDGEMENTS_FILENAME


def _valid_entry(value: object) -> dict[str, str] | None:
    if not isinstance(value, dict) or set(value) != {"harness", "key", "acknowledged_at"}:
        return None
    harness, key, at = value["harness"], value["key"], value["acknowledged_at"]
    if not (isinstance(harness, str) and _HARNESS.fullmatch(harness)):
        return None
    if not (isinstance(key, str) and _KEY.fullmatch(key)):
        return None
    if not isinstance(at, str) or len(at) > 40:
        return None
    return {"harness": harness, "key": key, "acknowledged_at": at}


def load_acknowledgements(guard_home: Path) -> list[dict[str, str]]:
    """Read the bounded store; a corrupt store acknowledges nothing."""

    try:
        raw = _path(guard_home).read_bytes()
    except OSError:
        return []
    if len(raw) > MAX_STORE_BYTES:
        return []
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict) or payload.get("version") != STORE_VERSION:
        return []
    items = payload.get("items")
    if not isinstance(items, list):
        return []
    entries = [entry for entry in (_valid_entry(item) for item in items[:MAX_ACKNOWLEDGEMENTS]) if entry]
    return entries


def acknowledged_keys(guard_home: Path, harness: str) -> frozenset[str]:
    return frozenset(entry["key"] for entry in load_acknowledgements(guard_home) if entry["harness"] == harness)


def _write(guard_home: Path, entries: list[dict[str, str]]) -> None:
    guard_home.mkdir(parents=True, exist_ok=True)
    body = json.dumps({"version": STORE_VERSION, "items": entries[-MAX_ACKNOWLEDGEMENTS:]}, sort_keys=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=".hvc-ack-", dir=guard_home)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temp_name, 0o600)
        os.replace(temp_name, _path(guard_home))
        fsync_directory(guard_home)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise


def record_acknowledgement(guard_home: Path, *, harness: str, key: str) -> dict[str, str]:
    """Store one acknowledgement, replacing earlier ones for the harness."""

    if not _HARNESS.fullmatch(harness) or not _KEY.fullmatch(key):
        raise ValueError("invalid acknowledgement")
    entry = {
        "harness": harness,
        "key": key,
        "acknowledged_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    entries = [item for item in load_acknowledgements(guard_home) if item["harness"] != harness]
    entries.append(entry)
    _write(guard_home, entries)
    return entry


def clear_acknowledgements(guard_home: Path, *, harness: str) -> int:
    if not _HARNESS.fullmatch(harness):
        raise ValueError("invalid harness")
    entries = load_acknowledgements(guard_home)
    kept = [item for item in entries if item["harness"] != harness]
    if len(kept) != len(entries):
        _write(guard_home, kept)
    return len(entries) - len(kept)
