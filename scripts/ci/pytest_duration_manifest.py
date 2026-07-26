"""Validate, merge, and age-check deterministic pytest duration data."""

from __future__ import annotations

import gzip
import json
import math
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import cast

DURATION_REPORT_SCHEMA_VERSION = 1
DURATION_MANIFEST_SCHEMA_VERSION = 3


def load_duration_report(path: Path) -> dict[str, float]:
    """Read one CI shard report with strict data validation."""

    payload = _load_json(path)
    if not isinstance(payload, dict) or payload.get("schema_version") != DURATION_REPORT_SCHEMA_VERSION:
        raise ValueError("unsupported pytest duration report")
    return _load_durations(payload)


def merge_duration_reports(paths: Iterable[Path]) -> dict[str, float]:
    """Merge distinct shard reports, rejecting duplicate node ownership."""

    merged: dict[str, float] = {}
    for path in sorted(paths):
        for node_id, duration in load_duration_report(path).items():
            if node_id in merged:
                raise ValueError(f"duplicate pytest duration entry for {node_id!r}")
            merged[node_id] = duration
    return dict(sorted(merged.items()))


def write_duration_manifest(path: Path, durations: Mapping[str, float], observed_at: datetime) -> None:
    """Write a compact, reproducible manifest from already validated durations."""

    if observed_at.tzinfo is None:
        raise ValueError("pytest duration manifest observed_at must include a timezone")
    normalized = _validate_durations(durations)
    payload = {
        "node_durations_seconds": dict(
            sorted((node_id_digest(node_id), duration) for node_id, duration in normalized.items())
        ),
        "node_id_hash": "sha256",
        "observed_at": observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "schema_version": DURATION_MANIFEST_SCHEMA_VERSION,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if path.suffix == ".gz":
        path.write_bytes(gzip.compress(serialized, mtime=0))
    else:
        path.write_bytes(serialized)


def load_duration_manifest(path: Path, *, now: datetime, max_age: timedelta) -> dict[str, float]:
    """Load a current manifest and fail explicitly once its evidence is stale."""

    if now.tzinfo is None:
        raise ValueError("pytest duration manifest now must include a timezone")
    if max_age < timedelta(0):
        raise ValueError("pytest duration manifest max_age must be non-negative")
    payload = _load_json(path)
    if not isinstance(payload, dict) or payload.get("schema_version") != DURATION_MANIFEST_SCHEMA_VERSION:
        raise ValueError("unsupported pytest duration manifest")
    if payload.get("node_id_hash") != "sha256":
        raise ValueError("unsupported pytest duration manifest node_id_hash")
    observed_at = _parse_observed_at(payload.get("observed_at"))
    current_time = now.astimezone(timezone.utc)
    if observed_at > current_time:
        raise ValueError("pytest duration manifest is future-dated")
    if current_time - observed_at > max_age:
        raise ValueError("pytest duration manifest is stale")
    return _load_durations(payload)


def _load_durations(payload: Mapping[str, object]) -> dict[str, float]:
    values = payload.get("node_durations_seconds")
    if not isinstance(values, dict):
        raise ValueError("pytest duration data requires node_durations_seconds")
    return _validate_durations(values)


def _validate_durations(values: Mapping[str, float] | Mapping[object, object]) -> dict[str, float]:
    durations: dict[str, float] = {}
    for node_id, value in values.items():
        if not isinstance(node_id, str) or not node_id:
            raise ValueError("pytest duration data has an invalid node id")
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            or value < 0
        ):
            raise ValueError(f"pytest duration data has an invalid duration for {node_id!r}")
        durations[node_id] = float(value)
    return durations


def _parse_observed_at(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("pytest duration manifest requires observed_at")
    try:
        observed_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("pytest duration manifest has invalid observed_at") from exc
    if observed_at.tzinfo is None:
        raise ValueError("pytest duration manifest observed_at must include a timezone")
    return observed_at.astimezone(timezone.utc)


def _load_json(path: Path) -> object:
    content = gzip.decompress(path.read_bytes()) if path.suffix == ".gz" else path.read_bytes()
    return cast(object, json.loads(content))


def node_id_digest(node_id: str) -> str:
    """Return the stable, privacy-preserving manifest key for a pytest node id."""

    return sha256(node_id.encode("utf-8")).hexdigest()
