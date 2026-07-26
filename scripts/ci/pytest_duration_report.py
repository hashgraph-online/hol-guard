"""Emit deterministic per-node pytest call durations for CI sharding evidence."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, cast

OUTPUT_ENV = "GUARD_PYTEST_DURATION_OUTPUT"
SCHEMA_VERSION = 1


class _Report(Protocol):
    when: str
    nodeid: str
    duration: float


class _Config(Protocol):
    workerinput: Mapping[str, object] | None


_DURATIONS: dict[str, float] = {}


def pytest_runtest_logreport(report: _Report) -> None:
    """Keep only the call phase, keyed by the exact collected node id."""

    if report.when == "call" and report.duration >= 0:
        _DURATIONS[report.nodeid] = report.duration


def pytest_sessionstart() -> None:
    """Prevent stale in-process values when pytest is invoked repeatedly."""

    _DURATIONS.clear()


def pytest_sessionfinish(session: object, exitstatus: int) -> None:
    """Write the shard artifact only when CI requested a destination."""

    _ = session, exitstatus
    output_value = os.environ.get(OUTPUT_ENV)
    if not output_value:
        return
    output = Path(output_value)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "node_durations_seconds": dict(sorted(_DURATIONS.items())),
    }
    output.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def load_duration_report(path: Path) -> dict[str, float]:
    """Validate a report before it is used as future shard input."""

    payload = cast(object, json.loads(path.read_text(encoding="utf-8")))
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported pytest duration report")
    values = payload.get("node_durations_seconds")
    if not isinstance(values, dict):
        raise ValueError("pytest duration report requires node_durations_seconds")
    durations: dict[str, float] = {}
    for node_id, value in values.items():
        if not isinstance(node_id, str) or not node_id:
            raise ValueError("pytest duration report has an invalid node id")
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise ValueError(f"pytest duration report has an invalid duration for {node_id!r}")
        durations[node_id] = float(value)
    return durations
