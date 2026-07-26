"""Emit deterministic per-node pytest call durations for CI sharding evidence."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.pytest_duration_manifest import DURATION_REPORT_SCHEMA_VERSION
from scripts.ci.pytest_duration_manifest import load_duration_report as _load_duration_report

OUTPUT_ENV = "GUARD_PYTEST_DURATION_OUTPUT"
SCHEMA_VERSION = DURATION_REPORT_SCHEMA_VERSION


class _Report(Protocol):
    when: str
    nodeid: str
    duration: float


class _Config(Protocol):
    workerinput: Mapping[str, object] | None


_DURATIONS: dict[str, float] = {}


def load_duration_report(path: Path) -> dict[str, float]:
    """Validate one report before it becomes duration-manifest input."""

    return _load_duration_report(path)


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
