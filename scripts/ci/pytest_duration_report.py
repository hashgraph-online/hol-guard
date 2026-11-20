"""Emit deterministic per-node pytest durations for CI sharding evidence."""

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
_OFFLINE_MODULE = "tests/test_native_offline_cache.py"
_STORAGE_MARKERS = {json.dumps({"offline_fixture_storage": kind}): kind for kind in ("disk", "tmpfs")}
_FIXTURE_STORAGE: set[str] = set()


def load_duration_report(path: Path) -> dict[str, float]:
    """Validate one report before it becomes duration-manifest input."""

    return _load_duration_report(path)


def pytest_runtest_logreport(report: _Report) -> None:
    """Include fixture setup and teardown in the cost of each collected node."""

    if report.when in {"setup", "call", "teardown"} and report.duration >= 0:
        _DURATIONS[report.nodeid] = _DURATIONS.get(report.nodeid, 0.0) + report.duration
    if report.when == "setup" and report.nodeid.startswith(_OFFLINE_MODULE + "::"):
        captured = getattr(report, "capstdout", "")
        if isinstance(captured, str) and len(captured) <= 65536:
            for line in captured.splitlines():
                if line in _STORAGE_MARKERS:
                    _FIXTURE_STORAGE.add(_STORAGE_MARKERS[line])


def pytest_sessionstart() -> None:
    """Prevent stale in-process values when pytest is invoked repeatedly."""

    _DURATIONS.clear()
    _FIXTURE_STORAGE.clear()


def pytest_sessionfinish(session: object, exitstatus: int) -> None:
    """Write the shard artifact only when CI requested a destination (controller only)."""

    _ = exitstatus
    config = getattr(session, "config", None)
    if getattr(config, "workerinput", None) is not None:
        return
    output_value = os.environ.get(OUTPUT_ENV)
    if not output_value:
        return
    output = Path(output_value)
    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "node_durations_seconds": dict(sorted(_DURATIONS.items())),
    }
    if _FIXTURE_STORAGE:
        # Diagnostic only: never copy paths, arbitrary stdout or native payloads.
        payload["fixture_storage"] = {_OFFLINE_MODULE: sorted(_FIXTURE_STORAGE)}
    output.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
