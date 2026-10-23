"""Freeze Python's passive VM probe and resource admission decisions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ci.gauntlet.control_plane import config, telemetry


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/control_plane/telemetry.py"
SOURCE_SHA256 = "bc294a2507ef6adc1a86aa6086142ef4737ef939db8e7ad629c6d89d7d97c503"
NOW = 1_700_000_000.0
GIB = 1024**3


def snapshot() -> dict:
    return {
        "deployment": {"status": "installed"},
        "host": {"checked_at": NOW - 5, "disk_free": 40 * GIB},
        "vm": {"status": "running", "checked_at": NOW - 4,
               "disk_free": 12 * GIB, "disk_total": 47 * GIB,
               "memory_total": 15.6 * GIB, "memory_available": 8 * GIB},
    }


def main() -> None:
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("pinned Python telemetry source changed")
    sample = {"status": "running", "checked_at": NOW - 4, "cpus": 2,
              "load": 0.25, "memory_total": 16 * GIB, "memory_available": 8 * GIB,
              "disk_total": 47 * GIB, "disk_free": 12 * GIB}
    calls = []

    def fake_run(argv, **kwargs):
        calls.append({"argv": argv, "timeout": kwargs["timeout"],
                      "capture_output": kwargs["capture_output"], "text": kwargs["text"]})
        return SimpleNamespace(returncode=0, stdout=json.dumps(sample), stderr="")

    with patch.object(telemetry.subprocess, "run", side_effect=fake_run):
        positive = telemetry.vm(config.DEFAULTS)
    if len(calls) != 1:
        raise AssertionError("one VM probe required")
    with patch.object(telemetry.subprocess, "run", return_value=SimpleNamespace(
            returncode=1, stdout="", stderr="VM refused")), \
         patch.object(telemetry.time, "time", return_value=NOW):
        unavailable = telemetry.vm(config.DEFAULTS)

    cases = []
    changes = [
        ("healthy", lambda value: None),
        ("stale_host", lambda value: value["host"].update(checked_at=NOW - 91)),
        ("stale_vm", lambda value: value["vm"].update(checked_at=NOW - 91)),
        ("host_disk_floor", lambda value: value["host"].update(disk_free=11 * GIB)),
        ("vm_unavailable", lambda value: value["vm"].update(status="unavailable")),
        ("vm_disk_floor", lambda value: value["vm"].update(disk_free=7 * GIB)),
        ("vm_memory_total", lambda value: value["vm"].update(memory_total=14 * GIB)),
        ("vm_disk_total", lambda value: value["vm"].update(disk_total=44 * GIB)),
        ("vm_memory_available", lambda value: value["vm"].update(memory_available=GIB - 1)),
        ("deployment_missing", lambda value: value["deployment"].update(status="unknown")),
        ("all_limits", lambda value: (value["deployment"].update(status="unknown"),
                                      value["host"].update(checked_at=0, disk_free=0),
                                      value["vm"].update(checked_at=0, disk_free=0,
                                                         memory_total=0, disk_total=0,
                                                         memory_available=0))),
    ]
    with patch.object(telemetry.time, "time", return_value=NOW):
        for name, change in changes:
            value = snapshot()
            change(value)
            cases.append({"name": name, "snapshot": value,
                          "reasons": telemetry.admission(value, config.DEFAULTS)})
    print(json.dumps({"schema": "gauntlet-telemetry-fixtures.v1",
                      "source_sha256": SOURCE_SHA256, "now": NOW,
                      "probe": {"call": calls[0], "sample_stdout": json.dumps(sample),
                                "positive": positive, "unavailable": unavailable},
                      "admission_cases": cases}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
