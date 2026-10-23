"""Freeze the pinned Python macOS host resource calculation."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ci.gauntlet.control_plane import telemetry


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/control_plane/telemetry.py"
SOURCE_SHA256 = "bc294a2507ef6adc1a86aa6086142ef4737ef939db8e7ad629c6d89d7d97c503"
SYSCTL = "549755813888\n"
VM_STAT = ("Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
           "Pages free: 1000.\nPages active: 3000.\nPages inactive: 2000.\n"
           "Pages speculative: 300.\n")


def subprocess_result(argv, **kwargs):
    assert kwargs == {"capture_output": True, "text": True, "check": True, "timeout": 5}
    if argv == ["/usr/sbin/sysctl", "-n", "hw.memsize"]:
        return subprocess.CompletedProcess(argv, 0, stdout=SYSCTL)
    if argv == ["/usr/bin/vm_stat"]:
        return subprocess.CompletedProcess(argv, 0, stdout=VM_STAT)
    raise AssertionError(f"unexpected host probe: {argv}")


def main() -> None:
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("pinned Python telemetry source changed")
    disk = SimpleNamespace(total=1099511627776, free=549755813888)
    with patch.object(telemetry.shutil, "disk_usage", return_value=disk), \
         patch.object(telemetry.time, "time", return_value=1700000000.25), \
         patch.object(telemetry.platform, "system", return_value="Darwin"), \
         patch.object(telemetry.os, "cpu_count", return_value=32), \
         patch.object(telemetry.os, "getloadavg", return_value=(1.25, 2.5, 3.75)), \
         patch.object(telemetry.subprocess, "run", side_effect=subprocess_result):
        result = telemetry.host(Path("/not-read"))
    print(json.dumps({"schema": "gauntlet-host-telemetry-fixtures.v1",
                      "source_sha256": SOURCE_SHA256, "sysctl_stdout": SYSCTL,
                      "vm_stat_stdout": VM_STAT, "python_host": result},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
