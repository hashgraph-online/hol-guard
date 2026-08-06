from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_RUNNER = _REPOSITORY_ROOT / "scripts" / "mdm" / "run-local-lab.py"


def test_local_mdm_lab_reports_portable_contract_checks() -> None:
    completed = subprocess.run(
        [sys.executable, str(_RUNNER), "--json"],
        check=False,
        cwd=_REPOSITORY_ROOT,
        env={**os.environ, "PYTHONPATH": str(_REPOSITORY_ROOT / "src")},
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)

    assert report["schemaVersion"] == "hol-guard-mdm-local-lab.v1"
    assert report["healthy"] is True
    assert [result["id"] for result in report["results"]] == [
        "absent-user-status",
        "relative-home-rejection",
        "managed-policy-parser",
    ]
    assert all(result["status"] == "pass" for result in report["results"])
    assert report["nativeCertification"] == {
        "outcome": "not-evaluated",
        "reason": "requires real macOS or Windows MDM enrollment and native signing evidence",
        "requiredGates": [
            {"id": "macos-mdm-enrollment", "platform": "macOS"},
            {"id": "macos-package-signing", "platform": "macOS"},
            {"id": "windows-intune-enrollment", "platform": "Windows"},
            {"id": "windows-msix-signing", "platform": "Windows"},
        ],
    }
