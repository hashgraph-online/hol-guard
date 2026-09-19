"""Required proof commands fail before success when local tooling is missing."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("name", ["run-cloud-exception-sync-proof.sh", "run-policy-cloud-exceptions-release-audit.sh"])
def test_missing_local_frontend_tool_is_incomplete(tmp_path: Path, name: str) -> None:
    script = tmp_path / "scripts" / name
    script.parent.mkdir()
    shutil.copyfile(ROOT / "scripts" / name, script)
    result = subprocess.run(
        ["bash", str(script)],
        env={**os.environ, "HOL_GUARD_CLOUD_EXCEPTION_PROOF_OPTIONAL": "1"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "incomplete" in result.stderr
    assert "dashboard tsx" in result.stderr
    assert ": ok" not in result.stdout
