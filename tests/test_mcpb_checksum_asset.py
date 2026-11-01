"""The published MCPB checksum verifies next to the downloaded bundle."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/publish-mcpb.yml"


def _checksum_command() -> str:
    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["publish"]["steps"]
    pack = next(step for step in steps if step.get("name") == "Pack the immutable bundle")
    return next(line for line in pack["run"].splitlines() if '> "${ARTIFACT}.sha256"' in line).strip()


@pytest.mark.skipif(shutil.which("sha256sum") is None, reason="sha256sum is not installed")
def test_checksum_names_the_asset_not_the_runner_path(tmp_path: Path) -> None:
    build = tmp_path / "runner" / "_temp"
    build.mkdir(parents=True)
    artifact = build / "hol-guard-3.57.0.mcpb"
    artifact.write_bytes(b"bundle")
    env = {"ARTIFACT": str(artifact), "PATH": os.environ["PATH"]}
    subprocess.run(["bash", "-c", _checksum_command()], check=True, cwd=tmp_path, env=env)
    line = (build / "hol-guard-3.57.0.mcpb.sha256").read_text()
    assert line.split()[1] == "hol-guard-3.57.0.mcpb"
    download = tmp_path / "download"
    download.mkdir()
    shutil.copy(artifact, download)
    shutil.copy(build / "hol-guard-3.57.0.mcpb.sha256", download)
    subprocess.run(["sha256sum", "-c", "hol-guard-3.57.0.mcpb.sha256"], check=True, cwd=download, capture_output=True)
