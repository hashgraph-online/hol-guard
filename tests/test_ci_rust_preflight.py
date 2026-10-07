"""Keep required Rust validation parallel, complete, and fail-closed on every branch."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow(name: str) -> dict:
    """Load declarative workflow metadata without executing repository runtime code."""
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))




@pytest.mark.skipif(os.name == "nt", reason="The workspace matrix executes on Ubuntu with Bash")
@pytest.mark.parametrize("mode", ["clippy", "test", "unexpected"])
@pytest.mark.parametrize("cargo_exit", [0, 23])
def test_workspace_commands_propagate_cargo_failures(tmp_path, mode, cargo_exit) -> None:
    steps = workflow("ci.yml")["jobs"]["native-workspace"]["steps"]
    step = next(step for step in steps if "CARGO_CHECK" in step.get("env", {}))
    cargo = tmp_path / "cargo"
    cargo.write_text('#!/bin/sh\nexit "$CARGO_EXIT"\n')
    cargo.chmod(0o755)
    completed = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", step["run"]],
        cwd=tmp_path,
        env={
            **os.environ,
            "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "CARGO_CHECK": mode,
            "CARGO_EXIT": str(cargo_exit),
        },
        check=False,
        capture_output=True,
        timeout=5,
    )
    if mode == "unexpected":
        assert completed.returncode == 64
    else:
        assert completed.returncode == cargo_exit


@pytest.mark.skipif(os.name == "nt", reason="The required aggregate executes on Ubuntu with Bash")
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", "timed_out"])
@pytest.mark.parametrize("dependency", ["NATIVE_WORKSPACE_RESULT", "QUALITY_RESULT", "COVERAGE_RESULT"])
def test_required_aggregate_rejects_failed_or_skipped_dependencies(result: str, dependency: str) -> None:
    step = workflow("ci.yml")["jobs"]["ci-python-312"]["steps"][0]
    environment = {name: "success" for name in step["env"]}
    environment[dependency] = result
    completed = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", step["run"]],
        env={**os.environ, **environment},
        check=False,
        capture_output=True,
        timeout=5,
    )
    assert completed.returncode != 0


