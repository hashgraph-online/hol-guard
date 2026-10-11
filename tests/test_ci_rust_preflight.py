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


def test_shipped_native_size_gate_uses_cargo_release_profile() -> None:
    document = workflow("ci.yml")
    env = document["env"]
    assert env["CARGO_PROFILE_RELEASE_LTO"] == "false"
    assert env["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"] == "16"

    evaluators = document["jobs"]["native-command-evaluators"]
    assert evaluators["timeout-minutes"] >= 10
    evaluator_runs = "\n".join(step.get("run", "") for step in evaluators["steps"])
    assert "check_wheel_size.py" not in evaluator_runs
    assert "unset CARGO_PROFILE_RELEASE_LTO" not in evaluator_runs

    size_job = document["jobs"]["native-release-size"]
    assert size_job["timeout-minutes"] >= 40
    measure = next(
        step for step in size_job["steps"] if step.get("name") == "Measure the shipped fat-LTO release binaries"
    )
    script = measure["run"]
    unset_at = script.index("unset CARGO_PROFILE_RELEASE_LTO")
    codegen_at = script.index("unset CARGO_PROFILE_RELEASE_CODEGEN_UNITS")
    build_at = script.index(
        "cargo build --manifest-path rust/Cargo.toml --locked --release "
        "-p guard-command -p hol-guard-runtime --bin guard-command-source --bin hol-guard-runtime"
    )
    check_at = script.index(
        "python3 scripts/ci/check_wheel_size.py --native-dir rust/target/release "
        "--platform manylinux_2_17_x86_64"
    )
    assert unset_at < codegen_at < build_at < check_at
    assert "CARGO_PROFILE_RELEASE_LTO" not in measure.get("env", {})

    required = document["jobs"]["required"]
    assert "native-release-size" in required["needs"]
    aggregate = "\n".join(step.get("run", "") for step in required["steps"])
    assert '"native-release-size"' in aggregate
