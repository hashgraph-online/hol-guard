"""Keep required Rust validation parallel, complete, and fail-closed on every branch."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
STANDALONE = (
    "!((github.event_name == 'pull_request' && github.base_ref == 'main') || "
    "(github.event_name == 'push' && github.ref == 'refs/heads/main'))"
)


def workflow(name: str) -> dict:
    """Load declarative workflow metadata without executing repository runtime code."""
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))


def test_required_rust_checks_are_parallel_to_the_fast_artifact_producer() -> None:
    ci = workflow("ci.yml")
    events = ci.get("on", ci.get(True))
    for event in ("push", "pull_request"):
        assert "main" in events[event]["branches"]
        assert "paths" not in events[event] and "paths-ignore" not in events[event]
    jobs = ci["jobs"]
    native = jobs["native-workspace"]
    assert not {"if", "needs", "continue-on-error"} & native.keys()
    assert native["strategy"]["matrix"] == {"check": ["clippy", "test"]}
    assert native["strategy"]["fail-fast"] is False
    assert native["timeout-minutes"] == 15
    step = next(step for step in native["steps"] if "CARGO_CHECK" in step.get("env", {}))
    assert step["env"]["CARGO_CHECK"] == "${{ matrix.check }}"
    assert "if" not in step and "continue-on-error" not in step
    assert "--skip" not in step["run"] and "|| true" not in step["run"]
    producer = jobs["native-command-evaluators"]
    assert "needs" not in producer and producer["timeout-minutes"] == 5
    commands = "\n".join(step.get("run", "") for step in producer["steps"])
    assert "cargo fmt --manifest-path rust/Cargo.toml --all --check" in commands
    assert "cargo clippy" not in commands and "cargo test" not in commands
    assert jobs["quality"]["needs"] == "native-command-evaluators"
    assert jobs["coverage-plan"]["needs"] == "native-command-evaluators"
    assert jobs["coverage"]["needs"] == ["coverage-plan", "native-command-evaluators"]
    required = jobs["ci-python-312"]
    assert required["name"] == "ci (3.12)" and required["if"] == "always()"
    assert {"native-workspace", "quality", "coverage-plan", "coverage"} <= set(required["needs"])


@pytest.mark.skipif(os.name == "nt", reason="The workspace matrix executes on Ubuntu with Bash")
@pytest.mark.parametrize("mode", ["clippy", "test", "unexpected"])
@pytest.mark.parametrize("cargo_exit", [0, 23])
def test_workspace_commands_preserve_the_full_proof_and_cargo_exit(tmp_path, mode, cargo_exit) -> None:
    steps = workflow("ci.yml")["jobs"]["native-workspace"]["steps"]
    step = next(step for step in steps if "CARGO_CHECK" in step.get("env", {}))
    cargo = tmp_path / "cargo"
    cargo.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" > "$ARGUMENTS"\nexit "$CARGO_EXIT"\n')
    cargo.chmod(0o755)
    arguments = tmp_path / "arguments"
    completed = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", step["run"]],
        env={
            **os.environ,
            "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "CARGO_CHECK": mode,
            "CARGO_EXIT": str(cargo_exit),
            "ARGUMENTS": str(arguments),
        },
        check=False,
        capture_output=True,
        timeout=5,
    )
    if mode == "unexpected":
        assert completed.returncode == 64 and not arguments.exists()
    else:
        assert completed.returncode == cargo_exit
        expected = [mode, "--manifest-path", "rust/Cargo.toml", "--locked", "--workspace", "--all-targets"]
        if mode == "clippy":
            expected += ["--", "-D", "warnings"]
        assert arguments.read_text().splitlines() == expected


@pytest.mark.skipif(os.name == "nt", reason="The required aggregate executes on Ubuntu with Bash")
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", "timed_out"])
@pytest.mark.parametrize("dependency", ["NATIVE_WORKSPACE_RESULT", "QUALITY_RESULT", "COVERAGE_RESULT"])
def test_required_aggregate_rejects_failed_or_skipped_dependencies(result: str, dependency: str) -> None:
    step = workflow("ci.yml")["jobs"]["ci-python-312"]["steps"][0]
    assert step["env"]["NATIVE_WORKSPACE_RESULT"] == "${{ needs.native-workspace.result }}"
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


@pytest.mark.parametrize(
    ("name", "job_id", "step_name"),
    [
        ("rust-authority-ownership.yml", "ownership", "Compile and lint complete Rust workspace"),
        ("rust-command-model-differential.yml", "command-model", "Validate locked command workspace"),
        ("rust-posttool-authority-acceptance.yml", "authority", "Build and lint"),
        ("rust-runtime-rule-contract.yml", "rule-contract", "Validate locked Rust workspace"),
        ("rust-runtime-windows-resident.yml", "unix-regression", "Check locked Rust workspace"),
        ("rust-runtime.yml", "rust", "Test"),
    ],
)
def test_only_main_duplicates_are_skipped_so_other_branches_keep_standalone_proofs(name, job_id, step_name):
    job = workflow(name)["jobs"][job_id]
    proof = next(step for step in job["steps"] if step.get("name") == step_name)
    # Negating ONLY these main events keeps every release, stacked PR, special push,
    # scheduled run, manual dispatch and future event covered without a branch allowlist.
    assert proof["if"] == STANDALONE
    assert "cargo test" in proof["run"] and "--workspace --all-targets" in proof["run"]
    assert "continue-on-error" not in job and "continue-on-error" not in proof
    builds = [step for step in job["steps"] if "cargo build" in step.get("run", "")]
    assert builds and all("if" not in step and "continue-on-error" not in step for step in builds)


def test_windows_and_macos_workspace_proofs_remain_platform_specific() -> None:
    for name in ("rust-daemon-edge-hardening.yml", "rust-runtime-windows-resident.yml"):
        job = workflow(name)["jobs"]["windows-workspace"]
        assert "if" not in job and "continue-on-error" not in job
        proof = next(step for step in job["steps"] if "cargo test " in step.get("run", ""))
        assert "if" not in proof and "--workspace --all-targets" in proof["run"]
    steps = workflow("rust-daemon-edge-hardening.yml")["jobs"]["cross-platform"]["steps"]
    proof = next(step for step in steps if "cargo test " in step.get("run", ""))
    assert proof["if"] == f"runner.os == 'macOS' || (runner.os == 'Linux' && {STANDALONE})"
    lifecycle = next(step for step in steps if step.get("name") == "Validate real native client lifecycle")
    assert "if" not in lifecycle and "continue-on-error" not in lifecycle
