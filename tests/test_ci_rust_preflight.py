"""Keep required Rust validation parallel, complete, and fail-closed on every branch."""

from __future__ import annotations

import os
import json
import subprocess
import sys
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
    """Reject any unsuccessful required dependency, including skipped jobs."""
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
    """Measure shipped artifacts without the faster CI-only release overrides."""
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


@pytest.mark.skipif(os.name == "nt", reason="Linux workspace profile uses Bash")
def test_fast_rust_workspace_profile(tmp_path: Path) -> None:
    """Restore compatible dependencies before changing workspace test codegen."""
    steps = workflow("ci.yml")["jobs"]["native-workspace"]["steps"]
    configure = next(
        step for step in steps if step.get("name") == "Configure the dependency-compatible test profile"
    )
    cache = next(step for step in steps if step.get("uses") == "./.github/actions/setup-rust")
    assert steps.index(configure) < steps.index(cache)
    assert configure["if"] == "matrix.check != 'clippy'"
    environment_file = tmp_path / "github-env"
    subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", configure["run"]],
        env={**os.environ, "GITHUB_ENV": str(environment_file)},
        check=True,
        capture_output=True,
        timeout=5,
    )
    configured = dict(line.split("=", 1) for line in environment_file.read_text().splitlines())
    assert configured["CARGO_PROFILE_TEST_OPT_LEVEL"] == "1"
    assert configured["CARGO_PROFILE_TEST_DEBUG_ASSERTIONS"] == "true"
    assert configured["CARGO_PROFILE_TEST_OVERFLOW_CHECKS"] == "true"
    assert configured["CARGO_PROFILE_TEST_DEBUG"] == "line-tables-only"
    assert "RUSTFLAGS" not in configured



@pytest.mark.skipif(os.name == "nt", reason="Linux workspace validation uses Bash")
@pytest.mark.parametrize(
    ("check", "packages"),
    [
        ("test-core", ["--workspace", "--exclude", "guard-command", "--exclude", "hol-guard-runtime"]),
        ("test-command", ["--package", "guard-command"]),
        ("test-runtime", ["--package", "hol-guard-runtime"]),
    ],
)
def test_rust_shards_preserve_full_target_selection(tmp_path: Path, check: str, packages: list[str]) -> None:
    """Execute each shard's shell branch and inspect the exact Cargo arguments."""
    job = workflow("ci.yml")["jobs"]["native-workspace"]
    assert job["strategy"]["matrix"]["check"] == ["clippy", "test-core", "test-command", "test-runtime"]
    assert job["strategy"]["fail-fast"] is False
    validate = next(step["run"] for step in job["steps"] if step.get("name") == "Validate the locked Rust workspace")
    assert "cargo clippy --manifest-path rust/Cargo.toml --locked --workspace --all-targets" in validate
    assert "-- -D warnings" in validate
    bindir = tmp_path / "bin"
    bindir.mkdir()
    installer = bindir / "python3"
    installer.write_text('#!/bin/sh\nprintf "%s\\n" "$FAKE_BIN"\n', encoding="utf-8")
    installer.chmod(0o755)
    cargo = bindir / "cargo"
    cargo.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "Path(os.environ['CAPTURE']).write_text(json.dumps({'args': sys.argv[1:], "
        "'opt': os.environ.get('CARGO_PROFILE_TEST_OPT_LEVEL')}))\n",
        encoding="utf-8",
    )
    cargo.chmod(0o755)
    capture = tmp_path / "cargo.json"
    subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", validate],
        env={
            **os.environ, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
            "CARGO_CHECK": check, "FAKE_BIN": str(bindir), "CAPTURE": str(capture),
            "CARGO_PROFILE_TEST_OPT_LEVEL": "1",
        },
        check=True, capture_output=True, timeout=5,
    )
    invocation = json.loads(capture.read_text())
    assert invocation["opt"] == "0"
    assert invocation["args"] == [
        "nextest", "run", "--manifest-path", "rust/Cargo.toml", "--locked", "--all-targets",
        *packages, "--config", 'profile.test.package."*".opt-level=1', "--profile", "ci",
        "--test-threads", "4", "--retries", "0", "--no-fail-fast",
    ]


def test_rust_shards_remain_required_and_cache_compatible() -> None:
    """Keep every matrix child mandatory and reuse the existing dependency cache."""
    jobs = workflow("ci.yml")["jobs"]
    assert "native-workspace" in jobs["required"]["needs"]
    cache = next(step for step in jobs["native-workspace"]["steps"]
                 if step.get("uses") == "./.github/actions/setup-rust")
    assert cache["with"]["cache-key"] == "ci-workspace-${{ matrix.check == 'clippy' && 'clippy' || 'test' }}"
