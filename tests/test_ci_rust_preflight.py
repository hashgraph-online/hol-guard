"""Keep required Rust validation parallel, complete, and fail-closed on every branch."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.support.ci_workflow import expand_ci_job_actions

ROOT = Path(__file__).resolve().parents[1]


def workflow(name: str) -> dict:
    """Load declarative workflow metadata without executing repository runtime code."""
    return expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8")))


@pytest.mark.skipif(os.name == "nt", reason="The required aggregate executes on Ubuntu with Bash")
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", "timed_out"])
@pytest.mark.parametrize("dependency", ["NATIVE_WORKSPACE_RESULT", "QUALITY_RESULT", "COVERAGE_RESULT"])
def test_required_aggregate_rejects_failed_or_skipped_dependencies(result: str, dependency: str) -> None:
    """Reject any unsuccessful required dependency, including skipped jobs."""
    step = workflow("ci.yml")["jobs"]["required"]["steps"][1]
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


def test_native_evaluators_build_with_the_ci_release_overrides() -> None:
    """Build the mandatory evaluator artifacts with the faster CI-only release overrides."""
    document = workflow("ci.yml")
    env = document["env"]
    assert env["CARGO_PROFILE_RELEASE_LTO"] == "false"
    assert env["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"] == "16"

    evaluators = document["jobs"]["native-command-evaluators"]
    assert evaluators["timeout-minutes"] >= 10
    evaluator_runs = "\n".join(step.get("run", "") for step in evaluators["steps"])
    assert "unset CARGO_PROFILE_RELEASE_LTO" not in evaluator_runs
    # The unshipped source compiler remains compiled and verified against
    # current source in the mandatory artifact producer.
    assert (
        "cargo build --manifest-path rust/Cargo.toml --locked --release "
        "-p guard-command -p hol-guard-runtime --bin guard-command-source --bin hol-guard-runtime"
    ) in evaluator_runs
    assert "verify_native_command_program.py" in evaluator_runs
    assert "native-command-evaluators" in document["jobs"]["required"]["needs"]


@pytest.mark.skipif(os.name == "nt", reason="The required workspace formatting check uses Bash")
@pytest.mark.parametrize("cargo_status", [0, 42])
def test_required_clippy_formats_the_full_workspace_even_with_cached_archives(
    tmp_path: Path, cargo_status: int
) -> None:
    document = workflow("ci.yml")
    job = document["jobs"]["native-workspace"]
    steps = job["steps"]
    setup = next(step for step in steps if step.get("uses") == "./.github/actions/setup-rust")
    formatting = next(
        step for step in steps if step.get("name") == "Check native formatting in the required Clippy job"
    )
    assert setup["with"]["components"] == "${{ matrix.check == 'clippy' && 'clippy rustfmt' || 'clippy' }}"
    assert steps.index(setup) + 1 == steps.index(formatting)
    assert formatting["if"] == "matrix.check == 'clippy'"
    assert "continue-on-error" not in formatting
    assert "runtime-archive" not in formatting["if"]
    assert "native-workspace" in document["jobs"]["required"]["needs"]
    assert "continue-on-error" not in job
    (tmp_path / "rust").mkdir()
    (tmp_path / "rust/rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.88.0"\n')
    bindir = tmp_path / "bin"
    bindir.mkdir()
    cargo = bindir / "cargo"
    cargo.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE"\nexit {cargo_status}\n')
    cargo.chmod(0o755)
    capture = tmp_path / "arguments"
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", formatting["run"]],
        cwd=tmp_path,
        env={**os.environ, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}", "CAPTURE": str(capture)},
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == cargo_status
    assert capture.read_text().splitlines() == [
        "+1.88.0",
        "fmt",
        "--manifest-path",
        "rust/Cargo.toml",
        "--all",
        "--check",
    ]


@pytest.mark.skipif(os.name == "nt", reason="Linux workspace profile uses Bash")
def test_fast_rust_workspace_profile(tmp_path: Path) -> None:
    """Restore compatible dependencies before changing workspace test codegen."""
    steps = workflow("ci.yml")["jobs"]["native-workspace"]["steps"]
    configure = next(step for step in steps if step.get("name") == "Configure the checked test profile")
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
@pytest.mark.parametrize("archive_hit", [False, True])
@pytest.mark.parametrize(
    ("check", "packages", "partition"),
    [
        ("test-core", ["--workspace", "--exclude", "guard-command", "--exclude", "hol-guard-runtime"], []),
        ("test-command", ["--package", "guard-command"], []),
        ("test-runtime-1", ["--package", "hol-guard-runtime"], ["--partition", "hash:1/2"]),
        ("test-runtime-2", ["--package", "hol-guard-runtime"], ["--partition", "hash:2/2"]),
    ],
)
def test_rust_shards_preserve_full_target_selection(
    tmp_path: Path, check: str, packages: list[str], partition: list[str], archive_hit: bool
) -> None:
    """Execute each shard's shell branch and inspect the exact Cargo arguments."""
    job = workflow("ci.yml")["jobs"]["native-workspace"]
    assert job["strategy"]["matrix"]["check"] == [
        "clippy",
        "test-core",
        "test-command",
        "test-runtime-1",
        "test-runtime-2",
    ]
    assert job["strategy"]["fail-fast"] is False
    assert "continue-on-error" not in job
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
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", validate],
        env={
            **os.environ,
            "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
            "CARGO_CHECK": check,
            "FAKE_BIN": str(bindir),
            "CAPTURE": str(capture),
            "CARGO_PROFILE_TEST_OPT_LEVEL": "1",
            "RUNTIME_ARCHIVE_HIT": str(archive_hit).lower(),
            "RUNNER_TEMP": str(tmp_path),
            "GITHUB_WORKSPACE": str(workspace),
        },
        check=True,
        capture_output=True,
        timeout=5,
    )
    invocation = json.loads(capture.read_text())
    assert invocation["opt"] == "1"
    assert (workspace / "rust/target").is_dir() is archive_hit
    if archive_hit:
        build_args = [
            "--archive-file",
            str(tmp_path / "runtime-test-archive.tar.zst"),
            "--workspace-remap",
            str(workspace / "rust"),
        ]
    else:
        build_args = ["--manifest-path", "rust/Cargo.toml", "--locked", "--all-targets", *packages]
    assert invocation["args"] == [
        "nextest",
        "run",
        *build_args,
        "--profile",
        "ci",
        *partition,
        "--test-threads",
        "4",
        "--retries",
        "0",
        "--no-fail-fast",
    ]


def test_rust_shards_remain_required_and_cache_isolated() -> None:
    """Keep every matrix child mandatory and prevent competing partial cache writers."""
    jobs = workflow("ci.yml")["jobs"]
    assert "native-workspace" in jobs["required"]["needs"]
    cache = next(
        step for step in jobs["native-workspace"]["steps"] if step.get("uses") == "./.github/actions/setup-rust"
    )
    assert cache["with"]["cache-key"] == "ci-workspace-${{ matrix.check }}"


def test_rust_shard_cache_fallback_is_read_only_and_conditional() -> None:
    """Seed new shards from trusted dependencies without recreating writer races."""
    action = yaml.safe_load((ROOT / ".github/actions/setup-rust/action.yml").read_text(encoding="utf-8"))
    assert action["inputs"]["cache-fallback-key"]["default"] == ""
    steps = action["runs"]["steps"]
    primary = next(step for step in steps if step.get("id") == "rust-cache")
    fallback = next(
        step for step in steps if step.get("name") == "Seed a new cache namespace from compatible dependencies"
    )
    assert steps.index(primary) < steps.index(fallback)
    restored = next(step for step in steps if step.get("id") == "rust-cache-state")
    assert steps.index(primary) < steps.index(restored) < steps.index(fallback)
    assert restored["if"] == "inputs.cache-fallback-key != '' && steps.rust-cache.outputs.cache-hit != 'true'"
    assert fallback["if"] == (
        "inputs.cache-fallback-key != '' && steps.rust-cache.outputs.cache-hit != 'true' "
        "&& steps.rust-cache-state.outputs.restored != 'true'"
    )
    assert fallback["with"]["save-if"] == "false"
    assert "inputs.cache-key" in primary["with"]["shared-key"]
    assert "inputs.cache-fallback-key" in fallback["with"]["shared-key"]
    for key in ("prefix-key", "workspaces", "cache-workspace-crates", "cache-bin"):
        assert fallback["with"][key] == primary["with"][key]
    assert "github.ref == 'refs/heads/main'" in primary["with"]["save-if"]
    setup = next(
        step
        for step in workflow("ci.yml")["jobs"]["native-workspace"]["steps"]
        if step.get("uses") == "./.github/actions/setup-rust"
    )
    assert setup["with"]["cache-key"] == "ci-workspace-${{ matrix.check }}"
    assert setup["with"]["cache-fallback-key"] == "${{ matrix.check != 'clippy' && 'ci-workspace-test' || '' }}"


@pytest.mark.skipif(os.name == "nt", reason="Execute the composite action's Bash restore probe")
@pytest.mark.parametrize(
    ("artifact", "expected"),
    [
        (None, "false"),
        ("empty", "false"),
        (".rustc_info.json", "false"),
        ("debug/deps/libdependency.rlib", "true"),
        ("aarch64-unknown-linux-gnu/release/deps/libdependency.rmeta", "true"),
    ],
)
def test_rust_cache_probe_distinguishes_partial_restores(
    tmp_path: Path,
    artifact: str | None,
    expected: str,
) -> None:
    """Skip fallback only when cached dependency artifacts actually exist."""
    action = yaml.safe_load((ROOT / ".github/actions/setup-rust/action.yml").read_text(encoding="utf-8"))
    probe = next(step for step in action["runs"]["steps"] if step.get("id") == "rust-cache-state")
    assert probe["shell"] == "bash"
    workspace = tmp_path / "workspace with spaces"
    workspace.mkdir()
    target = workspace / "rust/target"
    if artifact is not None:
        target.mkdir(parents=True)
        if artifact != "empty":
            cached_file = target / artifact
            cached_file.parent.mkdir(parents=True, exist_ok=True)
            cached_file.write_text("cached dependency", encoding="utf-8")
    output = tmp_path / "github-output"
    subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", probe["run"]],
        cwd=workspace,
        env={**os.environ, "GITHUB_OUTPUT": str(output)},
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    )
    assert output.read_text(encoding="utf-8").splitlines() == [f"restored={expected}"]
    if artifact not in (None, "empty"):
        assert (target / artifact).read_text(encoding="utf-8") == "cached dependency"
