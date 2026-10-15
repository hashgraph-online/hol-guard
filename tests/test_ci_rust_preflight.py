"""Keep required Rust validation parallel, complete, and fail-closed on every branch."""

from __future__ import annotations

import json
import os
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
    # The unshipped source compiler remains compiled and verified against
    # current source in the mandatory artifact producer.
    assert (
        "cargo build --manifest-path rust/Cargo.toml --locked --release "
        "-p guard-command -p hol-guard-runtime --bin guard-command-source --bin hol-guard-runtime"
    ) in evaluator_runs
    assert "verify_native_command_program.py" in evaluator_runs
    assert "native-command-evaluators" in document["jobs"]["required"]["needs"]

    size_job = document["jobs"]["native-release-size"]
    assert size_job["timeout-minutes"] >= 40
    build = next(
        step for step in size_job["steps"] if step.get("name") == "Build the shipped fat-LTO runtime"
    )
    script = build["run"]
    unset_at = script.index("unset CARGO_PROFILE_RELEASE_LTO")
    codegen_at = script.index("unset CARGO_PROFILE_RELEASE_CODEGEN_UNITS")
    build_at = script.index(
        "cargo build --manifest-path rust/Cargo.toml --locked --release "
        "-p hol-guard-runtime --bin hol-guard-runtime"
    )
    assert "--bin guard-command-source" not in script
    measure = next(
        step for step in size_job["steps"] if step.get("name") == "Measure the shipped fat-LTO runtime size"
    )
    assert (
        "python3 scripts/ci/check_wheel_size.py --native-dir rust/target/release "
        "--platform manylinux_2_17_x86_64"
    ) in measure["run"]
    assert unset_at < codegen_at < build_at
    assert size_job["steps"].index(build) < size_job["steps"].index(measure)
    assert "if" not in measure
    assert "CARGO_PROFILE_RELEASE_LTO" not in build.get("env", {})

    required = document["jobs"]["required"]
    assert "native-release-size" in required["needs"]
    aggregate = "\n".join(step.get("run", "") for step in required["steps"])
    assert '"native-release-size"' in aggregate


def test_shipped_runtime_cache_is_exact_and_only_main_can_write() -> None:
    """Reuse only matching shipped builds, and always measure the restored binary."""
    steps = workflow("ci.yml")["jobs"]["native-release-size"]["steps"]
    restore = next(step for step in steps if step.get("id") == "shipped-runtime-cache")
    setup = next(step for step in steps if step.get("uses") == "./.github/actions/setup-rust")
    stage = next(step for step in steps if step.get("name") == "Stage shipped runtime trust bindings")
    platform = next(step for step in steps if step.get("id") == "shipping-platform")
    save = next(step for step in steps if step.get("name") == "Save the verified shipped runtime")
    measure = next(step for step in steps if step.get("name") == "Measure the shipped fat-LTO runtime size")
    assert steps.index(stage) < steps.index(restore) < steps.index(setup)
    assert steps.index(platform) < steps.index(restore)
    assert "${ImageOS:?}-${ImageVersion:?}" in platform["run"]
    assert "restore-keys" not in restore["with"]
    for token in (
        "runner.os", "runner.arch", "steps.shipping-platform.outputs.image",
        "'rust/**'", "'contributions/**'", "'contracts/**'", "'spec/**'",
        "'src/codex_plugin_scanner/guard/contracts/**'",
        "'.github/actions/setup-rust/action.yml'", "'.github/workflows/ci.yml'",
    ):
        assert token in restore["with"]["key"]
    miss = "steps.shipped-runtime-cache.outputs.cache-hit != 'true'"
    for name in ("Install content-addressed compiler cache", "Build the shipped fat-LTO runtime"):
        assert next(step for step in steps if step.get("name") == name)["if"] == miss
    assert setup["if"] == miss
    assert "if" not in measure
    assert "continue-on-error" not in measure
    assert save["if"] == f"{miss} && github.event_name == 'push' && github.ref == 'refs/heads/main'"
    assert save["with"]["key"] == "${{ steps.shipped-runtime-cache.outputs.cache-primary-key }}"
    assert save["with"]["path"] == restore["with"]["path"] == "rust/target/release/hol-guard-runtime"
    assert steps.index(measure) < steps.index(save)


@pytest.mark.skipif(os.name == "nt", reason="The shipped size gate executes on Ubuntu with Bash")
@pytest.mark.parametrize("extra_bytes", [0, 1, None])
def test_restored_runtime_still_fails_the_size_gate(tmp_path: Path, extra_bytes: int | None) -> None:
    """A cache hit cannot hide an oversized or missing artifact."""
    platform = "manylinux_2_17_x86_64"
    budgets = json.loads((ROOT / "ci/package_size/budgets.json").read_text(encoding="utf-8"))
    if extra_bytes is not None:
        with (tmp_path / "hol-guard-runtime").open("wb") as binary:
            binary.truncate(budgets[platform]["runtime"] + extra_bytes)
    steps = workflow("ci.yml")["jobs"]["native-release-size"]["steps"]
    measure = next(step for step in steps if step.get("name") == "Measure the shipped fat-LTO runtime size")
    # Execute the real workflow command with only its artifact directory redirected.
    script = measure["run"].replace("rust/target/release", str(tmp_path))
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", script],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=5,
    )
    assert (result.returncode == 0) is (extra_bytes == 0)
    if extra_bytes == 1:
        assert "exceeds budget" in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="Linux workspace profile uses Bash")
def test_fast_rust_workspace_profile(tmp_path: Path) -> None:
    """Restore compatible dependencies before changing workspace test codegen."""
    steps = workflow("ci.yml")["jobs"]["native-workspace"]["steps"]
    configure = next(
        step for step in steps if step.get("name") == "Configure the checked test profile"
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
    assert invocation["opt"] == "1"
    assert invocation["args"] == [
        "nextest", "run", "--manifest-path", "rust/Cargo.toml", "--locked", "--all-targets",
        *packages, "--profile", "ci",
        "--test-threads", "4", "--retries", "0", "--no-fail-fast",
    ]


def test_rust_shards_remain_required_and_cache_isolated() -> None:
    """Keep every matrix child mandatory and prevent competing partial cache writers."""
    jobs = workflow("ci.yml")["jobs"]
    assert "native-workspace" in jobs["required"]["needs"]
    cache = next(step for step in jobs["native-workspace"]["steps"]
                 if step.get("uses") == "./.github/actions/setup-rust")
    assert cache["with"]["cache-key"] == "ci-workspace-${{ matrix.check }}"


def test_rust_shard_cache_fallback_is_read_only_and_conditional() -> None:
    """Seed new shards from trusted dependencies without recreating writer races."""
    action = yaml.safe_load((ROOT / ".github/actions/setup-rust/action.yml").read_text(encoding="utf-8"))
    assert action["inputs"]["cache-fallback-key"]["default"] == ""
    steps = action["runs"]["steps"]
    primary = next(step for step in steps if step.get("id") == "rust-cache")
    fallback = next(
        step for step in steps
        if step.get("name") == "Seed a new cache namespace from compatible dependencies"
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
    setup = next(step for step in workflow("ci.yml")["jobs"]["native-workspace"]["steps"]
                 if step.get("uses") == "./.github/actions/setup-rust")
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
    tmp_path: Path, artifact: str | None, expected: str,
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
        capture_output=True, text=True, check=True, timeout=5,
    )
    assert output.read_text(encoding="utf-8").splitlines() == [f"restored={expected}"]
    if artifact not in (None, "empty"):
        assert (target / artifact).read_text(encoding="utf-8") == "cached dependency"
