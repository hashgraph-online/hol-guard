"""Exact native reuse must retain source verification and both binaries."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from tests.support.ci_workflow import composite_action_steps, load_ci_workflow

MISS = "steps.evaluator-cache.outputs.cache-hit != 'true'"
WRITE = f"{MISS} && github.event_name == 'push' && github.ref == 'refs/heads/main'"
PREVIOUS_MISS = "steps.previous-cache.outputs.cache-hit != 'true'"
PREVIOUS_WRITE = f"{PREVIOUS_MISS} && github.event_name == 'push' && github.ref == 'refs/heads/main'"


def test_linux_cache_skips_only_compilation_and_always_verifies_current_sources() -> None:
    steps = composite_action_steps("ci-job-native-command-build")
    restore = next(step for step in steps if step.get("id") == "evaluator-cache")
    save = next(step for step in steps if step.get("name") == "Save verified native command evaluators")
    assert (
        restore["with"]["path"].split()
        == save["with"]["path"].split()
        == [
            "rust/target/release/guard-command-source",
            "rust/target/release/hol-guard-runtime",
        ]
    )
    key = restore["with"]["key"]
    for required in (
        "runner.arch",
        "outputs.image",
        "outputs.compiler-env",
        "CARGO_PROFILE_RELEASE_LTO",
        "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
        "'rust/**'",
        "'contributions/**'",
        "'contracts/**'",
        "'spec/**'",
        "'src/codex_plugin_scanner/guard/contracts/**'",
        "'.cargo/**'",
        "'scripts/ci/native_cache_environment.py'",
        "'scripts/refresh_extension_artifacts.py'",
        "'.github/actions/ci-job-native-command-build/action.yml'",
        "'.github/actions/setup-rust/action.yml'",
    ):
        assert required in key
    assert ".github/workflows/ci.yml" not in key
    assert "restore-keys" not in restore["with"]
    assert save["if"] == WRITE
    assert save["with"]["key"] == "${{ steps.evaluator-cache.outputs.cache-primary-key }}"
    for step in steps:
        if step.get("uses") == "./.github/actions/setup-rust" or step.get("name") in {
            "Install content-addressed compiler cache",
            "Build native command evaluators once for pytest shards",
        }:
            assert step["if"] == MISS
    stage = next(step for step in steps if step.get("name") == "Stage native build trust bindings")
    binaries = next(step for step in steps if step.get("name") == "Require both executable native evaluators")
    verify = next(
        step for step in steps if step.get("name") == "Verify generated native command catalogs before pytest fan-out"
    )
    assert all("if" not in step for step in (stage, binaries, verify))
    assert steps.index(stage) < steps.index(restore) < steps.index(binaries)
    assert steps.index(binaries) < steps.index(verify) < steps.index(save)
    # Required workspace validation owns formatting; a warm producer need not
    # install a toolchain solely to recheck it before artifact fan-out.
    assert all("cargo" not in step.get("run", "") or " fmt " not in step["run"] for step in steps)
    assert all("rustfmt" not in str(step) for step in steps)
    assert "verify_native_command_program.py" in verify["run"]
    build = next(step for step in steps if step.get("name") == "Build native command evaluators once for pytest shards")
    timings = next(step for step in steps if step.get("name") == "Retain native compilation timings")
    assert build["run"].splitlines()[0].endswith(" --timings")
    assert timings["if"] == f"always() && {MISS}"
    assert timings["with"] == {
        "name": "native-compilation-timings-linux",
        "path": "rust/target/cargo-timings/cargo-timing.html",
        "if-no-files-found": "ignore",
        "retention-days": 1,
        "overwrite": True,
    }
    assert steps.index(build) < steps.index(binaries) < steps.index(verify) < steps.index(timings)


@pytest.mark.skipif(os.name == "nt", reason="The Linux cache preflight uses executable mode bits")
@pytest.mark.parametrize("missing", ["guard-command-source", "hol-guard-runtime", "both", "none"])
def test_partial_cache_cannot_proceed_to_verification(tmp_path: Path, missing: str) -> None:
    steps = composite_action_steps("ci-job-native-command-build")
    preflight = next(step for step in steps if step.get("name") == "Require both executable native evaluators")
    directory = tmp_path / "rust/target/release"
    directory.mkdir(parents=True)
    for name in ("guard-command-source", "hol-guard-runtime"):
        if missing not in (name, "both"):
            binary = directory / name
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
    result = subprocess.run(["bash", "-e", "-c", preflight["run"]], cwd=tmp_path, timeout=5, capture_output=True)
    assert (result.returncode == 0) == (missing == "none")


@pytest.mark.parametrize("platform", ["macos", "windows"])
def test_platform_cache_tracks_compiler_inputs_not_unrelated_workflow_edits(platform: str) -> None:
    steps = composite_action_steps(f"ci-job-{platform}-native-runtime")
    identify = next(step for step in steps if step.get("id") == "runtime-platform")
    restore = next(step for step in steps if step.get("id") == "runtime-cache")
    assert "scripts.ci.native_cache_environment" in identify["run"]
    key = restore["with"]["key"]
    assert "outputs.compiler-env" in key
    for required in (
        "CARGO_PROFILE_RELEASE_LTO",
        "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
        "'.cargo/**'",
        "'scripts/ci/native_cache_environment.py'",
        "'scripts/refresh_extension_artifacts.py'",
    ):
        assert required in key
    assert ".github/workflows/ci.yml" not in key
    assert "restore-keys" not in restore["with"]

    build = next(step for step in steps if step.get("name", "").startswith("Build the "))
    upload = next(step for step in steps if step.get("name", "").startswith("Upload the "))
    timings = next(step for step in steps if step.get("name") == "Retain native compilation timings")
    miss = "steps.runtime-cache.outputs.cache-hit != 'true'"
    command = (
        "cargo build --manifest-path rust/Cargo.toml --locked --release "
        "-p hol-guard-runtime --bin hol-guard-runtime --timings"
    )
    assert build["run"].splitlines()[-1] == command
    assert build["if"] == miss
    assert "if" not in upload  # Runtime delivery remains mandatory even on exact cache hits.
    assert upload["with"]["if-no-files-found"] == "error"
    assert not any(step.get("continue-on-error", False) for step in (build, upload, timings))
    assert timings["if"] == f"always() && {miss}"
    assert timings["uses"] == upload["uses"]
    assert timings["with"] == {
        "name": f"native-compilation-timings-{platform}",
        "path": "rust/target/cargo-timings/cargo-timing.html",
        "if-no-files-found": "ignore",
        "retention-days": 1,
        "overwrite": True,
    }
    assert steps.index(restore) < steps.index(build) < steps.index(upload) < steps.index(timings)


def test_native_offline_previous_caches_pinned_artifacts_and_verifies_executables() -> None:
    steps = load_ci_workflow()["jobs"]["native-offline-previous"]["steps"]
    identify = next(step for step in steps if step.get("id") == "previous-platform")
    restore = next(step for step in steps if step.get("id") == "previous-cache")
    build = next(
        step for step in steps if step.get("name") == "Build the real prior native pair and matching projections"
    )
    require = next(step for step in steps if step.get("name") == "Require pinned prior native command evaluators")
    save = next(step for step in steps if step.get("name") == "Save pinned prior native evaluators and projections")
    assert "scripts.ci.native_cache_environment" in identify["run"]
    assert (
        restore["with"]["path"].splitlines()
        == save["with"]["path"].splitlines()
        == [
            "rust/target/previous-client/release/guard-command-source",
            "rust/target/previous-client/release/hol-guard-runtime",
            "previous-client/contracts/extensions/",
            "previous-client/src/codex_plugin_scanner/guard/contracts/data/extensions/",
        ]
    )
    key = restore["with"]["key"]
    for required in (
        "native-offline-previous-v1-",
        "runner.arch",
        "steps.previous-platform.outputs.image",
        "steps.previous-platform.outputs.compiler-env",
        "env.CARGO_PROFILE_RELEASE_LTO",
        "env.CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
        "env.NATIVE_OFFLINE_PREVIOUS_SHA",
        "'previous-client/rust/Cargo.toml'",
        "'previous-client/rust/Cargo.lock'",
    ):
        assert required in key
    assert "restore-keys" not in restore["with"]
    assert build["if"] == PREVIOUS_MISS
    assert build["env"]["RUSTC_WORKSPACE_WRAPPER"] == "sccache"
    assert "if" not in require
    assert "test -x rust/target/previous-client/release/guard-command-source" in require["run"]
    assert "test -x rust/target/previous-client/release/hol-guard-runtime" in require["run"]
    assert save["if"] == PREVIOUS_WRITE
    assert save["with"]["key"] == "${{ steps.previous-cache.outputs.cache-primary-key }}"
    assert steps.index(identify) < steps.index(restore) < steps.index(build) < steps.index(require) < steps.index(save)


def test_quality_action_lints_and_formats_offline_export_and_ci_cache_contracts() -> None:
    steps = composite_action_steps("ci-job-quality")
    required_paths = {
        "src/",
        "tests/test_guard_durable_io.py",
        "tests/test_guard_managed_install_context.py",
        "tests/test_guard_private_file_io.py",
        "tests/test_native_offline_cache.py",
        "tests/test_native_policy_test_support.py",
        "tests/test_ci_native_evaluator_cache.py",
    }
    for name, invocation in (
        ("Lint production sources", "python -m ruff check"),
        ("Check formatting for production sources", "python -m ruff format --check"),
    ):
        step = next(step for step in steps if step.get("name") == name)
        assert invocation in step["run"]
        assert required_paths <= set(step["run"].replace("\\", "").split())
        assert not step.get("continue-on-error", False)
