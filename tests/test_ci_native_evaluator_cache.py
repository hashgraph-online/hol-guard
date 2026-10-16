"""Exact native reuse must retain formatting, source verification and both binaries."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from tests.support.ci_workflow import composite_action_steps

MISS = "steps.evaluator-cache.outputs.cache-hit != 'true'"
WRITE = f"{MISS} && github.event_name == 'push' && github.ref == 'refs/heads/main'"


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
    formatting = next(step for step in steps if step.get("name") == "Check native formatting before compilation")
    binaries = next(step for step in steps if step.get("name") == "Require both executable native evaluators")
    verify = next(
        step for step in steps if step.get("name") == "Verify generated native command catalogs before pytest fan-out"
    )
    assert all("if" not in step for step in (stage, formatting, binaries, verify))
    assert steps.index(stage) < steps.index(restore) < steps.index(formatting) < steps.index(binaries)
    assert steps.index(binaries) < steps.index(verify) < steps.index(save)
    assert 'rustup toolchain install "$toolchain" --profile minimal --component rustfmt' in formatting["run"]
    assert "verify_native_command_program.py" in verify["run"]


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
