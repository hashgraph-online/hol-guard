"""The macOS runtime build must reuse content-addressed objects."""

from __future__ import annotations

from tests.support.ci_workflow import composite_action_steps, load_ci_workflow, step_index


def test_runtime_builds_run_after_the_compiler_cache_is_routed() -> None:
    steps = composite_action_steps("ci-job-macos-native-runtime")
    routed = step_index(steps, "Route the runtime build through the compiler cache")
    assert step_index(steps, "Install content-addressed compiler cache") < routed
    assert routed < step_index(steps, "Build the macOS native runtime")
    script = steps[routed]["run"]
    assert "RUSTC_WRAPPER=sccache" in script
    assert "SCCACHE_GHA_VERSION=cross-platform-runtime" in script


def test_only_main_pushes_write_the_cross_platform_compiler_cache() -> None:
    steps = composite_action_steps("ci-job-macos-native-runtime")
    step = steps[step_index(steps, "Route the runtime build through the compiler cache")]
    assert step["env"]["SCCACHE_MODE"] == (
        "${{ (github.event_name == 'push' && github.ref == 'refs/heads/main') && 'READ_WRITE' || 'READ_ONLY' }}"
    )
    assert "SCCACHE_GHA_RW_MODE=${SCCACHE_MODE}" in step["run"]


def test_runtime_cache_preserves_the_optimized_profile_and_cold_build_allowance() -> None:
    workflow = load_ci_workflow()
    assert "CARGO_PROFILE_RELEASE_OPT_LEVEL" not in workflow["env"]
    # Cold crate-graph builds on this stack measure ~19 min on macOS (PRs read
    # the compiler cache read-only until main seeds new crates), so the macOS
    # allowance is 25 while Windows still fits 15.
    allowances = {"macos-native-runtime": 25, "windows-native-runtime": 15}
    for name, allowance in allowances.items():
        job = workflow["jobs"][name]
        assert job["timeout-minutes"] == allowance
        assert "CARGO_PROFILE_RELEASE_OPT_LEVEL" not in job.get("env", {})
    assert "CARGO_PROFILE_RELEASE_OPT_LEVEL" not in workflow["jobs"]["native-command-evaluators"].get("env", {})
    assert "macos-native-runtime" in workflow["jobs"]["required"]["needs"]
    assert "windows-native-runtime" in workflow["jobs"]["required"]["needs"]


def test_macos_runtime_cache_requires_all_inputs_and_only_main_can_save() -> None:
    steps = composite_action_steps("ci-job-macos-native-runtime")
    restore = next(step for step in steps if step.get("id") == "runtime-cache")
    setup = next(step for step in steps if step.get("uses") == "./.github/actions/setup-rust")
    stage = next(step for step in steps if step.get("name") == "Stage trust bindings the native build embeds")
    platform = next(step for step in steps if step.get("id") == "runtime-platform")
    assert steps.index(stage) < steps.index(restore) < steps.index(setup)
    assert steps.index(platform) < steps.index(restore)
    assert "scripts.ci.native_cache_environment" in platform["run"]
    assert "restore-keys" not in restore["with"]
    for token in (
        "runner.arch", "steps.runtime-platform.outputs.image", "steps.runtime-platform.outputs.compiler-env",
        "env.CARGO_PROFILE_RELEASE_LTO", "env.CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
        "'rust/**'", "'contributions/**'", "'contracts/**'", "'spec/**'",
        "'src/codex_plugin_scanner/guard/contracts/**'",
        "'.github/actions/setup-rust/action.yml'",
        "'.github/actions/ci-job-macos-native-runtime/action.yml'", "'.cargo/**'",
        "'scripts/ci/native_cache_environment.py'", "'scripts/refresh_extension_artifacts.py'",
    ):
        assert token in restore["with"]["key"]
    assert "'.github/workflows/ci.yml'" not in restore["with"]["key"]
    miss = "steps.runtime-cache.outputs.cache-hit != 'true'"
    assert setup["if"] == miss
    for name in (
        "Install content-addressed compiler cache", "Route the runtime build through the compiler cache",
        "Build the macOS native runtime",
    ):
        assert next(step for step in steps if step.get("name") == name)["if"] == miss
    build = next(step for step in steps if step.get("name") == "Build the macOS native runtime")
    assert "--config" not in build["run"]
    save = next(step for step in steps if step.get("name") == "Save the macOS native runtime cache")
    assert save["if"] == f"{miss} && github.event_name == 'push' && github.ref == 'refs/heads/main'"
    assert save["with"]["key"] == "${{ steps.runtime-cache.outputs.cache-primary-key }}"
    upload = next(step for step in steps if step.get("name") == "Upload the macOS native runtime")
    assert "if" not in upload
    assert upload["with"]["if-no-files-found"] == "error"
    assert restore["with"]["path"] == save["with"]["path"] == upload["with"]["path"]
    assert steps.index(build) < steps.index(save) < steps.index(upload)
