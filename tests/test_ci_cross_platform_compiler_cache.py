"""The macOS runtime build must reuse content-addressed objects."""

from __future__ import annotations

from tests.support.ci_workflow import composite_action_steps, step_index


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
