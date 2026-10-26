"""Keep the macOS skill-identity lane bound to its CI-built runtime."""

from __future__ import annotations

import ast
import re

from tests.support.ci_workflow import composite_action_steps, load_ci_workflow, step_index

RUNTIME_ACTION = "ci-job-macos-native-runtime"


def _pytest_files(step: dict) -> list[str]:
    """List the test files a pytest run step exercises, in order."""
    return re.findall(r"tests/test_[a-z0-9_]*\.py", step.get("run", ""))


def test_macos_native_runtime_builds_early_and_publishes_the_binary() -> None:
    """Build the macOS runtime off the evaluator critical path and publish it."""
    job = load_ci_workflow()["jobs"]["macos-native-runtime"]
    needs = job["needs"] if isinstance(job["needs"], list) else [job["needs"]]
    assert needs == ["plan"]
    assert job["runs-on"] == "macos-latest"
    steps = composite_action_steps(RUNTIME_ACTION)
    setup_rust = next(i for i, step in enumerate(steps) if step.get("uses") == "./.github/actions/setup-rust")
    routed = step_index(steps, "Route the runtime build through the compiler cache")
    build = step_index(steps, "Build the macOS native runtime")
    assert step_index(steps, "Stage trust bindings the native build embeds") < setup_rust < routed < build
    assert "cargo build --manifest-path rust/Cargo.toml --locked --release -p hol-guard-runtime" in steps[build]["run"]
    upload = next(step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert upload["with"]["name"] == "macos-native-runtime"
    assert upload["with"]["path"] == "rust/target/release/hol-guard-runtime"


def test_macos_skill_identity_consumes_the_ci_runtime() -> None:
    """Bind the identity lane to the downloaded runtime and matching test list."""
    job = load_ci_workflow()["jobs"]["macos-skill-identity"]
    needs = job["needs"] if isinstance(job["needs"], list) else [job["needs"]]
    assert "native-command-evaluators" in needs
    assert "macos-native-runtime" in needs
    steps = job["steps"]
    download = next(
        step
        for step in steps
        if step.get("uses", "").startswith("actions/download-artifact@")
        and step.get("with", {}).get("name") == "macos-native-runtime"
    )
    assert download["with"]["path"] == "${{ runner.temp }}/hol-guard-native-runtime"
    expose = step_index(steps, "Expose the CI-built macOS runtime")
    assert "chmod 0755" in steps[expose]["run"]
    assert "HOL_GUARD_NATIVE_BINARY=$RUNNER_TEMP/hol-guard-native-runtime/hol-guard-runtime" in steps[expose]["run"]
    assert "HOL_GUARD_NATIVE_REGRESSION=1" in steps[expose]["run"]
    regression = step_index(steps, "Run macOS skill-directory identity regressions")
    assert expose < regression
    windows_step = next(
        step
        for step in load_ci_workflow()["jobs"]["cross-platform"]["steps"]
        if step.get("name") == "Run cross-platform skill-directory identity regressions"
    )
    windows_files = _pytest_files(windows_step)
    macos_files = _pytest_files(steps[regression])
    # Adapter and AIBOM discovery run in the native resident, which only the
    # macOS lane builds; every other file must match the Windows lane exactly.
    native_only = {
        "tests/test_gemini_adapter.py",
        "tests/test_gemini_skill_directory_identity.py",
        "tests/test_antigravity_adapter.py",
        "tests/test_guard_aibom_detection.py",
        "tests/test_guard_aibom_skill_directory_identity.py",
    }
    assert windows_files != []
    assert [name for name in macos_files if name not in native_only] == windows_files
    assert native_only <= set(macos_files)


def test_required_aggregate_includes_the_macos_native_lane() -> None:
    """Require both new macOS jobs in the needs graph and the lane-gated set."""
    workflow = load_ci_workflow()
    required = workflow["jobs"]["required"]
    assert "macos-native-runtime" in required["needs"]
    assert "macos-skill-identity" in required["needs"]
    assert "macos-gates" in required["needs"]
    run = "\n".join(step.get("run", "") for step in required["steps"])
    lane_gated = re.search(r"required\s*=\s*(\[[^]]*\])", run)
    assert lane_gated is not None
    gated = ast.literal_eval(lane_gated.group(1))
    assert "macos-native-runtime" in gated
    assert "macos-skill-identity" in gated
    assert "macos-gates" in gated


def test_macos_gates_run_the_benign_and_replay_gates_on_the_ci_runtime() -> None:
    """Run the false-positive gates against the macOS runtime, not only on Linux."""
    job = load_ci_workflow()["jobs"]["macos-gates"]
    needs = job["needs"] if isinstance(job["needs"], list) else [job["needs"]]
    assert {"native-command-evaluators", "macos-native-runtime"} <= set(needs)
    steps = job["steps"]
    expose = step_index(steps, "Expose the CI-built macOS runtime")
    gates = step_index(steps, "Benign false-positive and Gauntlet replay gates on macOS")
    assert expose < gates
    assert set(_pytest_files(steps[gates])) == {
        "tests/test_guard_benign_false_positive_gate.py",
        "tests/test_guard_gauntlet_replay_gate.py",
        "tests/test_guard_command_corpus_benign_allow.py",
    }
