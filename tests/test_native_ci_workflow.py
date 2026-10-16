"""Preserve native artifact provenance and full qualification during CI changes."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.support.ci_workflow import expand_ci_job_actions

ROOT = Path(__file__).resolve().parents[1]


def _workflow(name: str) -> dict:
    """Load expanded workflow definitions for CI contract assertions."""
    return expand_ci_job_actions(yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")))


@pytest.mark.parametrize(
    ("ref", "event", "platform", "opt_in", "allowed"),
    [
        ("refs/heads/main", "push", "Linux", "false", True),
        ("refs/heads/main", "push", "Windows", "false", True),
        ("refs/heads/main", "schedule", "Windows", "true", True),
        ("refs/heads/main", "workflow_dispatch", "Windows", "true", True),
        ("refs/heads/main", "pull_request", "Windows", "true", False),
        ("refs/pull/3701/merge", "pull_request", "Windows", "true", False),
        ("refs/heads/contributor", "push", "Windows", "true", False),
        ("refs/heads/main-other", "workflow_dispatch", "Windows", "true", False),
        ("refs/heads/main", "schedule", "Windows", "false", False),
        ("refs/heads/main", "workflow_dispatch", "Windows", None, False),
        ("refs/heads/main", "workflow_dispatch", "macOS", "true", False),
        ("refs/heads/main", "schedule", "Linux", "true", False),
    ],
)
def test_effective_cache_write_privilege_is_limited_to_trusted_main_builds(ref, event, platform, opt_in, allowed):
    assert _cache_write_allowed(ref, event, platform, opt_in, None) is allowed


RELEASE_REF = "refs/heads/release-please--branches--main--components--hol-guard"


@pytest.mark.parametrize(
    ("ref", "event", "push_ref", "allowed"),
    [
        (RELEASE_REF, "push", RELEASE_REF, True),
        (RELEASE_REF, "push", None, False),
        (RELEASE_REF, "workflow_dispatch", RELEASE_REF, False),
        (RELEASE_REF, "pull_request", RELEASE_REF, False),
        ("refs/pull/3701/merge", "pull_request", RELEASE_REF, False),
        ("refs/heads/contributor", "push", RELEASE_REF, False),
        (RELEASE_REF + "-other", "push", RELEASE_REF, False),
        ("refs/heads/main", "push", RELEASE_REF, True),
        ("refs/heads/main", "workflow_dispatch", RELEASE_REF, False),
    ],
)
def test_named_push_ref_may_save_only_its_own_push_builds(ref, event, push_ref, allowed):
    """A caller-named branch saves only on its own pushes; PR refs and dispatches stay readers."""
    assert _cache_write_allowed(ref, event, "macOS", None, push_ref) is allowed


def test_gauntlet_runtime_builds_on_release_branch_pushes_only() -> None:
    """The qualify wheel rebuilds on every release-branch push and cancels a stale head's build."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/gauntlet-full-task-runtime.yml").read_text(encoding="utf-8"))
    triggers = workflow[True]
    assert triggers["push"] == {"branches": [RELEASE_REF.removeprefix("refs/heads/")]}
    assert "pull_request_target" not in triggers
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "group": "gauntlet-full-task-runtime-${{ github.ref }}",
        "cancel-in-progress": True,
    }
    steps = workflow["jobs"]["native-build"]["steps"]
    setup = next(step for step in steps if step.get("uses") == "./.github/actions/setup-rust")
    assert setup["with"]["save-push-ref"] == RELEASE_REF


def _cache_write_allowed(ref, event, platform, opt_in, push_ref) -> bool:
    action = yaml.safe_load((ROOT / ".github/actions/setup-rust/action.yml").read_text(encoding="utf-8"))
    cache = next(step for step in action["runs"]["steps"] if step.get("uses", "").startswith("Swatinem/"))
    if opt_in is None:
        opt_in = action["inputs"]["save-main-cache"]["default"]
    if push_ref is None:
        push_ref = action["inputs"]["save-push-ref"]["default"]
    expression = cache["with"]["save-if"].strip()[3:-2]
    for name, value in {
        "github.ref": ref,
        "github.event_name": event,
        "runner.os": platform,
        "inputs.save-main-cache": opt_in,
        "inputs.save-push-ref": push_ref,
    }.items():
        expression = expression.replace(name, repr(value))
    expression = "(" + expression.replace("&&", " and ").replace("||", " or ") + ")"
    tree = ast.parse(expression, mode="eval")
    permitted = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Eq, ast.NotEq, ast.Constant)
    assert all(isinstance(node, permitted) for node in ast.walk(tree)), "Unsupported cache-policy expression"
    return bool(eval(compile(tree, "<cache-policy>", "eval"), {"__builtins__": {}}))


def test_parallel_macos_proofs_use_this_runs_matching_platform_wheel() -> None:
    workflow = _workflow("nightly-native.yml")
    build = workflow["jobs"]["macos-build"]
    proof = workflow["jobs"]["macos-proof"]
    assert proof["needs"] == "macos-build"
    assert {item["target"] for item in build["strategy"]["matrix"]["include"]} == {
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
    }
    assert {item["target"] for item in proof["strategy"]["matrix"]["include"]} == {
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
    }
    upload = next(step for step in build["steps"] if step.get("uses", "").startswith("actions/upload-artifact@"))
    download = next(step for step in proof["steps"] if step.get("uses", "").startswith("actions/download-artifact@"))
    assert download["with"] == {"name": upload["with"]["name"]}
    assert "matrix.target" in download["with"]["name"]
    # A failed build/proof may never be turned into a green installed gate.
    for job in (build, proof):
        assert "continue-on-error" not in job
        assert all(not step.get("continue-on-error") for step in job["steps"])
    assert set(proof["strategy"]["matrix"]["proof"]) == {"default", "pi", "extensions", "performance"}


def test_macos_cross_build_keeps_native_platform_proofs_and_cache_isolation() -> None:
    """Keep Intel cross-compilation separate from native platform qualification."""
    jobs = _workflow("nightly-native.yml")["jobs"]
    build = jobs["macos-build"]
    build_targets = {item["target"]: item["runner"] for item in build["strategy"]["matrix"]["include"]}
    proof_targets = {item["target"]: item["runner"] for item in jobs["macos-proof"]["strategy"]["matrix"]["include"]}
    assert build_targets == {"x86_64-apple-darwin": "macos-15", "aarch64-apple-darwin": "macos-15"}
    assert proof_targets == {"x86_64-apple-darwin": "macos-15-intel", "aarch64-apple-darwin": "macos-15"}
    setup = next(step for step in build["steps"] if step.get("uses") == "./.github/actions/setup-rust")
    assert setup["with"]["targets"] == "${{ matrix.target == 'x86_64-apple-darwin' && matrix.target || '' }}"
    commands = (ROOT / "scripts/ci/build-native-wheel-macos.sh").read_text(encoding="utf-8")
    assert any(step.get("run") == "bash scripts/ci/build-native-wheel-macos.sh" for step in build["steps"])
    assert '--target "$TARGET"' in commands
    assert 'target_dir="$target_dir/$TARGET"' in commands
    assert "--locked --release" in commands
    assert '--platform-tag "$PLATFORM_TAG"' in commands
    assert '--source-sha "$HOL_GUARD_BUILD_SHA"' in commands


@pytest.mark.skipif(os.name == "nt", reason="macOS wheel builds execute in Bash")
@pytest.mark.skipif(sys.version_info < (3, 11), reason="Native wheel workflow uses Python 3.12 with tomllib")
@pytest.mark.parametrize("target", ["x86_64-apple-darwin", "aarch64-apple-darwin"])
@pytest.mark.parametrize("failed_stage", ["cargo", "self-test", "capabilities"])
def test_macos_build_failures_stop_before_packaging(tmp_path: Path, target: str, failed_stage: str) -> None:
    """Run the workflow's build command and reject each failed native build stage."""
    job = _workflow("nightly-native.yml")["jobs"]["macos-build"]
    commands = next(step["run"] for step in job["steps"] if step.get("name", "").startswith("Build and assemble"))
    (tmp_path / "pyproject.toml").write_text('[project]\nversion="1.2.3"\n', encoding="utf-8")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    (binaries / "python").symlink_to(sys.executable)
    cargo = binaries / "cargo"
    cargo.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$@" > cargo-arguments\nif [ "$FAILED_STAGE" = cargo ]; then exit 19; fi\n',
        encoding="utf-8",
    )
    cargo.chmod(0o755)
    output = tmp_path / "rust/target"
    if target == "x86_64-apple-darwin":
        output /= target
    runtime = output / "release/hol-guard-runtime"
    runtime.parent.mkdir(parents=True)
    runtime.write_text(
        '#!/bin/sh\nif [ "$1" = "$FAILED_STAGE" ]; then exit 23; fi\nprintf \'{"rule_digest":"fixture-digest"}\\n\'\n',
        encoding="utf-8",
    )
    runtime.chmod(0o755)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    build_helper = scripts / "ci/build-native-wheel-macos.sh"
    build_helper.parent.mkdir()
    build_helper.write_text(
        (ROOT / "scripts/ci/build-native-wheel-macos.sh").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (scripts / "build_native_hol_guard_wheel.py").write_text(
        'from pathlib import Path\nPath("packaged").touch()\n', encoding="utf-8"
    )
    completed = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", commands],
        cwd=tmp_path,
        env={
            **os.environ,
            "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}",
            "TARGET": target,
            "PLATFORM_TAG": "fixture-platform",
            "HOL_GUARD_BUILD_SHA": "fixture-sha",
            "FAILED_STAGE": failed_stage,
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode != 0
    assert not (tmp_path / "packaged").exists()
    cargo_arguments = (tmp_path / "cargo-arguments").read_text(encoding="utf-8").splitlines()
    assert ("--target" in cargo_arguments) == (target == "x86_64-apple-darwin")
    if "--target" in cargo_arguments:
        assert cargo_arguments[cargo_arguments.index("--target") + 1] == target


def test_bounded_stress_never_claims_full_soak_qualification() -> None:
    workflow = _workflow("nightly-native.yml")
    assert workflow[True]["schedule"]
    assert "workflow_dispatch" in workflow[True]
    steps = workflow["jobs"]["linux-proof"]["steps"]
    full = next(step for step in steps if "--enforce-soak" in step.get("run", ""))
    smoke = next(step for step in steps if "--json native-stress-smoke.json" in step.get("run", ""))
    assert full["if"] == "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
    assert "--requests 100000" in full["run"]
    assert "--receipts 250000" in full["run"]
    assert "--json native-soak.json" in full["run"]
    assert smoke["if"] == "github.event_name != 'schedule' && github.event_name != 'workflow_dispatch'"
    assert "--enforce-soak" not in smoke["run"]
    assert "native-soak.json" not in smoke["run"]
    provenance = next(step for step in steps if "validate_release_artifacts.py" in step.get("run", ""))
    assert "if" not in provenance


def test_authority_source_and_both_distribution_formats_are_gated_together() -> None:
    workflow = _workflow("nightly-native.yml")
    calls = [
        step["run"]
        for step in workflow["jobs"]["linux-native"]["steps"]
        if "python_capability_cleanup_gate.py" in step.get("run", "")
    ]
    assert len(calls) == 1
    assert '--artifact "$BUILT_WHEEL" --artifact "$BUILT_SDIST"' in calls[0]
    assert "uv build --wheel --sdist" in calls[0]
    assert "--root ." in calls[0]


def test_windows_build_and_proof_failures_cannot_fall_through() -> None:
    for job in _workflow("nightly-native.yml")["jobs"].values():
        for step in job.get("steps", []):
            if step.get("shell") != "pwsh":
                continue
            lines = step.get("run", "").splitlines()
            if len(lines) == 1:
                continue
            for index, line in enumerate(lines):
                if line.startswith(
                    ("cargo ", "rustfmt ", "uv ", ".venv\\", ".\\rust\\", "rust/target/")
                ) and not line.endswith("`"):
                    assert lines[index + 1] == "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"


def test_parallel_windows_workspace_checks_remain_required() -> None:
    job = _workflow("nightly-native.yml")["jobs"]["native-platform"]
    assert "windows-2025" in job["strategy"]["matrix"]["os"]
    assert job["strategy"]["fail-fast"] is False
    assert "if" not in job
    assert "continue-on-error" not in job
    assert "needs" not in job
    assert all(not step.get("continue-on-error") for step in job["steps"])
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "cargo clippy --manifest-path rust/Cargo.toml --locked --workspace --all-targets -- -D warnings" in commands
    assert "cargo test --manifest-path rust/Cargo.toml --locked --workspace --all-targets" in commands
    assert "cargo build --manifest-path rust/Cargo.toml --locked --release -p hol-guard-runtime" in commands
    assert "test_native_hook_client.py" in commands
    assert "test_native_hook_client_transport.py" in commands
    assert "test_rust_daemon_edge_hardening_contracts.py" in commands
    assert "test_native_managed_resident.py" in commands


@pytest.mark.parametrize("event", ["pull_request", "push"])
def test_production_resident_stream_selects_runtime_performance(event: str) -> None:
    # BaseLoader preserves the YAML `on` key rather than interpreting it as a boolean.
    workflow = yaml.load(
        (ROOT / ".github/workflows/rust-runtime-performance.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader
    )
    assert "src/codex_plugin_scanner/guard/native_resident_stream.py" in workflow["on"][event]["paths"]
