"""Required consumers publish exact compilation archives after successful main tests."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PARTITION = "matrix.check == 'test-command' && 'command' || (matrix.check == 'test-core' && 'core' || 'runtime')"


def workflow(name):
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def named(steps, name):
    return next(step for step in steps if step.get("name") == name)


def test_required_consumers_are_the_only_test_archive_producers():
    workflows = ROOT / ".github/workflows"
    assert not (workflows / "rust-test-cache-warm.yml").exists()
    producers = {
        path.name for path in workflows.glob("*.yml") if "scripts/ci/archive_rust_tests.sh" in path.read_text()
    }
    assert producers == {"ci.yml"}
    ci = workflow("ci.yml")
    trigger = ci.get("on", ci.get(True))
    # Main consumers run on every push, rather than a warmer's source path filter.
    assert "main" in trigger["push"]["branches"]
    assert "paths" not in trigger["push"] and "paths-ignore" not in trigger["push"]
    assert "if" not in ci["jobs"]["native-workspace"]
    # Preserve active main work and coalesce obsolete pending source revisions.
    assert ci["concurrency"] == {
        "group": "ci-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}",
        "cancel-in-progress": "${{ github.ref != 'refs/heads/main' }}",
    }


def test_main_test_locks_follow_archive_families_and_leave_other_runs_independent():
    ci = workflow("ci.yml")["jobs"]["native-workspace"]
    assert ci["strategy"]["matrix"]["check"] == [
        "clippy",
        "test-core",
        "test-command",
        "test-runtime-1",
        "test-runtime-2",
    ]
    assert ci["strategy"]["fail-fast"] is False
    assert ci["concurrency"]["queue"] == "max"
    assert ci["concurrency"]["cancel-in-progress"] is False
    group = ci["concurrency"]["group"]
    assert "github.event_name == 'push' && github.ref == 'refs/heads/main' && matrix.check != 'clippy' &&" in group
    # The same selector binds lock identity and the exact archive family. Both
    # runtime shards use runtime, while distinct source SHAs remain independent.
    assert f"format('trusted-rust-tests-{{0}}-{{1}}', github.sha, {PARTITION})" in group
    restore = named(ci["steps"], "Restore exact runtime test executables")
    assert restore["with"]["partition"] == "${{ " + PARTITION + " }}"
    assert "|| format('rust-workspace-{0}-{1}-{2}', github.run_id, github.run_attempt, matrix.check)" in group
    validate = named(ci["steps"], "Validate the locked Rust workspace")["run"]
    assert 'nextest_args+=(--partition "hash:${CARGO_CHECK##*-}/2")' in validate
    assert "--test-threads 4 --retries 0 --no-fail-fast" in validate
    assert "--workspace-remap" in validate and "--profile ci" in validate


def test_consumers_keep_the_checked_profile_and_main_only_compiler_cache_writes():
    ci = workflow("ci.yml")
    steps = ci["jobs"]["native-workspace"]["steps"]
    assert ci["env"]["CARGO_PROFILE_RELEASE_LTO"] == "false"
    assert ci["env"]["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"] == "16"
    profile = named(steps, "Configure the checked test profile")
    assert profile["if"] == "matrix.check != 'clippy'"
    for setting in (
        "CARGO_PROFILE_TEST_OPT_LEVEL=1",
        "CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true",
        "CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true",
        "CARGO_PROFILE_TEST_DEBUG=line-tables-only",
    ):
        assert setting in profile["run"]
    setup = next(step for step in steps if step.get("uses") == "./.github/actions/setup-rust")
    assert setup["with"]["cache-key"] == "ci-workspace-${{ matrix.check }}"
    assert setup["with"]["normalize-toolchains"] == "true"
    install = named(steps, "Install content-addressed compiler cache")
    assert install["with"] == {"version": "v0.18.0"}
    route = named(steps, "Route workspace crates through the compiler cache")
    assert route["env"] == {
        "SCCACHE_MODE": (
            "${{ (github.event_name == 'push' && github.ref == 'refs/heads/main') && 'READ_WRITE' || 'READ_ONLY' }}"
        )
    }
    assert "SCCACHE_GHA_VERSION=ci-workspace-test" in route["run"]
    assert "RUSTC_WORKSPACE_WRAPPER=$wrapper" in route["run"]
    for name in (
        "Install content-addressed compiler cache",
        "Route workspace crates through the compiler cache",
        "Check compiler cache readiness",
        "Provision the Linux test linker",
    ):
        assert named(steps, name)["if"] == (
            "matrix.check != 'clippy' && steps.runtime-archive.outputs.cache-hit != 'true'"
        )
    assert named(steps, "Provision the Linux test linker")["run"] == "bash scripts/ci/setup_test_linker.sh"


def test_either_runtime_partition_can_publish_only_a_successful_main_push_miss():
    steps = workflow("ci.yml")["jobs"]["native-workspace"]["steps"]
    archive = named(steps, "Archive the complete runtime test build")
    validate = named(steps, "Validate the locked Rust workspace")
    save = named(steps, "Save successful runtime test compilation")
    guard = (
        "matrix.check != 'clippy' && "
        "steps.runtime-archive.outputs.cache-hit != 'true' && "
        "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    )
    for step in (archive, save):
        # Implicit success() must remain: neither an archive failure nor a test
        # failure may publish a cache, and PRs/cache hits stay read-only.
        assert " ".join(step["if"].split()) == guard
        assert step.get("continue-on-error", False) is False
    assert validate.get("continue-on-error", False) is False
    assert steps.index(archive) < steps.index(validate) < steps.index(save)
    assert archive["run"] == 'bash scripts/ci/archive_rust_tests.sh "$CARGO_CHECK"'
    assert save["with"] == {
        "path": "${{ runner.temp }}/runtime-test-archive.tar.zst",
        "key": "${{ steps.runtime-archive.outputs.cache-primary-key }}",
    }


@pytest.fixture
def recipe(tmp_path):
    binaries = tmp_path / "bin"
    binaries.mkdir()
    for name, source in {
        "python3": '#!/bin/bash\n[[ "$*" == scripts/ci/install_nextest.py ]] || exit 90\nprintf "%s\\n" "$FAKE_BIN"\n',
        "cargo": (
            '#!/bin/bash\nprintf "%s\\n" "$@" > "$ARGS"\n'
            '[[ "${CARGO_STATUS:-0}" == 0 ]] || exit "$CARGO_STATUS"\n'
            'printf new > "$RUNNER_TEMP/runtime-test-archive.tar.zst"\n'
        ),
    }.items():
        path = binaries / name
        path.write_text(source)
        path.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{binaries}:{os.environ['PATH']}",
        "FAKE_BIN": str(binaries),
        "RUNNER_TEMP": str(tmp_path),
        "ARGS": str(tmp_path / "args"),
    }

    def run(part, **extra):
        return subprocess.run(
            ["bash", str(ROOT / "scripts/ci/archive_rust_tests.sh"), part],
            env={**env, **extra},
            capture_output=True,
            text=True,
            check=False,
        )

    return tmp_path, run


@pytest.mark.parametrize(
    "part,selection",
    [
        (part, selection)
        for aliases, selection in (
            (("core", "test-core"), ["--workspace", "--exclude", "guard-command", "--exclude", "hol-guard-runtime"]),
            (("command", "test-command"), ["--package", "guard-command"]),
            (("runtime", "test-runtime-1", "test-runtime-2"), ["--package", "hol-guard-runtime"]),
        )
        for part in aliases
    ],
)
def test_archive_recipe_builds_all_selected_targets_and_replaces_only_its_staging_file(recipe, part, selection):
    temporary, run = recipe
    archive = temporary / "runtime-test-archive.tar.zst"
    archive.write_text("previous partition")
    unrelated = temporary / "keep"
    unrelated.write_text("keep")
    assert run(part).returncode == 0
    assert (temporary / "args").read_text().splitlines() == [
        "nextest",
        "archive",
        "--manifest-path",
        "rust/Cargo.toml",
        "--locked",
        *selection,
        "--all-targets",
        "--archive-file",
        str(archive),
        "--zstd-level",
        "1",
        "--timings",
    ]
    assert archive.read_text() == "new" and unrelated.read_text() == "keep"


@pytest.mark.parametrize("part", ["clippy", "unknown"])
def test_archive_recipe_rejects_unsupported_selections_before_running_tools(recipe, part):
    temporary, run = recipe
    assert run(part).returncode == 64
    assert not (temporary / "args").exists()


def test_archive_recipe_fails_closed_for_symlinks_and_failed_compilation(recipe):
    temporary, run = recipe
    archive = temporary / "runtime-test-archive.tar.zst"
    target = temporary / "keep"
    target.write_text("keep")
    archive.symlink_to(target)
    assert run("core").returncode == 64
    assert target.read_text() == "keep" and not (temporary / "args").exists()
    archive.unlink()
    assert run("core", CARGO_STATUS="23").returncode == 23
    assert not archive.exists()
