"""Trusted warming may reuse builds, never required test results or PR writes."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.ci.rust_test_archive_inputs import EXTERNAL_ROOTS

ROOT = Path(__file__).resolve().parents[1]
MISS = " || ".join(f"steps.{part}.outputs.cache-hit != 'true'" for part in ("core", "command", "runtime"))


def workflow(name):
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def named(steps, name):
    return next(step for step in steps if step.get("name") == name)


def test_warming_has_one_trusted_runner_and_covers_every_shared_input():
    warm = workflow("rust-test-cache-warm.yml")
    trigger = warm.get("on", warm.get(True))
    assert set(trigger) == {"push"}
    assert trigger["push"]["branches"] == ["main"]
    paths = set(trigger["push"]["paths"])
    assert {f"{root}/**" for root in EXTERNAL_ROOTS} <= paths
    assert {"rust/**", ".github/workflows/ci.yml", ".github/workflows/rust-test-cache-warm.yml"} <= paths
    assert warm["permissions"] == {"actions": "read", "contents": "read"}
    assert set(warm["jobs"]) == {"warm"}
    job = warm["jobs"]["warm"]
    assert "strategy" not in job and "needs" not in job
    assert job["if"] == "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    assert job["runs-on"] == "ubuntu-latest"
    # Coalesce obsolete pending warm revisions, never active/required work.
    assert warm["concurrency"] == {"group": "trusted-rust-test-warm-main", "cancel-in-progress": False}
    assert not any("producer" in step.get("uses", "") for step in job["steps"])


def test_main_test_locks_queue_consumers_but_pr_and_clippy_groups_are_unique():
    ci = workflow("ci.yml")["jobs"]["native-workspace"]
    warm = workflow("rust-test-cache-warm.yml")["jobs"]["warm"]
    assert ci["strategy"]["matrix"]["check"] == [
        "clippy",
        "test-core",
        "test-command",
        "test-runtime-1",
        "test-runtime-2",
    ]
    assert ci["strategy"]["fail-fast"] is False
    for job in (ci, warm):
        assert job["concurrency"]["queue"] == "max"
        assert job["concurrency"]["cancel-in-progress"] is False
        assert "format('trusted-rust-tests-{0}', github.sha)" in job["concurrency"]["group"]
    group = ci["concurrency"]["group"]
    assert "github.ref == 'refs/heads/main' && matrix.check != 'clippy' &&" in group
    assert "|| format('rust-workspace-{0}-{1}-{2}', github.run_id, github.run_attempt, matrix.check)" in group
    validate = named(ci["steps"], "Validate the locked Rust workspace")["run"]
    assert 'nextest_args+=(--partition "hash:${CARGO_CHECK##*-}/2")' in validate
    assert "--test-threads 4 --retries 0 --no-fail-fast" in validate
    assert "--workspace-remap" in validate and "--profile ci" in validate


def test_warmer_uses_the_consumer_profile_wrapper_linker_and_cache_namespace():
    ci = workflow("ci.yml")
    warm = workflow("rust-test-cache-warm.yml")
    consumers = ci["jobs"]["native-workspace"]["steps"]
    steps = warm["jobs"]["warm"]["steps"]
    assert warm["env"] == {key: ci["env"][key] for key in warm["env"]}
    for name in (
        "Configure the checked test profile",
        "Route workspace crates through the compiler cache",
        "Check compiler cache readiness",
        "Provision the Linux test linker",
    ):
        assert named(steps, name)["run"] == named(consumers, name)["run"]
    setup = next(step for step in steps if step.get("uses") == "./.github/actions/setup-rust")
    assert setup["if"] == MISS
    assert setup["with"] == {
        "cache-key": "ci-workspace-test",
        "cache-fallback-key": "ci-workspace-test-runtime-1",
        "components": "clippy",
        "normalize-toolchains": "true",
    }
    install = named(steps, "Install content-addressed compiler cache")
    assert install["uses"] == named(consumers, install["name"])["uses"]
    assert install["with"] == {"version": "v0.18.0"}
    assert named(steps, "Route workspace crates through the compiler cache")["env"] == {"SCCACHE_MODE": "READ_WRITE"}
    for name in (
        "Install content-addressed compiler cache",
        "Route workspace crates through the compiler cache",
        "Check compiler cache readiness",
        "Provision the Linux test linker",
    ):
        assert named(steps, name)["if"] == MISS


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


def test_each_missed_archive_is_built_then_saved_at_the_consumer_cache_version_path():
    steps = workflow("rust-test-cache-warm.yml")["jobs"]["warm"]["steps"]
    consumer = named(
        workflow("ci.yml")["jobs"]["native-workspace"]["steps"], "Save successful runtime test compilation"
    )
    setup_index = next(index for index, step in enumerate(steps) if step.get("uses") == "./.github/actions/setup-rust")
    prior_save = setup_index
    for part in ("core", "command", "runtime"):
        restore = next(step for step in steps if step.get("id") == part)
        assert restore["uses"] == "./.github/actions/restore-runtime-tests"
        assert restore["with"] == {"partition": part}
        assert steps.index(restore) < setup_index
        build = named(steps, f"Archive complete {part} test compilation")
        save = named(steps, f"Save exact {part} test compilation")
        assert prior_save < steps.index(build) < steps.index(save)
        assert build["run"] == f"bash scripts/ci/archive_rust_tests.sh {part}"
        assert build["if"] == save["if"] == f"steps.{part}.outputs.cache-hit != 'true'"
        assert save["uses"] == consumer["uses"]
        assert save["with"] == {
            "path": consumer["with"]["path"],
            "key": "${{ steps." + part + ".outputs.cache-primary-key }}",
        }
        prior_save = steps.index(save)


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
