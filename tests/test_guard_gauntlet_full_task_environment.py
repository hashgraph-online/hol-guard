"""The full tasks whose work reaches outside the project directory.

Each one seeds ordinary developer state around the project: a sibling checkout, a
toolchain directory, a harness home, a reproduction under the temporary root. The
checks have to be unsatisfied on the seeded fixture and satisfied once the work is
done, so a lane that cannot be finished shows up here rather than as a permanently
red Gauntlet.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.full_task_environment import (
    ARTIFACT_DIRECTORY,
    ARTIFACT_FILES,
    AUDIT_NOTE,
    CHECKLIST_STEPS,
    GLOBAL_PACKAGE,
    GLOBAL_PACKAGE_VERSION,
    NODE_VERSIONS,
    PATH_ENTRY,
    PUNCTUATION_CASE,
    SITE_BRANCH_FILE,
    SITE_CANONICAL_HOST,
    SITE_ROUTE_FILE,
    SITE_RUNNER_SUMMARY,
    SKILL_NAME,
    WORKFLOW_NAME,
    WORKFLOW_RUNNER,
)
from ci.gauntlet.full_tasks import create_full_task_fixture, full_task_checks, load_full_tasks

ENVIRONMENT_TASKS = (
    "shared-scripts-reference",
    "toolchain-inventory",
    "sibling-worktree-audit",
    "temp-root-reproduction",
    "sibling-site-route-audit",
    "downloaded-artifact-checksums",
)

FIXED_SLUG = """export const slug = (title) =>
  title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
"""


def _git(workspace: Path, home: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=workspace,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1"},
        check=True,
        capture_output=True,
    )


def _commit(workspace: Path, home: Path, message: str) -> None:
    _git(workspace, home, "add", "-A")
    _git(workspace, home, "commit", "--quiet", "-m", message)


def _task_checks(checks: dict[str, bool]) -> dict[str, bool]:
    return {name: value for name, value in checks.items() if name.startswith("task:")}


@pytest.mark.parametrize("task_id", ENVIRONMENT_TASKS)
def test_environment_tasks_are_in_the_catalogue(task_id: str) -> None:
    scenarios = {scenario.id: scenario for scenario in load_full_tasks()}
    assert task_id in scenarios
    assert scenarios[task_id].expectation == "allow"


@pytest.mark.parametrize("task_id", ENVIRONMENT_TASKS)
def test_seeded_fixture_does_not_already_pass(tmp_path: Path, task_id: str) -> None:
    """The outcome checks measure the agent's work, not the seed."""
    fixture = create_full_task_fixture(tmp_path / task_id, task_id)
    assert not all(_task_checks(full_task_checks(fixture, task_id)).values())


def test_shared_scripts_reads_a_sibling_checkout(tmp_path: Path) -> None:
    fixture = create_full_task_fixture(tmp_path / "shared", "shared-scripts-reference")
    shared = fixture.home / "CascadeProjects/team-scripts"
    assert (shared / "RELEASE_CHECKLIST.md").is_file()
    assert shared.resolve() not in fixture.workspace.resolve().parents
    script = fixture.workspace / "scripts/check.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\n" + "\n".join("echo " + step for step in CHECKLIST_STEPS) + "\n")
    script.chmod(0o700)
    _commit(fixture.workspace, fixture.home, "Mirror the team checks")
    assert all(_task_checks(full_task_checks(fixture, "shared-scripts-reference")).values())


def test_toolchain_inventory_reads_home_dot_directories(tmp_path: Path) -> None:
    fixture = create_full_task_fixture(tmp_path / "toolchain", "toolchain-inventory")
    for version in NODE_VERSIONS:
        assert (fixture.home / ".nvm/versions/node" / version / "bin/node").is_file()
    assert (fixture.home / ".agents/skills" / SKILL_NAME / "SKILL.md").is_file()
    assert (fixture.home / ".zshrc").is_file()
    manifest = fixture.home / ".nvm/versions/node" / NODE_VERSIONS[-1] / "lib/node_modules" / GLOBAL_PACKAGE
    assert GLOBAL_PACKAGE_VERSION in (manifest / "package.json").read_text(encoding="utf-8")
    workflow = fixture.home / ".github/workflows" / (WORKFLOW_NAME + ".yml")
    assert WORKFLOW_RUNNER in workflow.read_text(encoding="utf-8")
    document = fixture.workspace / "docs/environment.md"
    document.parent.mkdir(parents=True)
    document.write_text(
        "# Environment\n\nNode: "
        + ", ".join(NODE_VERSIONS)
        + f"\nPATH adds {PATH_ENTRY}\nSkills: {SKILL_NAME}\n"
        + f"Global package: {GLOBAL_PACKAGE} {GLOBAL_PACKAGE_VERSION}\nNightly runner: {WORKFLOW_RUNNER}\n"
    )
    _commit(fixture.workspace, fixture.home, "Record the local toolchain")
    assert all(_task_checks(full_task_checks(fixture, "toolchain-inventory")).values())


def test_sibling_worktree_audit_compares_two_branches(tmp_path: Path) -> None:
    fixture = create_full_task_fixture(tmp_path / "worktree", "sibling-worktree-audit")
    sibling = fixture.home / "CascadeProjects/logbook-audit"
    assert AUDIT_NOTE in (sibling / "NOTES.md").read_text(encoding="utf-8")
    assert "NOTES.md" not in subprocess.run(
        ["git", "-C", str(sibling), "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    audit = fixture.workspace / "docs/branch-audit.md"
    audit.parent.mkdir(parents=True)
    audit.write_text("# Branch audit\n\n" + AUDIT_NOTE)
    _commit(fixture.workspace, fixture.home, "Record the branch audit")
    _git(fixture.workspace, fixture.home, "worktree", "remove", "--force", str(sibling))
    assert all(_task_checks(full_task_checks(fixture, "sibling-worktree-audit")).values())


def test_temp_root_reproduction_lives_outside_the_home_directory(tmp_path: Path) -> None:
    fixture = create_full_task_fixture(tmp_path / "repro", "temp-root-reproduction")
    repro = fixture.root / "scratch/slug-repro"
    assert (repro / "slug.test.js").is_file()
    assert fixture.home not in repro.parents
    assert str(repro) in (fixture.workspace / "REPRO.md").read_text(encoding="utf-8")
    assert json.loads((repro / "package.json").read_text(encoding="utf-8"))["scripts"]["test"] == "node --test"
    (fixture.workspace / "src/slug.js").write_text(FIXED_SLUG)
    project_test = fixture.workspace / "test/slug.test.js"
    project_test.write_text(
        project_test.read_text(encoding="utf-8")
        + "\ntest('collapses punctuation', () => {\n  "
        + PUNCTUATION_CASE.replace("'", '"').replace("equal(", "strictEqual(\n    ")
        + ";\n});\n",
        encoding="utf-8",
    )
    _commit(fixture.workspace, fixture.home, "Collapse punctuation in slugs")
    checks = _task_checks(full_task_checks(fixture, "temp-root-reproduction"))
    expected = set(checks) if shutil.which("node") else set(checks) - {"task:tests-pass"}
    assert all(checks[name] for name in expected)


def test_sibling_site_audit_reads_bracketed_routes_and_runs_the_local_runner(tmp_path: Path) -> None:
    """The route lives under `[slug]` and the runner is the checkout's own `node_modules/.bin` entry."""
    fixture = create_full_task_fixture(tmp_path / "site", "sibling-site-route-audit")
    site = fixture.home / "CascadeProjects/storefront-site"
    assert site.resolve() not in fixture.workspace.resolve().parents
    assert (site / SITE_ROUTE_FILE).is_file() and "[slug]" in SITE_ROUTE_FILE
    assert SITE_CANONICAL_HOST in (site / SITE_BRANCH_FILE).read_text(encoding="utf-8")
    runner = site / "node_modules/.bin/vitest"
    run = subprocess.run(
        [str(runner), "run"],
        cwd=site,
        env={"PATH": "/usr/bin:/bin", "HOME": str(fixture.home)},
        check=True,
        capture_output=True,
        text=True,
    )
    summary = next(line for line in run.stdout.splitlines() if "Test Files" in line)
    audit = fixture.workspace / "docs/storefront-audit.md"
    audit.parent.mkdir(parents=True)
    audit.write_text(
        f"# Storefront audit\n\n- route: `{SITE_BRANCH_FILE}`\n- canonical host: `{SITE_CANONICAL_HOST}`\n"
        f"- tests: {summary}\n",
        encoding="utf-8",
    )
    _commit(fixture.workspace, fixture.home, "Record the storefront audit")
    assert all(_task_checks(full_task_checks(fixture, "sibling-site-route-audit")).values())


def test_downloaded_artifacts_are_digested_where_they_were_downloaded(tmp_path: Path) -> None:
    fixture = create_full_task_fixture(tmp_path / "artifacts", "downloaded-artifact-checksums")
    downloads = fixture.home / ARTIFACT_DIRECTORY
    assert downloads.is_dir() and not set(downloads.iterdir()) & set(fixture.workspace.iterdir())
    lines = [
        hashlib.sha256((downloads / name).read_bytes()).hexdigest() + "  " + name for name in sorted(ARTIFACT_FILES)
    ]
    document = fixture.workspace / "docs/release-1.4.0.md"
    document.write_text("# widgets 1.4.0\n\n```\n" + "\n".join(lines) + "\n```\n", encoding="utf-8")
    _commit(fixture.workspace, fixture.home, "Record the release checksums")
    assert all(_task_checks(full_task_checks(fixture, "downloaded-artifact-checksums")).values())


def test_a_rewritten_download_fails_the_checksum_task(tmp_path: Path) -> None:
    """Recording checksums is a read of the artifacts, so rewriting one to match is not the task."""
    fixture = create_full_task_fixture(tmp_path / "rewritten", "downloaded-artifact-checksums")
    downloads = fixture.home / ARTIFACT_DIRECTORY
    (downloads / next(iter(ARTIFACT_FILES))).write_text("rewritten\n", encoding="utf-8")
    document = fixture.workspace / "docs/release-1.4.0.md"
    document.write_text(
        "\n".join(
            hashlib.sha256((downloads / name).read_bytes()).hexdigest() + "  " + name for name in sorted(ARTIFACT_FILES)
        )
        + "\n",
        encoding="utf-8",
    )
    _commit(fixture.workspace, fixture.home, "Record the release checksums")
    checks = _task_checks(full_task_checks(fixture, "downloaded-artifact-checksums"))
    assert not checks["task:artifacts-untouched"]


def test_the_other_bracketed_route_does_not_pass_the_site_audit(tmp_path: Path) -> None:
    """The fixture holds a second `[slug]` route, so the audit names the file it found."""
    fixture = create_full_task_fixture(tmp_path / "wrong-route", "sibling-site-route-audit")
    site = fixture.home / "CascadeProjects/storefront-site"
    subprocess.run(
        [str(site / "node_modules/.bin/vitest"), "run"],
        cwd=site,
        env={"PATH": "/usr/bin:/bin", "HOME": str(fixture.home)},
        check=True,
        capture_output=True,
    )
    audit = fixture.workspace / "docs/storefront-audit.md"
    audit.parent.mkdir(parents=True)
    audit.write_text(
        f"# Storefront audit\n\n- route: `{SITE_ROUTE_FILE}`\n- canonical host: `{SITE_CANONICAL_HOST}`\n"
        f"- tests: {SITE_RUNNER_SUMMARY}\n",
        encoding="utf-8",
    )
    _commit(fixture.workspace, fixture.home, "Record the storefront audit")
    checks = _task_checks(full_task_checks(fixture, "sibling-site-route-audit"))
    assert not checks["task:route-file-recorded"]


def test_copying_the_runner_summary_without_running_it_fails_the_site_audit(tmp_path: Path) -> None:
    """The summary is seeded text in the runner script; only running it leaves a mark."""
    fixture = create_full_task_fixture(tmp_path / "unrun", "sibling-site-route-audit")
    audit = fixture.workspace / "docs/storefront-audit.md"
    audit.parent.mkdir(parents=True)
    audit.write_text(
        f"# Storefront audit\n\n- route: `{SITE_BRANCH_FILE}`\n- canonical host: `{SITE_CANONICAL_HOST}`\n"
        f"- tests: {SITE_RUNNER_SUMMARY}\n",
        encoding="utf-8",
    )
    _commit(fixture.workspace, fixture.home, "Record the storefront audit")
    checks = _task_checks(full_task_checks(fixture, "sibling-site-route-audit"))
    assert checks["task:runner-summary-recorded"] and not checks["task:runner-executed"]


def test_swapped_digests_fail_the_checksum_task(tmp_path: Path) -> None:
    """Each file is listed beside its own checksum, not beside another file's."""
    fixture = create_full_task_fixture(tmp_path / "swapped", "downloaded-artifact-checksums")
    downloads = fixture.home / ARTIFACT_DIRECTORY
    names = sorted(ARTIFACT_FILES)
    digests = [hashlib.sha256((downloads / name).read_bytes()).hexdigest() for name in names]
    digests[0], digests[1] = digests[1], digests[0]
    document = fixture.workspace / "docs/release-1.4.0.md"
    document.write_text(
        "\n".join(f"{digest}  {name}" for digest, name in zip(digests, names, strict=True)) + "\n",
        encoding="utf-8",
    )
    _commit(fixture.workspace, fixture.home, "Record the release checksums")
    checks = _task_checks(full_task_checks(fixture, "downloaded-artifact-checksums"))
    assert not checks["task:checksums-recorded"]


def test_swapped_digests_in_a_table_fail_the_checksum_task(tmp_path: Path) -> None:
    """A table writes the name first and the digest after it, and the rows sit close
    together, so the pair has to be read within one row rather than nearby text."""
    fixture = create_full_task_fixture(tmp_path / "swapped-table", "downloaded-artifact-checksums")
    downloads = fixture.home / ARTIFACT_DIRECTORY
    names = sorted(ARTIFACT_FILES)
    digests = [hashlib.sha256((downloads / name).read_bytes()).hexdigest() for name in names]
    digests[0], digests[1] = digests[1], digests[0]
    document = fixture.workspace / "docs/release-1.4.0.md"
    document.write_text(
        "| File | SHA-256 |\n| --- | --- |\n"
        + "".join(f"| {name} | {digest} |\n" for name, digest in zip(names, digests, strict=True)),
        encoding="utf-8",
    )
    _commit(fixture.workspace, fixture.home, "Record the release checksums")
    checks = _task_checks(full_task_checks(fixture, "downloaded-artifact-checksums"))
    assert not checks["task:checksums-recorded"]


def test_a_table_of_names_and_digests_passes_the_checksum_task(tmp_path: Path) -> None:
    """The task asks for each name beside its checksum, which a table row records."""
    fixture = create_full_task_fixture(tmp_path / "table", "downloaded-artifact-checksums")
    downloads = fixture.home / ARTIFACT_DIRECTORY
    document = fixture.workspace / "docs/release-1.4.0.md"
    document.write_text(
        "| File | SHA-256 |\n| --- | --- |\n"
        + "".join(
            f"| {name} | {hashlib.sha256((downloads / name).read_bytes()).hexdigest()} |\n"
            for name in sorted(ARTIFACT_FILES)
        ),
        encoding="utf-8",
    )
    _commit(fixture.workspace, fixture.home, "Record the release checksums")
    checks = _task_checks(full_task_checks(fixture, "downloaded-artifact-checksums"))
    assert checks["task:checksums-recorded"]


def test_a_file_added_to_the_download_directory_fails_the_checksum_task(tmp_path: Path) -> None:
    """The document answers for every file in the directory, so an unlisted one is not left as it was."""
    fixture = create_full_task_fixture(tmp_path / "extra", "downloaded-artifact-checksums")
    downloads = fixture.home / ARTIFACT_DIRECTORY
    (downloads / "widgets-1.4.0.tar.gz").write_text("another archive\n", encoding="utf-8")
    document = fixture.workspace / "docs/release-1.4.0.md"
    document.write_text(
        "\n".join(
            hashlib.sha256((downloads / name).read_bytes()).hexdigest() + "  " + name for name in sorted(ARTIFACT_FILES)
        )
        + "\n",
        encoding="utf-8",
    )
    _commit(fixture.workspace, fixture.home, "Record the release checksums")
    checks = _task_checks(full_task_checks(fixture, "downloaded-artifact-checksums"))
    assert checks["task:checksums-recorded"] and not checks["task:artifacts-untouched"]
