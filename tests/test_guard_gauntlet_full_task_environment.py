"""The full tasks whose work reaches outside the project directory.

Each one seeds ordinary developer state around the project: a sibling checkout, a
toolchain directory, a harness home, a reproduction under the temporary root. The
checks have to be unsatisfied on the seeded fixture and satisfied once the work is
done, so a lane that cannot be finished shows up here rather than as a permanently
red Gauntlet.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.full_task_environment import (
    AUDIT_NOTE,
    CHECKLIST_STEPS,
    GLOBAL_PACKAGE,
    GLOBAL_PACKAGE_VERSION,
    NODE_VERSIONS,
    PATH_ENTRY,
    PUNCTUATION_CASE,
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
