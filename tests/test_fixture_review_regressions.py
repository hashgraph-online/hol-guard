"""Regression checks for publication, intake and fixture-only CI isolation."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts import build_native_command_program as builder
from scripts import intake_contribution_pr as intake
from scripts.ci import build_pytest_shard_plan as planner
from tests.support.ci_workflow import expand_ci_job_actions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("name", ["nested.rs", "nested.json", "nested"])
def test_source_suffix_directories_are_traversed_not_hashed_as_files(tmp_path, name):
    """Verify source suffix directories are traversed not hashed as files."""
    directory = tmp_path / name
    directory.mkdir()
    code = directory / "lib.rs"
    code.write_text("pub fn example() {}")
    (directory / "notes.txt").write_text("not a native input")
    assert builder._implementation_files(tmp_path) == {code}


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX symlink creation")
@pytest.mark.parametrize("target_kind", ["missing", "directory", "file"])
@pytest.mark.parametrize("link_name", ["entry.rs", "entry"])
def test_native_fingerprint_rejects_all_symlinks_before_filtering(tmp_path, target_kind, link_name):
    """Verify native fingerprint rejects all symlinks before filtering."""
    root = tmp_path / "src"
    root.mkdir()
    target = tmp_path / "target"
    if target_kind == "directory":
        target.mkdir()
    elif target_kind == "file":
        target.write_text("native code")
    (root / link_name).symlink_to(target, target_is_directory=target_kind == "directory")
    with pytest.raises(ValueError, match="invalid native implementation input"):
        builder._implementation_files(root)


@pytest.mark.parametrize(
    "path",
    [
        "contracts/managed-controls/v1/extension-projection-digest-vector.json",
        "tests/test_guard_extension_trust.py",
        "tests/test_policy_bundle_delivery_runtime.py",
        "tests/fixtures/extension-controls/catalog-baseline.v1.json",
        "tests/fixtures/guard-command-corpus/decision-diff-report.json",
        "tests/fixtures/command-source-contributor.v1.json",
    ],
)
def test_intake_does_not_silently_reset_independent_expectations(path):
    """Verify intake does not silently reset independent expectations."""
    assert not intake.is_machine_managed(path)


@pytest.mark.parametrize(
    "path",
    [
        "contracts/extensions/command-catalog.v1.json",
        "docs/guard/extensions/catalog.v2.json",
        "src/codex_plugin_scanner/guard/extension_builder/unsafe.py",
    ],
)
def test_intake_still_sanitizes_generated_outputs_and_credential_sensitive_tooling(path):
    """Verify intake still sanitizes generated outputs and credential sensitive tooling."""
    assert intake.is_machine_managed(path)


def test_publication_staging_works_without_a_nonexistent_mcp_resource_directory(tmp_path):
    """Verify publication staging works without a nonexistent MCP resource directory."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/extension-artifact-regen.yml").read_text())
    step = next(
        item
        for item in workflow["jobs"]["regen"]["steps"]
        if item.get("name") == "Regenerate and publish refreshed artifacts"
    )
    script = step["run"].split("git add -A", 1)[1].split("close_superseded()", 1)[0]
    paths = [part for part in script.split() if part != chr(92)]
    assert paths == [
        "contracts/extensions",
        "docs/guard/extensions",
        "contributions/extensions",
        "src/codex_plugin_scanner/guard/contracts/data/extensions",
    ]
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for name in paths:
        directory = tmp_path / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "generated.json").write_text("{}\n")
    subprocess.run(["git", "add", "-A", *paths], cwd=tmp_path, check=True)
    tracked = subprocess.check_output(["git", "ls-files"], cwd=tmp_path, text=True).splitlines()
    assert len(tracked) == len(paths)


@pytest.mark.parametrize("measured", [False, True])
def test_full_report_evaluation_has_one_process_owner_without_losing_tests(measured):
    """Verify full report evaluation has one process owner without losing tests."""
    report = "tests/test_guard_command_decision_diff.py"
    nodes = [f"{report}::test_case_{i}" for i in range(37)]
    others = [f"tests/test_other_{i}.py::test_case" for i in range(100)]
    durations = {planner.node_id_digest(node): 0.1 for node in nodes + others} if measured else {}
    shards, _ = planner.build_affinity_node_shards(nodes + others, 16, durations)
    assert sum(any(node.startswith(report + "::") for node in shard) for shard in shards) == 1
    flattened = [node for shard in shards for node in shard]
    assert sorted(flattened) == sorted(nodes + others)
    assert len(flattened) == len(set(flattened))


def test_ci_entry_point_and_extracted_actions_keep_bounded_reviewable_files():
    """Verify CI entry point and extracted actions keep bounded reviewable files."""
    path = ROOT / ".github/workflows/ci.yml"
    assert len(path.read_text().splitlines()) <= 750
    workflow = yaml.safe_load(path.read_text())
    expanded = expand_ci_job_actions(workflow)
    assert set(workflow["jobs"]) == set(expanded["jobs"])
    assert expanded["jobs"]["ci-python-312"]["name"] == "ci (3.12)"
    for name, job in workflow["jobs"].items():
        assert {k: v for k, v in job.items() if k != "steps"} == {
            k: v for k, v in expanded["jobs"][name].items() if k != "steps"
        }
    for action in (ROOT / ".github/actions").glob("ci-job-*/action.yml"):
        assert len(action.read_text().splitlines()) <= 500
        document = yaml.safe_load(action.read_text())
        assert document["runs"]["using"] == "composite"
        for step in document["runs"]["steps"]:
            assert "run" not in step or "shell" in step
    gate = next(s for s in expanded["jobs"]["sonar"]["steps"] if s.get("name") == "SonarQube Quality Gate check")
    assert gate["run"] == "timeout --signal=TERM --kill-after=5s 300s python -m scripts.ci.check_sonar_quality"
    assert not gate.get("continue-on-error")


def test_expansion_preserves_literal_input_values_and_rejects_missing_bindings(tmp_path):
    """Verify expansion preserves literal input values and rejects missing bindings."""
    folder = tmp_path / ".github/actions/ci-job-example"
    folder.mkdir(parents=True)
    (folder / "action.yml").write_text(
        yaml.safe_dump(
            {
                "inputs": {"python-version": {"required": True}},
                "runs": {
                    "using": "composite",
                    "steps": [{"run": "python ${{ inputs.python-version }}", "shell": "bash"}],
                },
            }
        )
    )
    call = {"uses": "./.github/actions/ci-job-example", "with": {"python-version": "${{ matrix.python-version }}"}}
    workflow = {"jobs": {"test": {"steps": [call]}}}
    assert (
        expand_ci_job_actions(workflow, tmp_path)["jobs"]["test"]["steps"][0]["run"]
        == "python ${{ matrix.python-version }}"
    )
    del call["with"]
    with pytest.raises(ValueError, match="inputs must be explicit"):
        expand_ci_job_actions(workflow, tmp_path)


def test_validation_guide_generates_evidence_before_comparing_current_report():
    """Verify validation guide generates evidence before comparing current report."""
    guide = (ROOT / "docs/guard/extension-builder/VALIDATION.md").read_text()
    assert guide.index("guard_command_decision_diff.py --write") < guide.index("guard_command_decision_diff.py --check")


def test_synthetic_contribution_does_not_reuse_a_real_extension_action_class():
    """Verify synthetic contribution does not reuse a real extension action class."""
    import json

    from scripts.ci.check_extension_fixture_isolation import EXTENSION_ID, acceptance_source

    path = ROOT / "contributions/command-sources/command.noodle.json"
    original_bytes = path.read_bytes()
    original = json.loads(original_bytes)["extension"]
    candidate = acceptance_source(ROOT)["extension"]
    assert candidate["extension_id"] == EXTENSION_ID
    assert not (
        {item.casefold() for item in original["action_classes"]}
        & {item.casefold() for item in candidate["action_classes"]}
    )
    expected = candidate["action_classes"]
    assert expected and all(row["action_classes"] == expected for row in candidate["permissions"] + candidate["rules"])
    assert path.read_bytes() == original_bytes


def test_actual_intake_keeps_reviewed_expectations_and_contributor_ancestry(tmp_path, monkeypatch):
    """Verify actual intake keeps reviewed expectations and contributor ancestry."""
    import json
    import sys

    remote = tmp_path / "origin.git"
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "init", "--bare", "-q", "-b", "main", str(remote)], check=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(checkout)], check=True)

    def git(*args):
        """Run a Git command against the temporary intake repository."""
        return subprocess.check_output(["git", *args], cwd=checkout, text=True).strip()

    git("config", "user.name", "Intake test")
    git("config", "user.email", "intake-test@example.invalid")
    git("remote", "add", "origin", str(remote))
    authored = [
        "tests/test_guard_extension_trust.py",
        "tests/test_policy_bundle_delivery_runtime.py",
        "tests/fixtures/extension-controls/catalog-baseline.v1.json",
        "contracts/managed-controls/v1/extension-projection-digest-vector.json",
        "contributions/command-sources/command.intake-test.json",
    ]
    generated = "contracts/extensions/command-catalog.v1.json"
    for name in [*authored, generated]:
        path = checkout / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("original\n")
    git("add", ".")
    git("commit", "-qm", "reviewed base")
    git("push", "-q", "origin", "main")
    git("checkout", "-qb", "candidate")
    for name in [*authored, generated]:
        (checkout / name).write_text("reviewed contributor update\n")
    git("commit", "-qam", "contributor changes")
    contributor = git("rev-parse", "HEAD")
    git("push", "-q", "origin", "candidate")
    git("checkout", "-q", "main")
    monkeypatch.setattr(intake, "ROOT", checkout)
    monkeypatch.setattr(sys, "argv", ["intake", "--pr", "42", "--skip-regen"])
    monkeypatch.setattr(
        intake,
        "_gh",
        lambda *args: json.dumps(
            {
                "state": "OPEN",
                "headRepository": {"name": "fixture"},
                "headRepositoryOwner": {"login": "fixture"},
                "headRefName": "candidate",
            }
        ),
    )
    execute = intake._run

    def local_only(command, **kwargs):
        """Fetch from the local fixture remote while retaining the real intake operations."""
        if command[:2] == ["git", "fetch"] and command[2].startswith("https://github.com/"):
            command = [*command[:2], str(remote), *command[3:]]
        return execute(command, **kwargs)

    monkeypatch.setattr(intake, "_run", local_only)
    assert intake.main() == 0
    assert git("branch", "--show-current") == "intake/pr-42"
    assert git("merge-base", contributor, "HEAD") == contributor
    assert all((checkout / name).read_text() == "reviewed contributor update\n" for name in authored)
    assert (checkout / generated).read_text() == "original\n"
    assert git("status", "--porcelain") == ""
