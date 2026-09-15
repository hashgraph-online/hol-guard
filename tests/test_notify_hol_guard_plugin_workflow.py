"""Contracts for the stable HOL Guard plugin release notification."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "notify-hol-guard-plugin.yml"


def _workflow() -> dict[object, object]:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def _step(job: dict[str, object], name: str) -> dict[str, object]:
    steps = job["steps"]
    assert isinstance(steps, list)
    return next(step for step in steps if isinstance(step, dict) and step.get("name") == name)


def test_workflow_run_is_fail_closed_to_successful_main_publications() -> None:
    workflow = _workflow()
    trigger = workflow[True]["workflow_run"]
    resolve = workflow["jobs"]["resolve_publication"]

    assert trigger["workflows"] == ["Publish to PyPI"]
    assert trigger["types"] == ["completed"]
    assert trigger["branches"] == ["main"]
    assert workflow["permissions"] == {"actions": "read", "contents": "read"}

    condition = resolve["if"]
    assert "github.event.workflow_run.conclusion == 'success'" in condition
    assert "github.event.workflow_run.event == 'push'" in condition
    assert "github.event.workflow_run.head_branch == 'main'" in condition

    publication = _step(resolve, "Verify the triggering run completed stable publication")
    publication_run = publication["run"]
    assert "actions/runs/${TRIGGER_RUN_ID}/jobs?filter=latest&per_page=100" in publication_run
    assert '"Publish main release to PyPI": "success"' in publication_run
    assert '"Create main GitHub release": "success"' in publication_run
    assert 'print("eligible=false"' in publication_run
    assert 'print("eligible=true"' in publication_run


def test_triggering_version_and_sha_come_from_the_same_immutable_run() -> None:
    workflow = _workflow()
    resolve = workflow["jobs"]["resolve_publication"]
    download = _step(resolve, "Download the triggering run's immutable version artifact")
    read_identity = _step(resolve, "Read the triggering run's exact version")
    dispatch = workflow["jobs"]["dispatch_plugin_sync"]

    assert download["uses"] == (
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
    )
    assert download["with"] == {
        "name": "release-toolchain-sbom",
        "path": "triggering-release",
        "github-token": "${{ github.token }}",
        "repository": "${{ github.repository }}",
        "run-id": "${{ github.event.workflow_run.id }}",
    }

    identity_run = read_identity["run"]
    assert read_identity["env"]["SOURCE_SHA"] == "${{ github.event.workflow_run.head_sha }}"
    assert 'component.get("name") != "hol-guard-release-toolchain"' in identity_run
    assert 'component.get("version")' in identity_run
    assert "exact stable version" in identity_run
    assert "expected_source_sha" in identity_run

    assert dispatch["env"]["HOL_GUARD_VERSION"] == (
        "${{ needs.resolve_publication.outputs.version }}"
    )
    assert dispatch["env"]["SOURCE_SHA"] == (
        "${{ needs.resolve_publication.outputs.source_sha }}"
    )
    assert "github.event.workflow_run.head_sha" not in dispatch["env"]["SOURCE_SHA"]


def test_release_identity_is_cross_checked_against_github_and_exact_pypi_version() -> None:
    workflow = _workflow()
    resolve = workflow["jobs"]["resolve_publication"]
    verify = _step(resolve, "Verify the release identity and PyPI publication")
    verify_run = verify["run"]
    workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "releases/tags/{encoded_tag}" in verify_run
    assert "git/ref/tags/{encoded_tag}" in verify_run
    assert "source_sha != expected_source_sha" in verify_run
    assert "pypi.org/pypi/hol-guard/{version}/json" in verify_run
    assert "no non-yanked files" in verify_run
    assert "published=true" in verify_run
    assert "https://pypi.org/pypi/hol-guard/json" not in workflow_text


def test_manual_recovery_resolves_source_sha_from_the_selected_stable_release() -> None:
    workflow = _workflow()
    inputs = workflow[True]["workflow_dispatch"]["inputs"]
    resolve = workflow["jobs"]["resolve_publication"]
    requested = _step(resolve, "Resolve the requested stable GitHub release")
    verify = _step(resolve, "Verify the release identity and PyPI publication")

    assert inputs["version"]["required"] is False
    assert "latest stable GitHub release" in inputs["version"]["description"]
    assert requested["if"] == "github.event_name != 'workflow_run'"
    assert "releases?per_page=100&page={page}" in requested["run"]
    assert "version = max(candidates)[1]" in requested["run"]
    assert verify["env"]["EXPECTED_SOURCE_SHA"].endswith("|| '' }}")


def test_pull_request_validation_cannot_dispatch_downstream() -> None:
    workflow = _workflow()
    dispatch = workflow["jobs"]["dispatch_plugin_sync"]

    assert "github.event_name != 'pull_request'" in dispatch["if"]
    assert "needs.resolve_publication.outputs.published == 'true'" in dispatch["if"]
