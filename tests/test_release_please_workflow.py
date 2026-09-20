"""Contracts for Release Please stable publication."""

from __future__ import annotations

import json
from pathlib import Path

from tests.release_workflow_helpers import load_workflow

ROOT = Path(__file__).resolve().parents[1]
RELEASE_PLEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release-please.yml"
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
RELEASE_PLEASE_CONFIG = ROOT / "release-please-config.json"
RELEASE_PLEASE_MANIFEST = ROOT / ".release-please-manifest.json"
PINNED_RELEASE_PLEASE_ACTION = "googleapis/release-please-action@5c625bfb5d1ff62eadeeb3772007f7f66fdcf071"


def test_release_please_runs_on_main_pushes_only() -> None:
    workflow = load_workflow(RELEASE_PLEASE_WORKFLOW)

    assert workflow["name"] == "Release Please"
    assert workflow["permissions"] == {}
    assert workflow[True] == {"push": {"branches": ["main"]}}
    assert workflow["concurrency"] == {
        "group": "hol-guard-release-please-${{ github.ref }}",
        "cancel-in-progress": False,
    }


def test_release_please_job_is_pinned_and_least_privilege() -> None:
    jobs = load_workflow(RELEASE_PLEASE_WORKFLOW)["jobs"]
    release = jobs["release-please"]
    dispatch = jobs["dispatch-stable-publish"]

    assert release["permissions"] == {"contents": "write", "pull-requests": "write"}
    assert release["if"] == "github.run_attempt == 1"
    assert release["outputs"]["release_created"] == "${{ steps.release.outputs.release_created }}"
    assert release["outputs"]["tag_name"] == "${{ steps.release.outputs.tag_name }}"
    assert release["outputs"]["sha"] == "${{ steps.release.outputs.sha }}"
    assert release["outputs"]["version"] == "${{ steps.release.outputs.version }}"
    step = release["steps"][0]
    assert step["id"] == "release"
    assert step["uses"] == PINNED_RELEASE_PLEASE_ACTION
    assert step["with"]["target-branch"] == "main"
    assert step["with"]["config-file"] == "release-please-config.json"
    assert step["with"]["manifest-file"] == ".release-please-manifest.json"
    assert "skip-github-release" not in step.get("with", {})

    assert dispatch["needs"] == "release-please"
    assert dispatch["permissions"] == {"actions": "write", "contents": "read"}
    assert "needs.release-please.outputs.release_created == 'true'" in dispatch["if"]
    assert "github.run_attempt == 1" in dispatch["if"]
    run = dispatch["steps"][0]["run"]
    assert 'gh workflow run "Publish to PyPI"' in run
    assert '--ref "$TAG_NAME"' in run
    assert "--ref main" not in run
    assert "-f release_channel=stable" in run
    assert "-f release_train=main" in run
    assert '-f release_version="$VERSION"' in run
    assert '-f expected_sha="$SHA"' in run
    assert "github.token" in dispatch["steps"][0]["env"]["GH_TOKEN"]


def test_release_please_config_versions_python_and_synced_metadata() -> None:
    config = json.loads(RELEASE_PLEASE_CONFIG.read_text(encoding="utf-8"))
    manifest = json.loads(RELEASE_PLEASE_MANIFEST.read_text(encoding="utf-8"))
    package = config["packages"]["."]
    lockfile = (ROOT / "uv.lock").read_text(encoding="utf-8")
    version_module = (ROOT / "src/codex_plugin_scanner/version.py").read_text(encoding="utf-8")

    assert config["include-v-in-tag"] is True
    assert config["include-component-in-tag"] is False
    assert package["release-type"] == "python"
    assert package["package-name"] == "hol-guard"
    assert package["changelog-path"] == "CHANGELOG.md"
    assert package["pull-request-title-pattern"] == "chore(release): ${version}"
    assert package["extra-files"] == [
        "src/codex_plugin_scanner/version.py",
        "uv.lock",
    ]
    assert manifest == {".": "3.0.193"}
    assert 'version = "3.0.193"  # x-release-please-version' in lockfile
    assert '__version__ = "3.0.193"  # x-release-please-version' in version_module


def test_stable_dispatch_allows_actions_bot_while_alpha_stays_maintainer_only() -> None:
    publish = load_workflow(PUBLISH_WORKFLOW)
    authorize = publish["jobs"]["authorize-release"]["steps"][0]["run"]
    compute = next(
        step["run"] for step in publish["jobs"]["build"]["steps"] if step.get("name") == "Compute publish version"
    )
    alpha_gate = authorize[
        authorize.index("alpha:3.0:refs/heads/release/3.0") : authorize.index("stable:main:refs/heads/main")
    ]
    stable_gate = authorize[authorize.index("stable:main:refs/heads/main") :]

    assert '"$GITHUB_ACTOR_ID" != "6068672"' in alpha_gate
    assert '"$GITHUB_ACTOR_ID" != "301892678"' in alpha_gate
    assert "41898282" not in alpha_gate
    assert '"$GITHUB_ACTOR_ID" != "41898282"' in stable_gate
    assert '"$GITHUB_ACTOR_ID" != "41898282"' in compute
    assert "refs/tags/v${RELEASE_VERSION}" in authorize
    assert compute.index('"$CHANNEL" == "stable" && "$TRAIN" == "main"') < compute.index("41898282")
    assert compute.index("VALIDATOR_ARGS=(") < compute.index("41898282")
    assert '--arg candidate "$RELEASE_VERSION"' in compute
    assert "$tags | map(select(. != $candidate))" in compute
    assert "Stable tag does not target the dispatch source" in compute


def test_existing_notes_only_github_release_receives_stable_assets() -> None:
    stable_run = next(
        step["run"]
        for step in load_workflow(PUBLISH_WORKFLOW)["jobs"]["release-main"]["steps"]
        if step.get("name") == "Create discoverable main release"
    )

    assert 'gh release view "$tag" --json isDraft,isPrerelease,assets' in stable_run
    assert 'gh release upload "$tag" "${missing_files[@]}"' in stable_run
    assert 'missing_files+=("$local_file")' in stable_run
    assert stable_run.count("existing_dir=$(mktemp -d)") >= 2
    assert 'gh release create "$tag"' in stable_run


def test_stable_jobs_accept_the_release_please_tag_ref() -> None:
    jobs = load_workflow(PUBLISH_WORKFLOW)["jobs"]
    tag_ref = "github.ref == format('refs/tags/v{0}', github.event.inputs.release_version)"
    for job_name in (
        "build-native-guard-wheels",
        "publish-main-testpypi",
        "reserve-main-tag",
        "publish-main-pypi",
        "release-main",
        "publish-container",
    ):
        condition = jobs[job_name]["if"]
        assert "github.ref == 'refs/heads/main'" in condition
        assert tag_ref in condition
        assert f"(github.ref == 'refs/heads/main' || {tag_ref})" in condition
    reserve_run = next(
        step["run"]
        for step in jobs["reserve-main-tag"]["steps"]
        if step.get("name") == "Bind stable tag to the exact main source"
    )
    testpypi_run = next(
        step["run"]
        for step in jobs["publish-main-testpypi"]["steps"]
        if step.get("name") == "Revalidate main source before TestPyPI"
    )
    assert "git merge-base --is-ancestor" in reserve_run
    assert "git merge-base --is-ancestor" in testpypi_run
    assert "Stable tag source is not an ancestor of main" in reserve_run
