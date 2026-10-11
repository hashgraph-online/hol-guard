"""Contracts for Release Please stable publication and optional main alphas."""

from __future__ import annotations

from pathlib import Path

from tests.release_workflow_helpers import load_workflow

ROOT = Path(__file__).resolve().parents[1]
RELEASE_PLEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release-please.yml"
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
RELEASE_PLEASE_CONFIG = ROOT / "release-please-config.json"
RELEASE_PLEASE_MANIFEST = ROOT / ".release-please-manifest.json"
PINNED_RELEASE_PLEASE_ACTION = "googleapis/release-please-action@5c625bfb5d1ff62eadeeb3772007f7f66fdcf071"


def test_release_please_runs_on_main_pushes_and_maintainer_alpha_requests() -> None:
    workflow = load_workflow(RELEASE_PLEASE_WORKFLOW)

    assert workflow["name"] == "Release Please"
    assert workflow["permissions"] == {}
    assert workflow[True]["push"] == {"branches": ["main"]}
    assert workflow[True]["workflow_dispatch"]["inputs"] == {
        "alpha_version": {
            "description": 'Optional test alpha cut from main; "next" picks the next X.Y+1.0aN',
            "type": "string",
            "default": "next",
        }
    }
    assert workflow["concurrency"] == {
        "group": "hol-guard-release-please-${{ github.event_name }}-${{ github.ref }}",
        "cancel-in-progress": False,
    }


def test_release_please_job_is_pinned_and_least_privilege() -> None:
    jobs = load_workflow(RELEASE_PLEASE_WORKFLOW)["jobs"]
    release = jobs["release-please"]
    dispatch = jobs["dispatch-stable-publish"]

    assert release["permissions"] == {"contents": "write", "pull-requests": "write"}
    assert release["if"] == "github.event_name == 'push'"
    assert release["outputs"]["release_created"] == "${{ steps.release.outputs.release_created }}"
    assert release["outputs"]["tag_name"] == "${{ steps.release.outputs.tag_name }}"
    assert release["outputs"]["sha"] == "${{ steps.release.outputs.sha }}"
    assert release["outputs"]["version"] == "${{ steps.release.outputs.version }}"
    require_token = release["steps"][0]
    assert "RELEASE_PLEASE_TOKEN is not configured" in require_token["run"]
    assert require_token["env"]["RELEASE_PLEASE_TOKEN"] == "${{ secrets.RELEASE_PLEASE_TOKEN }}"
    step = release["steps"][1]
    assert step["id"] == "release"
    assert step["uses"] == PINNED_RELEASE_PLEASE_ACTION
    assert step["with"]["token"] == "${{ secrets.RELEASE_PLEASE_TOKEN }}"
    assert step["with"]["target-branch"] == "main"
    assert step["with"]["config-file"] == "release-please-config.json"
    assert step["with"]["manifest-file"] == ".release-please-manifest.json"
    assert "skip-github-release" not in step.get("with", {})

    assert dispatch["needs"] == "release-please"
    assert dispatch["permissions"] == {"actions": "write", "contents": "read"}
    assert dispatch["if"] == "needs.release-please.outputs.release_created == 'true'"
    assert "github.run_attempt == 1" not in str(dispatch.get("if", ""))
    run = dispatch["steps"][0]["run"]
    assert 'gh workflow run "Publish to PyPI"' in run
    assert '--ref "$TAG_NAME"' in run
    assert "--ref main" not in run
    assert "-f release_channel=stable" in run
    assert "-f release_train=main" in run
    assert '-f release_version="$VERSION"' in run
    assert '-f expected_sha="$SHA"' in run
    assert "github.token" in dispatch["steps"][0]["env"]["GH_TOKEN"]


def test_stable_dispatch_allows_actions_bot_while_train_alpha_stays_maintainer_only() -> None:
    publish = load_workflow(PUBLISH_WORKFLOW)
    authorize = publish["jobs"]["authorize-release"]["steps"][0]["run"]
    compute = next(
        step["run"] for step in publish["jobs"]["build"]["steps"] if step.get("name") == "Compute publish version"
    )
    alpha_gate = authorize[
        authorize.index("alpha:3.0:refs/heads/release/3.0") : authorize.index("alpha:main:refs/heads/main")
    ]
    stable_gate = authorize[authorize.index("stable:main:refs/heads/main") :]

    assert '"$GITHUB_ACTOR_ID" != "6068672"' in alpha_gate
    assert '"$GITHUB_ACTOR_ID" != "301892678"' in alpha_gate
    assert "41898282" not in alpha_gate
    assert '"$GITHUB_ACTOR_ID" != "41898282"' in stable_gate
    assert '"$GITHUB_ACTOR_ID" != "41898282"' in compute
    assert "refs/tags/v${RELEASE_VERSION}" in authorize
    train_alpha_compute = compute[
        compute.index('"$CHANNEL" == "alpha" && "$TRAIN" == "3.0"') : compute.index(
            '"$CHANNEL" == "alpha" && "$TRAIN" == "main"'
        )
    ]
    assert "41898282" not in train_alpha_compute
    assert compute.index('"$CHANNEL" == "alpha" && "$TRAIN" == "main"') < compute.index("41898282")
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


def test_alpha_dispatch_is_maintainer_only_and_targets_main() -> None:
    dispatch = load_workflow(RELEASE_PLEASE_WORKFLOW)["jobs"]["dispatch-alpha-publish"]
    step = next(s for s in dispatch["steps"] if s.get("name") == "Dispatch an alpha of the current main commit")
    run = step["run"]

    assert dispatch["if"] == "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'"
    assert "needs" not in dispatch
    assert dispatch["permissions"] == {"actions": "write", "contents": "read"}
    assert step["env"]["ACTOR_ID"] == "${{ github.actor_id }}"
    assert "SHA" not in step["env"]
    assert 'SHA=$(gh api "repos/${GITHUB_REPOSITORY}/commits/heads/main" --jq .sha)' in run
    assert run.index("commits/heads/main") < run.index("gh workflow run")
    assert '"$ACTOR_ID" != "6068672" && "$ACTOR_ID" != "301892678"' in run
    assert "41898282" not in run
    assert run.index('"$ACTOR_ID" != "6068672"') < run.index("gh workflow run")
    assert '"$ALPHA_VERSION" =~ ^[0-9]+\\.[0-9]+\\.0a[1-9][0-9]*$' in run
    assert 'gh workflow run "Publish to PyPI"' in run
    assert "--ref main" in run
    assert "-f release_channel=alpha" in run
    assert "-f release_train=main" in run
    assert '-f release_version="$ALPHA_VERSION"' in run
    assert '-f expected_sha="$SHA"' in run


def test_main_alpha_publication_trusts_the_release_please_bot_and_main_ancestry() -> None:
    jobs = load_workflow(PUBLISH_WORKFLOW)["jobs"]
    authorize = jobs["authorize-release"]["steps"][0]["run"]
    main_alpha_gate = authorize[
        authorize.index("alpha:main:refs/heads/main") : authorize.index("stable:main:refs/heads/main")
    ]
    compute = next(step["run"] for step in jobs["build"]["steps"] if step.get("name") == "Compute publish version")
    main_alpha_compute = compute[
        compute.index('"$CHANNEL" == "alpha" && "$TRAIN" == "main"') : compute.index(
            '"$CHANNEL" == "stable" && "$TRAIN" == "main"'
        )
    ]

    assert '"$GITHUB_ACTOR_ID" != "41898282"' in main_alpha_gate
    assert '"$GITHUB_REF" != "refs/heads/main"' in main_alpha_compute
    assert '--base-version "$BASE_VERSION"' in main_alpha_compute
    assert '"$RELEASE_VERSION" == "next"' in main_alpha_compute
    assert "compute_alpha_release_version.py" in main_alpha_compute
    assert "--release-train main" in main_alpha_compute
    assert "already published or reserved" in main_alpha_compute
    assert jobs["build"]["outputs"]["base_version"] == "${{ steps.version.outputs.base_version }}"
    for job_name, step_name in (
        ("publish-alpha-testpypi", "Revalidate alpha source before TestPyPI"),
        ("publish-alpha-pypi", "Revalidate alpha publication authorization"),
    ):
        step = next(s for s in jobs[job_name]["steps"] if s.get("name") == step_name)
        assert 'if [[ "$TRAIN" == "main" ]]; then' in step["run"]
        assert "bash scripts/ci/require_alpha_source_on_main.sh" in step["run"]
        assert "no longer the release train head" in step["run"]
        assert step["env"]["GH_TOKEN"] == "${{ steps.release-token.outputs.token }}"
    script = (ROOT / "scripts" / "ci" / "require_alpha_source_on_main.sh").read_text(encoding="utf-8")
    assert "compare/${SOURCE_SHA}...main" in script
    assert "ahead | identical) ;;" in script


def test_main_alpha_wakes_the_desktop_core_alpha_feed() -> None:
    wake = load_workflow(PUBLISH_WORKFLOW)["jobs"]["wake-alpha-core-feed"]
    step = next(s for s in wake["steps"] if s.get("name") == "Dispatch the exact published alpha Core version")
    run = step["run"]

    assert wake["needs"] == ["build", "release-alpha"]
    assert "needs.release-alpha.result == 'success'" in wake["if"]
    assert "needs.build.outputs.release_train == 'main'" in wake["if"]
    assert wake["permissions"] == {"actions": "write", "contents": "read"}
    assert step["env"]["PUBLICATION_SOURCE_SHA"] == "${{ needs.build.outputs.source_sha }}"
    assert "gh workflow run desktop-core-alpha-feed.yml" in run
    assert "-f release_channel=alpha" in run
    assert "--ref main" in run


def test_alpha_deletion_is_maintainer_only_and_limited_to_prereleases() -> None:
    workflow = load_workflow(ROOT / ".github" / "workflows" / "delete-alpha-release.yml")
    job = workflow["jobs"]["delete"]
    steps = {step["name"]: step["run"] for step in job["steps"] if "run" in step}

    assert set(workflow[True]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {}
    assert job["permissions"] == {"contents": "write", "packages": "write"}
    gate = steps["Require an authorized maintainer and a main alpha version"]
    assert '"$ACTOR_ID" != "6068672" && "$ACTOR_ID" != "301892678"' in gate
    assert '"$VERSION" =~ ^[0-9]+\\.[0-9]+\\.0a[1-9][0-9]*$' in gate
    names = [step["name"] for step in job["steps"]]
    verify = steps["Confirm the tag is a prerelease cut from main"]
    image = steps["Delete the alpha container image tag"]
    release = steps["Delete the GitHub prerelease and tag"]
    assert names.index("Confirm the tag is a prerelease cut from main") < names.index(
        "Delete the alpha container image tag"
    )
    assert names.index("Delete the alpha container image tag") < names.index("Delete the GitHub prerelease and tag")
    assert 'compare/${source_sha}...main" --jq .status' in verify
    assert '"$status" != "ahead" && "$status" != "identical"' in verify
    assert "it is not a prerelease" in verify
    assert "|| true" not in image
    assert 'grep -q "HTTP 404" lookup_error' in image
    assert 'tag="alpha/v${VERSION}"' in release
    assert "--cleanup-tag --yes" in release
    assert "gone" not in steps["Explain the PyPI follow-up"]
