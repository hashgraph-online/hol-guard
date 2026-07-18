"""Security contracts for release-train publishing."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"
RELEASE_BRANCHES = ["main", "release/2.2"]
RELEASE_MAINTAINERS = {"@kantorcodes", "@deep-purple-boots"}


def _workflow(path: Path) -> dict[object, object]:
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def test_release_codeowners_are_the_two_named_maintainers() -> None:
    pattern, *owners = CODEOWNERS.read_text(encoding="utf-8").split()

    assert pattern == "*"
    assert set(owners) == RELEASE_MAINTAINERS
    assert len(owners) == len(RELEASE_MAINTAINERS)


def test_release_branches_run_ci_and_pr_canaries() -> None:
    ci = _workflow(CI_WORKFLOW)
    publish = _workflow(PUBLISH_WORKFLOW)

    assert ci[True]["push"]["branches"] == RELEASE_BRANCHES
    assert ci[True]["pull_request"]["branches"] == RELEASE_BRANCHES
    assert publish[True]["push"]["branches"] == RELEASE_BRANCHES
    assert publish[True]["pull_request"]["branches"] == RELEASE_BRANCHES
    assert "tags" not in publish[True]["push"]


def test_ordinary_pushes_and_tag_pushes_cannot_publish() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]

    for job_name in (
        "publish-alpha-testpypi",
        "publish-alpha-pypi",
        "release-alpha",
        "publish-container",
    ):
        assert "github.event_name == 'workflow_dispatch'" in jobs[job_name]["if"]
    assert "publish-stable-testpypi" not in jobs
    assert "publish-stable-pypi" not in jobs
    assert "release" not in jobs

    assert "sync-repository-version" not in jobs
    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    assert "[skip release publish]" not in workflow_text
    assert "startsWith(github.ref, 'refs/tags/')" not in workflow_text


def test_push_build_keeps_the_repository_version_without_restamping() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    build_steps = workflow["jobs"]["build"]["steps"]
    compute_run = next(step["run"] for step in build_steps if step.get("name") == "Compute publish version")
    stamp_step = next(step for step in build_steps if step.get("name") == "Stamp package version when needed")
    stamp_run = stamp_step["run"]

    assert 'VERSION="$BASE_VERSION"' in compute_run
    assert 'CHANNEL="integration"' in compute_run
    assert 'elif [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]' in compute_run
    assert '[[ "$GITHUB_EVENT_NAME" == "push" ]]' not in compute_run
    assert "if" not in stamp_step
    assert "sync_repo_version.py --check" in stamp_run
    assert '[[ "$CURRENT_VERSION" == "$VERSION" ]]' in stamp_run
    assert 'sync_repo_version.py --version "$VERSION"' in stamp_run
    condition = '[[ "$CURRENT_VERSION" == "$VERSION" ]]'
    assert stamp_run.index("--check") < stamp_run.index(condition)
    assert stamp_run.index(condition) < stamp_run.index("--version")


def test_alpha_only_dispatch_and_pr_version_stamping_contracts() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    build_steps = workflow["jobs"]["build"]["steps"]
    compute_run = next(step["run"] for step in build_steps if step.get("name") == "Compute publish version")
    stamp_run = next(step["run"] for step in build_steps if step.get("name") == "Stamp package version when needed")

    assert 'if [[ "$CHANNEL" != "alpha" ]]' in compute_run
    assert "The release/2.2 train is alpha-only" in compute_run
    assert 'elif [[ "$CHANNEL" == "stable" ]]' not in compute_run
    assert "VERSION=$(uv run --no-sync python scripts/validate_alpha_release.py" in compute_run
    assert 'VERSION=$(BASE_VERSION="$BASE_VERSION" PR_NUMBER="$PR_NUMBER"' in compute_run
    assert 'sync_repo_version.py --version "$VERSION"' in stamp_run


def test_release_dispatch_binds_channel_train_version_and_sha() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    inputs = workflow[True]["workflow_dispatch"]["inputs"]
    jobs = workflow["jobs"]
    build_steps = workflow["jobs"]["build"]["steps"]

    assert inputs["release_channel"]["options"] == ["alpha"]
    assert inputs["release_train"]["options"] == ["2.2"]
    assert inputs["release_version"]["required"] is True
    assert inputs["expected_sha"]["required"] is True
    assert "promotion_pr" not in inputs

    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    assert '--github-sha "$SOURCE_SHA"' in workflow_text
    assert '--expected-sha "$EXPECTED_SHA"' in workflow_text
    assert '--actual-ref "$GITHUB_REF"' in workflow_text
    authorize_job = jobs["authorize-release"]
    assert authorize_job["permissions"] == {}
    assert len(authorize_job["steps"]) == 1
    dispatch_gate = authorize_job["steps"][0]
    assert dispatch_gate["name"] == "Enforce alpha release authority"
    assert dispatch_gate["if"] == "github.event_name == 'workflow_dispatch'"
    assert not any("uses" in step for step in authorize_job["steps"])
    assert '"$GITHUB_RUN_ATTEMPT" != "1"' in dispatch_gate["run"]
    assert '"$GITHUB_ACTOR_ID" != "6068672"' in dispatch_gate["run"]
    assert '"$GITHUB_ACTOR_ID" != "301892678"' in dispatch_gate["run"]
    assert '"$RELEASE_CHANNEL" != "alpha"' in dispatch_gate["run"]
    assert '"$RELEASE_TRAIN" != "2.2"' in dispatch_gate["run"]
    assert '"$GITHUB_REF" != "refs/heads/release/2.2"' in dispatch_gate["run"]
    assert '"$EXPECTED_SHA" != "$GITHUB_SHA"' in dispatch_gate["run"]
    assert jobs["build"]["needs"] == "authorize-release"
    assert jobs["build"]["if"] == "github.event_name != 'workflow_dispatch' || github.run_attempt == 1"
    assert jobs["alpha-cross-platform"]["needs"] == "build"
    for job_name in (
        "alpha-cross-platform",
        "publish-alpha-testpypi",
        "publish-alpha-pypi",
        "release-alpha",
        "publish-container",
    ):
        assert "github.run_attempt == 1" in jobs[job_name]["if"]
    compute_run = next(step["run"] for step in build_steps if step.get("name") == "Compute publish version")
    assert 'if [[ "$CHANNEL" != "alpha" ]]' in compute_run
    assert 'if [[ "$TRAIN" != "2.2" ]]' in compute_run
    assert 'if [[ "$GITHUB_REF" != "$TRAIN_REF" ]]' in compute_run
    assert '"$GITHUB_RUN_ATTEMPT" != "1"' in compute_run
    assert '"$GITHUB_ACTOR_ID" != "6068672"' in compute_run
    assert '"$GITHUB_ACTOR_ID" != "301892678"' in compute_run
    assert compute_run.index('"$GITHUB_RUN_ATTEMPT" != "1"') < compute_run.index("VALIDATOR_ARGS=(")
    for job_name in ("publish-alpha-testpypi", "publish-alpha-pypi", "release-alpha"):
        assert "build" in workflow["jobs"][job_name]["needs"]
        assert workflow["jobs"][job_name]["permissions"]["id-token"] == "write"
    assert "RELEASE_PUBLISHING_ENABLED" in workflow_text
    assert 'awk -v candidate="$RELEASE_VERSION"' in workflow_text
    assert "$0 != candidate" in workflow_text


def test_release_publication_reuses_one_hashed_build_artifact() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]

    assert "distribution-sha256" in {
        step.get("with", {}).get("name") for step in jobs["build"]["steps"] if isinstance(step, dict)
    }
    assert jobs["publish-alpha-pypi"]["needs"] == [
        "build",
        "alpha-cross-platform",
        "publish-alpha-testpypi",
    ]
    for job_name in (
        "publish-alpha-testpypi",
        "publish-alpha-pypi",
    ):
        steps = jobs[job_name]["steps"]
        assert any(step.get("run") == "sha256sum --check distribution-sha256.txt" for step in steps)
        assert any(
            step.get("name") == "Keep only the Guard release distribution" and "plugin_scanner" in step.get("run", "")
            for step in steps
        )

    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    assert "skip-existing" not in workflow_text


def test_publish_jobs_use_channel_specific_protected_environments() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]

    assert jobs["publish-testpypi"]["environment"] == "testpypi"
    assert jobs["publish-alpha-testpypi"]["environment"] == "testpypi-alpha"
    assert jobs["publish-alpha-pypi"]["environment"] == "pypi-alpha"
    assert jobs["publish-testpypi"]["permissions"] == {"id-token": "write"}
    assert jobs["publish-alpha-testpypi"]["permissions"] == {"contents": "read", "id-token": "write"}
    assert jobs["publish-alpha-pypi"]["permissions"] == {"contents": "read", "id-token": "write"}
    for job_name in ("publish-alpha-testpypi", "publish-alpha-pypi"):
        assert "vars.RELEASE_PUBLISHING_ENABLED == 'true'" in jobs[job_name]["if"]


def test_registry_state_is_revalidated_at_each_publication_boundary() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]

    for job_name in ("publish-alpha-testpypi",):
        steps = jobs[job_name]["steps"]
        inspect_step = next(step for step in steps if step.get("name") == "Inspect TestPyPI release state")
        publish_step = next(step for step in steps if str(step.get("uses", "")).startswith("pypa/"))
        verify_step = next(step for step in steps if step.get("name") == "Download and verify exact TestPyPI artifacts")
        assert "verify-release --registry testpypi" in inspect_step["run"]
        assert publish_step["if"] == "steps.testpypi.outputs.upload == 'true'"
        assert "--download-dir verified-testpypi" in verify_step["run"]
        assert 'uv tool run --from "$wheel"' in verify_step["run"]
        assert 'status" == "exact"' in verify_step["run"]
        assert 'status" != "absent"' in verify_step["run"]
        assert '== "hol-guard $VERSION"' in verify_step["run"]

    alpha_run = next(
        step["run"]
        for step in jobs["publish-alpha-pypi"]["steps"]
        if step.get("name") == "Revalidate alpha publication authorization"
    )
    assert "list-versions --registry pypi" in alpha_run
    assert "git ls-remote --exit-code origin" in alpha_run
    assert "validate_alpha_release.py" in alpha_run
    assert "refs/tags/alpha/v${VERSION}" in alpha_run
    assert 'awk -v candidate="$VERSION"' in alpha_run

    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    assert 'for registry in ("pypi.org", "test.pypi.org")' not in workflow_text

    for job_name in ("publish-alpha-pypi",):
        steps = jobs[job_name]["steps"]
        inspect_step = next(step for step in steps if step.get("name") == "Inspect PyPI release state")
        publish_step = next(step for step in steps if str(step.get("uses", "")).startswith("pypa/"))
        verify_step = next(step for step in steps if step.get("name") == "Download and verify exact PyPI artifacts")
        assert "verify-release --registry pypi" in inspect_step["run"]
        assert publish_step["if"] == "steps.pypi.outputs.upload == 'true'"
        assert "--download-dir verified-pypi" in verify_step["run"]
        assert 'status" == "exact"' in verify_step["run"]
        assert 'status" != "absent"' in verify_step["run"]
        assert '== "hol-guard $VERSION"' in verify_step["run"]


def test_release_tags_are_bound_to_the_exact_published_source() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]

    alpha_test_run = next(
        step["run"]
        for step in jobs["publish-alpha-testpypi"]["steps"]
        if step.get("name") == "Revalidate alpha source before TestPyPI"
    )
    assert 'git ls-remote --exit-code origin "$train_ref"' in alpha_test_run
    assert "refs/tags/alpha/v${VERSION}" in alpha_test_run
    assert '[[ -n "$remote_alpha_tag_sha" && "$remote_alpha_tag_sha" != "$SOURCE_SHA" ]]' in alpha_test_run

    alpha_pypi_run = next(
        step["run"]
        for step in jobs["publish-alpha-pypi"]["steps"]
        if step.get("name") == "Revalidate alpha publication authorization"
    )
    assert '[[ -n "$remote_alpha_tag_sha" && "$remote_alpha_tag_sha" != "$SOURCE_SHA" ]]' in alpha_pypi_run

    release_run = next(
        step["run"]
        for step in jobs["release-alpha"]["steps"]
        if step.get("name") == "Create discoverable alpha prerelease"
    )
    assert 'gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs"' in release_run
    assert '-f ref="refs/tags/${tag}"' in release_run
    assert 'remote_tag_sha" != "$SOURCE_SHA"' in release_run
    assert 'gh release view "$tag" --json isDraft,isPrerelease' in release_run
    assert 'gh release download "$tag"' in release_run
    assert 'cmp --silent "$local_file"' in release_run
    assert "mapfile -d '' local_files" in release_run
    assert 'gh attestation verify "$remote_file"' in release_run
    assert '--bundle "$bundle" --source-digest "$SOURCE_SHA"' in release_run
    assert "--verify-tag" in release_run


def test_release_22_has_no_stable_publication_surface() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]
    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert "channel == 'alpha'" in jobs["release-alpha"]["if"]
    assert "channel == 'stable'" not in jobs["publish-container"]["if"]
    assert jobs["publish-container"]["needs"] == [
        "build",
        "publish-alpha-pypi",
        "release-alpha",
    ]
    assert not {"publish-stable-testpypi", "publish-stable-pypi", "release"} & jobs.keys()
    assert "testpypi-stable" not in workflow_text
    assert "pypi-stable" not in workflow_text
    assert "refs/tags/v${VERSION}" not in workflow_text
    assert "--channel stable" not in workflow_text
    assert "name: Create GitHub Release" not in workflow_text
