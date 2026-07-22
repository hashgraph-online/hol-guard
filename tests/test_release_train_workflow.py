"""Security contracts for release-train publishing."""

from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib

import yaml

ROOT = Path(__file__).resolve().parents[1]
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"
CI_PUSH_BRANCHES = ["main"]
PUBLISH_PUSH_BRANCHES = ["main", "release/2.1"]
PR_BRANCHES = ["main", "release/2.1"]
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

    assert ci[True]["push"]["branches"] == CI_PUSH_BRANCHES
    assert ci[True]["pull_request"]["branches"] == PR_BRANCHES
    assert publish[True]["push"]["branches"] == PUBLISH_PUSH_BRANCHES
    assert publish[True]["pull_request"]["branches"] == PR_BRANCHES
    assert "tags" not in publish[True]["push"]
    assert publish["concurrency"]["group"] == "hol-guard-publish-${{ github.ref }}"
    assert publish["concurrency"]["cancel-in-progress"] is False


def test_branch_pushes_publish_their_channel_while_tag_pushes_cannot_publish() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]

    for job_name in (
        "publish-alpha-testpypi",
        "publish-alpha-pypi",
        "reserve-alpha-tag",
        "release-alpha",
        "publish-container",
    ):
        condition = jobs[job_name]["if"]
        assert "github.event_name == 'workflow_dispatch'" in condition
        assert "github.event_name == 'push'" in condition
        assert "github.ref == 'refs/heads/release/2.1'" in condition
        assert "needs.build.outputs.channel == 'alpha'" in condition
    for job_name in ("publish-main-testpypi", "publish-main-pypi", "release-main"):
        condition = jobs[job_name]["if"]
        assert "github.event_name == 'push'" in condition
        assert "github.run_attempt == 1" in condition
        assert "github.ref == 'refs/heads/main'" in condition
        assert "needs.build.outputs.channel == 'stable'" in condition
    assert jobs["publish-main-pypi"]["needs"] == ["build", "publish-main-testpypi"]
    assert jobs["release-main"]["needs"] == ["build", "publish-main-pypi"]

    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    assert "startsWith(github.ref, 'refs/tags/')" not in workflow_text
    assert "github.ref == 'refs/heads/main'" in workflow_text


def test_main_push_build_computes_a_registry_derived_stable_version() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    build_steps = workflow["jobs"]["build"]["steps"]
    compute_run = next(step["run"] for step in build_steps if step.get("name") == "Compute publish version")
    stamp_step = next(step for step in build_steps if step.get("name") == "Stamp package version when needed")
    stamp_run = stamp_step["run"]

    assert 'VERSION="$BASE_VERSION"' in compute_run
    assert 'CHANNEL="integration"' in compute_run
    assert 'elif [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]' in compute_run
    assert 'elif [[ "$GITHUB_EVENT_NAME" == "push" && "$GITHUB_REF" == "refs/heads/main" ]]' in compute_run
    assert 'CHANNEL="stable"' in compute_run
    assert "verify_release_registry.py" in compute_run
    assert "list-versions --registry pypi" in compute_run
    assert "list-versions --registry testpypi" in compute_run
    assert "'$pypi + $testpypi | unique'" in compute_run
    assert "compute_main_release_version.py" in compute_run
    assert "if" not in stamp_step
    assert "sync_repo_version.py --check" in stamp_run
    assert '[[ "$CURRENT_VERSION" == "$VERSION" ]]' in stamp_run
    assert 'sync_repo_version.py --version "$VERSION"' in stamp_run
    condition = '[[ "$CURRENT_VERSION" == "$VERSION" ]]'
    assert stamp_run.index("--check") < stamp_run.index(condition)
    assert stamp_run.index(condition) < stamp_run.index("--version")


def test_release_21_main_merge_publishes_exact_stable_version_and_tag() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    workflow = _workflow(PUBLISH_WORKFLOW)
    release_job = workflow["jobs"]["release-main"]
    release_step = next(step for step in release_job["steps"] if step.get("name") == "Create discoverable main release")

    assert project["project"]["version"] == "2.1.0"
    assert release_job["needs"] == ["build", "publish-main-pypi"]
    assert "github.ref == 'refs/heads/main'" in release_job["if"]
    assert "needs.build.outputs.channel == 'stable'" in release_job["if"]
    assert 'tag="v${VERSION}"' in release_step["run"]
    assert 'gh release create "$tag"' in release_step["run"]


def test_release_21_push_computes_a_deterministic_source_bound_alpha() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    build_steps = workflow["jobs"]["build"]["steps"]
    checkout = next(step for step in build_steps if str(step.get("uses", "")).startswith("actions/checkout@"))
    compute_run = next(step["run"] for step in build_steps if step.get("name") == "Compute publish version")

    assert _mapping(checkout["with"])["ref"] == (
        "${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}"
    )
    assert 'elif [[ "$GITHUB_EVENT_NAME" == "push" && "$GITHUB_REF" == "refs/heads/release/2.1" ]]' in compute_run
    assert 'CHANNEL="alpha"' in compute_run
    assert 'TRAIN="2.1"' in compute_run
    assert "compute_alpha_release_version.py" in compute_run
    assert '--release-train "$TRAIN"' in compute_run
    assert "SOURCE_SHA=$(git rev-parse 'HEAD^{commit}')" in compute_run
    assert '"$SOURCE_SHA" != "$GITHUB_SHA"' in compute_run

    auto_alpha_block = compute_run[
        compute_run.index(
            'elif [[ "$GITHUB_EVENT_NAME" == "push" && "$GITHUB_REF" == "refs/heads/release/2.1" ]]'
        ) : compute_run.index('elif [[ "$GITHUB_EVENT_NAME" == "push" && "$GITHUB_REF" == "refs/heads/main" ]]')
    ]
    assert "list-versions --registry pypi" in auto_alpha_block
    assert "list-versions --registry testpypi" in auto_alpha_block
    assert "git tag --list 'alpha/v*'" in auto_alpha_block
    assert "compute_alpha_release_version.py" in auto_alpha_block
    assert 'awk -v candidate="$RELEASE_VERSION"' not in auto_alpha_block
    assert "$0 != candidate" not in auto_alpha_block
    assert 'git tag --points-at "$SOURCE_SHA" --list "alpha/v${TRAIN}.0a*"' in auto_alpha_block
    assert '"${#SOURCE_ALPHA_TAGS[@]}" -gt 1' in auto_alpha_block
    assert '"${#SOURCE_ALPHA_TAGS[@]}" -eq 1' in auto_alpha_block
    assert 'RELEASE_VERSION="${SOURCE_ALPHA_TAGS[0]}"' in auto_alpha_block
    assert "select(. != $candidate)" not in auto_alpha_block
    assert "REUSING_RESERVED_ALPHA=true" in auto_alpha_block
    assert "--validate-phase-only" in auto_alpha_block
    assert 'if [[ "$REUSING_RESERVED_ALPHA" != "true" ]]' in auto_alpha_block
    assert auto_alpha_block.index('"${#SOURCE_ALPHA_TAGS[@]}" -eq 1') < auto_alpha_block.index(
        'if [[ "$REUSING_RESERVED_ALPHA" != "true" ]]'
    )


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return value


def test_alpha_only_dispatch_and_pr_version_stamping_contracts() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    build_steps = workflow["jobs"]["build"]["steps"]
    compute_run = next(step["run"] for step in build_steps if step.get("name") == "Compute publish version")
    stamp_run = next(step["run"] for step in build_steps if step.get("name") == "Stamp package version when needed")

    assert 'if [[ "$CHANNEL" != "alpha" ]]' in compute_run
    assert "The release/2.1 train is alpha-only" in compute_run
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
    assert inputs["release_train"]["options"] == ["2.1"]
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
    assert '"$RELEASE_TRAIN" != "2.1"' in dispatch_gate["run"]
    assert '"$GITHUB_REF" != "refs/heads/release/2.1"' in dispatch_gate["run"]
    assert '"$EXPECTED_SHA" != "$GITHUB_SHA"' in dispatch_gate["run"]
    assert jobs["build"]["needs"] == "authorize-release"
    build_condition = jobs["build"]["if"]
    assert "github.event_name != 'workflow_dispatch' || github.run_attempt == 1" in build_condition
    assert (
        "github.event_name != 'push' || github.run_attempt == 1 || github.ref == 'refs/heads/release/2.1'"
        in build_condition
    )
    assert jobs["alpha-cross-platform"]["needs"] == "build"
    for job_name in (
        "alpha-cross-platform",
        "publish-alpha-testpypi",
        "publish-alpha-pypi",
        "reserve-alpha-tag",
        "release-alpha",
        "publish-container",
    ):
        assert "github.run_attempt == 1" in jobs[job_name]["if"]
        if job_name != "alpha-cross-platform":
            assert "(github.event_name == 'push' && github.ref == 'refs/heads/release/2.1')" in jobs[job_name]["if"]
    compute_run = next(step["run"] for step in build_steps if step.get("name") == "Compute publish version")
    assert 'if [[ "$CHANNEL" != "alpha" ]]' in compute_run
    assert 'if [[ "$TRAIN" != "2.1" ]]' in compute_run
    assert 'if [[ "$GITHUB_REF" != "$TRAIN_REF" ]]' in compute_run
    assert '"$GITHUB_RUN_ATTEMPT" != "1"' in compute_run
    assert '"$GITHUB_ACTOR_ID" != "6068672"' in compute_run
    assert '"$GITHUB_ACTOR_ID" != "301892678"' in compute_run
    assert compute_run.index('"$GITHUB_RUN_ATTEMPT" != "1"') < compute_run.index("VALIDATOR_ARGS=(")
    alpha_registry_block = compute_run[
        compute_run.index("EXISTING_VERSION_FILE=$(mktemp)") : compute_run.index("VALIDATOR_ARGS=(")
    ]
    assert "list-versions --registry pypi" in alpha_registry_block
    assert "list-versions --registry testpypi" in alpha_registry_block
    for job_name in ("publish-alpha-testpypi", "publish-alpha-pypi", "release-alpha"):
        assert "build" in workflow["jobs"][job_name]["needs"]
        assert workflow["jobs"][job_name]["permissions"]["id-token"] == "write"
    assert "RELEASE_PUBLISHING_ENABLED" in workflow_text
    assert 'awk -v candidate="$RELEASE_VERSION"' in workflow_text
    assert "$0 != candidate" in workflow_text


def test_alpha_release_test_paths_exist() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    steps = workflow["jobs"]["alpha-cross-platform"]["steps"]

    for step in steps:
        command = step.get("run", "")
        if "pytest" not in command:
            continue
        for argument in command.split():
            if argument.startswith("tests/") and argument.endswith(".py"):
                assert (ROOT / argument).is_file(), f"release workflow references missing {argument}"


def test_alpha_publication_is_independent_of_cross_platform_tests() -> None:
    jobs = _workflow(PUBLISH_WORKFLOW)["jobs"]

    assert jobs["reserve-alpha-tag"]["needs"] == ["build"]
    assert jobs["publish-alpha-testpypi"]["needs"] == ["build", "reserve-alpha-tag"]
    assert jobs["publish-alpha-pypi"]["needs"] == [
        "build",
        "publish-alpha-testpypi",
    ]
    for job_name in ("reserve-alpha-tag", "publish-alpha-testpypi", "publish-alpha-pypi"):
        assert "alpha-cross-platform" not in jobs[job_name]["needs"]
        assert "needs.alpha-cross-platform" not in jobs[job_name]["if"]
    assert jobs["release-alpha"]["needs"] == ["build", "publish-alpha-pypi"]


def test_alpha_tag_is_reserved_atomically_before_testpypi() -> None:
    jobs = _workflow(PUBLISH_WORKFLOW)["jobs"]
    reserve = jobs["reserve-alpha-tag"]

    assert reserve["permissions"] == {"contents": "write"}
    checkout = next(step for step in reserve["steps"] if str(step.get("uses", "")).startswith("actions/checkout@"))
    assert _mapping(checkout["with"])["ref"] == "${{ needs.build.outputs.source_sha }}"
    reserve_run = next(step["run"] for step in reserve["steps"] if step.get("name") == "Reserve exact alpha tag")
    assert 'gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs"' in reserve_run
    assert '-f ref="refs/tags/${tag}"' in reserve_run
    assert '-f sha="$SOURCE_SHA"' in reserve_run
    assert 'remote_tag_sha" != "$SOURCE_SHA"' in reserve_run


def test_alpha_publication_uses_the_push_sha_without_branch_head_drift_gates() -> None:
    jobs = _workflow(PUBLISH_WORKFLOW)["jobs"]

    for job_name in (
        "reserve-alpha-tag",
        "publish-alpha-testpypi",
        "publish-alpha-pypi",
        "release-alpha",
        "publish-container",
    ):
        checkout = next(
            step for step in jobs[job_name]["steps"] if str(step.get("uses", "")).startswith("actions/checkout@")
        )
        assert _mapping(checkout["with"])["ref"] == "${{ needs.build.outputs.source_sha }}"

    for job_name in ("publish-alpha-testpypi", "publish-alpha-pypi"):
        commands = "\n".join(str(step.get("run", "")) for step in jobs[job_name]["steps"])
        assert "remote_train_sha=$(git ls-remote" not in commands
        assert '"$remote_train_sha" != "$SOURCE_SHA"' not in commands
        assert "refs/tags/alpha/v${VERSION}" in commands
        assert '"$remote_alpha_tag_sha" != "$SOURCE_SHA"' in commands


def test_release_publication_reuses_one_hashed_build_artifact() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]

    assert "distribution-sha256" in {
        step.get("with", {}).get("name") for step in jobs["build"]["steps"] if isinstance(step, dict)
    }
    assert jobs["publish-alpha-pypi"]["needs"] == [
        "build",
        "publish-alpha-testpypi",
    ]
    for job_name in (
        "publish-alpha-testpypi",
        "publish-alpha-pypi",
        "publish-main-testpypi",
        "publish-main-pypi",
    ):
        steps = jobs[job_name]["steps"]
        assert any(step.get("run") == "sha256sum --check distribution-sha256.txt" for step in steps)
        assert any(
            step.get("name") == "Keep only the Guard release distribution" and "plugin_scanner" in step.get("run", "")
            for step in steps
        )

    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    assert "skip-existing" not in workflow_text


def test_publish_jobs_use_registered_protected_environments() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]

    assert jobs["publish-testpypi"]["environment"] == "testpypi"
    assert jobs["publish-alpha-testpypi"]["environment"] == "testpypi"
    assert jobs["publish-alpha-pypi"]["environment"] == "pypi"
    assert jobs["publish-main-testpypi"]["environment"] == "testpypi"
    assert jobs["publish-main-pypi"]["environment"] == "pypi"
    assert jobs["publish-testpypi"]["permissions"] == {"id-token": "write"}
    assert jobs["publish-alpha-testpypi"]["permissions"] == {"contents": "read", "id-token": "write"}
    assert jobs["publish-alpha-pypi"]["permissions"] == {"contents": "read", "id-token": "write"}
    assert jobs["publish-main-testpypi"]["permissions"] == {"contents": "read", "id-token": "write"}
    assert jobs["publish-main-pypi"]["permissions"] == {"contents": "read", "id-token": "write"}
    for job_name in (
        "publish-alpha-testpypi",
        "publish-alpha-pypi",
        "publish-main-testpypi",
        "publish-main-pypi",
    ):
        assert "vars.RELEASE_PUBLISHING_ENABLED == 'true'" in jobs[job_name]["if"]


def test_registry_state_is_revalidated_at_each_publication_boundary() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]

    for job_name in ("publish-alpha-testpypi", "publish-main-testpypi"):
        steps = jobs[job_name]["steps"]
        inspect_step = next(step for step in steps if step.get("name") == "Inspect TestPyPI release state")
        publish_step = next(step for step in steps if str(step.get("uses", "")).startswith("pypa/"))
        cleanup_step = next(step for step in steps if step.get("name") == "Remove generated upload attestations")
        verify_step = next(step for step in steps if step.get("name") == "Download and verify exact TestPyPI artifacts")
        assert "verify-release --registry testpypi" in inspect_step["run"]
        assert publish_step["if"] == "steps.testpypi.outputs.upload == 'true'"
        assert cleanup_step["run"] == "rm -f dist/*.publish.attestation"
        assert steps.index(publish_step) < steps.index(cleanup_step) < steps.index(verify_step)
        assert "--download-dir verified-testpypi" in verify_step["run"]
        assert 'uv tool run --from "$wheel"' in verify_step["run"]
        assert 'status" == "exact"' in verify_step["run"]
        assert 'status" != "absent"' in verify_step["run"]
        assert "for attempt in {1..60}" in verify_step["run"]
        assert 'attempt" == "60"' in verify_step["run"]
        assert '== "hol-guard $VERSION"' in verify_step["run"]

    main_revalidation = next(
        step["run"] for step in jobs["publish-main-pypi"]["steps"] if step.get("name") == "Revalidate main publication"
    )
    assert "compute_main_release_version.py" in main_revalidation
    assert main_revalidation.count("uv run --with packaging==25.0") == 5
    assert "uv run --no-sync" not in main_revalidation
    assert "list-versions --registry pypi" in main_revalidation
    assert "list-versions --registry testpypi" in main_revalidation
    assert "'$pypi + $testpypi + [$version] | unique'" in main_revalidation
    assert '<<< "$RELEASE_VERSIONS"' in main_revalidation
    assert '[[ "$LATEST_RELEASE_VERSION" != "$VERSION" ]]' in main_revalidation
    assert "--latest-existing" in main_revalidation
    assert '<<< "$PRIOR_PYPI_VERSIONS"' in main_revalidation
    assert "refs/tags/v${LATEST_VERSION}" in main_revalidation
    assert 'git merge-base --is-ancestor "v${LATEST_VERSION}^{commit}" "$SOURCE_SHA"' in main_revalidation

    alpha_run = next(
        step["run"]
        for step in jobs["publish-alpha-pypi"]["steps"]
        if step.get("name") == "Revalidate alpha publication authorization"
    )
    assert "list-versions --registry pypi" not in alpha_run
    assert 'git ls-remote --exit-code origin "refs/tags/alpha/v${VERSION}"' in alpha_run
    assert "validate_alpha_release.py" in alpha_run
    assert "refs/tags/alpha/v${VERSION}" in alpha_run
    assert 'awk -v candidate="$VERSION"' not in alpha_run

    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    assert 'for registry in ("pypi.org", "test.pypi.org")' not in workflow_text

    for job_name in ("publish-alpha-pypi", "publish-main-pypi"):
        steps = jobs[job_name]["steps"]
        inspect_step = next(step for step in steps if step.get("name") == "Inspect PyPI release state")
        publish_step = next(step for step in steps if str(step.get("uses", "")).startswith("pypa/"))
        cleanup_step = next(step for step in steps if step.get("name") == "Remove generated upload attestations")
        verify_step = next(step for step in steps if step.get("name") == "Download and verify exact PyPI artifacts")
        assert "verify-release --registry pypi" in inspect_step["run"]
        assert publish_step["if"] == "steps.pypi.outputs.upload == 'true'"
        assert cleanup_step["run"] == "rm -f dist/*.publish.attestation"
        assert steps.index(publish_step) < steps.index(cleanup_step) < steps.index(verify_step)
        assert "--download-dir verified-pypi" in verify_step["run"]
        assert 'status" == "exact"' in verify_step["run"]
        assert 'status" != "absent"' in verify_step["run"]
        assert "for attempt in {1..60}" in verify_step["run"]
        assert 'attempt" == "60"' in verify_step["run"]
        assert '== "hol-guard $VERSION"' in verify_step["run"]


def test_release_tags_are_bound_to_the_exact_published_source() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]

    alpha_test_run = next(
        step["run"]
        for step in jobs["publish-alpha-testpypi"]["steps"]
        if step.get("name") == "Revalidate alpha source before TestPyPI"
    )
    assert 'git ls-remote --exit-code origin "$train_ref"' not in alpha_test_run
    assert "refs/tags/alpha/v${VERSION}" in alpha_test_run
    assert '[[ "$remote_alpha_tag_sha" != "$SOURCE_SHA" ]]' in alpha_test_run

    alpha_pypi_run = next(
        step["run"]
        for step in jobs["publish-alpha-pypi"]["steps"]
        if step.get("name") == "Revalidate alpha publication authorization"
    )
    assert '[[ "$remote_alpha_tag_sha" != "$SOURCE_SHA" ]]' in alpha_pypi_run

    release_run = next(
        step["run"]
        for step in jobs["release-alpha"]["steps"]
        if step.get("name") == "Create discoverable alpha prerelease"
    )
    assert 'remote_tag_sha" != "$SOURCE_SHA"' in release_run
    assert 'gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs"' not in release_run
    assert 'gh release view "$tag" --json isDraft,isPrerelease' in release_run
    assert 'gh release download "$tag"' in release_run
    assert 'cmp --silent "$local_file"' in release_run
    assert "mapfile -d '' local_files" in release_run
    assert 'gh attestation verify "$remote_file"' in release_run
    assert '--bundle "$bundle" --source-digest "$SOURCE_SHA"' in release_run
    assert '--target "$SOURCE_SHA"' in release_run
    assert "--verify-tag" in release_run
    assert 'git ls-remote --exit-code origin "refs/tags/${tag}"' in release_run

    main_release_run = next(
        step["run"] for step in jobs["release-main"]["steps"] if step.get("name") == "Create discoverable main release"
    )
    assert 'tag="v${VERSION}"' in main_release_run
    assert 'gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs"' in main_release_run
    assert '-f sha="$SOURCE_SHA"' in main_release_run
    assert 'remote_tag_sha" != "$SOURCE_SHA"' in main_release_run
    assert 'gh release view "$tag" --json isDraft,isPrerelease' in main_release_run
    assert "Existing stable release is a draft or prerelease" in main_release_run
    assert 'remote_guard_files=("$existing_dir"/hol_guard-*)' in main_release_run
    assert '[[ "${#remote_guard_files[@]}" -gt 0 ]]' in main_release_run
    assert 'gh attestation verify "$remote_file"' in main_release_run
    assert '--bundle "$bundle" --source-digest "$SOURCE_SHA"' in main_release_run
    assert "--verify-tag" in main_release_run


def test_release_21_dispatch_remains_alpha_only_while_main_is_stable() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]
    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert "channel == 'alpha'" in jobs["release-alpha"]["if"]
    assert "github.event_name == 'workflow_dispatch'" in jobs["release-alpha"]["if"]
    assert "channel == 'stable'" in jobs["publish-container"]["if"]
    assert jobs["publish-container"]["needs"] == [
        "build",
        "publish-alpha-pypi",
        "publish-main-pypi",
        "release-alpha",
        "release-main",
    ]
    assert {"publish-main-testpypi", "publish-main-pypi", "release-main"} <= jobs.keys()
    assert jobs["publish-main-testpypi"]["environment"] == "testpypi"
    assert jobs["publish-main-pypi"]["environment"] == "pypi"
    assert "refs/tags/${tag}" in workflow_text
    assert "--channel stable" not in workflow_text
    inputs = workflow[True]["workflow_dispatch"]["inputs"]
    assert inputs["release_channel"]["options"] == ["alpha"]
