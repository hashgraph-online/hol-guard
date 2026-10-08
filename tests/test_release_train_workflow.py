"""Security contracts for release-train publishing."""

from __future__ import annotations

from pathlib import Path

import yaml

from tests.support.ci_workflow import expand_ci_job_actions

ROOT = Path(__file__).resolve().parents[1]
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"
CI_BRANCHES = ["main", "release/3.0", "release/3.1", "release/3.2"]
RELEASE_BRANCHES = ["main", "release/3.0"]
PR_CANARY_BRANCHES = ["main", "release/3.0", "release/3.2"]
RELEASE_MAINTAINERS = {"@kantorcodes", "@deep-purple-boots", "@zerocodefast"}


def _workflow(path: Path) -> dict[object, object]:
    workflow = expand_ci_job_actions(yaml.safe_load(path.read_text(encoding="utf-8")))
    assert isinstance(workflow, dict)
    return workflow


def test_release_codeowners_are_the_named_maintainers() -> None:
    pattern, *owners = CODEOWNERS.read_text(encoding="utf-8").split()

    assert pattern == "*"
    assert set(owners) == RELEASE_MAINTAINERS
    assert len(owners) == len(RELEASE_MAINTAINERS)


def test_release_native_binary_and_base_wheel_use_the_same_regenerated_program() -> None:
    jobs = _workflow(PUBLISH_WORKFLOW)["jobs"]
    build_steps = jobs["build"]["steps"]
    source_generation = next(
        step for step in build_steps if step.get("name") == "Generate projections for release source distributions"
    )
    assert "if" not in source_generation
    assert "cargo +1.88.0 build" in source_generation["run"]
    assert build_steps.index(source_generation) < next(
        index for index, step in enumerate(build_steps) if step.get("name") == "Build Guard package (hol-guard)"
    )
    steps = jobs["build-native-guard-wheels"]["steps"]
    verify = next(step for step in steps if step.get("name") == "Verify native command program is current")
    run = verify["run"]
    generate = 'python scripts/build_native_command_program.py --compiler "$SOURCE_COMPILER"'
    assert '[[ "${{ github.event_name }}" == "pull_request" ]]' in run
    assert run.index(generate) < run.index("cargo build") < run.index("verify_native_command_program.py")
    assert verify["env"]["RUST_TARGET"] == "${{ matrix.target }}"
    rebuild = next(
        step for step in steps if step.get("name") == "Rebuild Guard base wheel after projection regeneration"
    )
    assert "if" not in rebuild
    setup_uv = next(step for step in steps if str(step.get("uses", "")).startswith("astral-sh/setup-uv@"))
    assert "if" not in setup_uv


def test_release_branches_run_ci_and_pr_canaries() -> None:
    ci = _workflow(CI_WORKFLOW)
    publish = _workflow(PUBLISH_WORKFLOW)

    assert ci[True]["push"]["branches"] == CI_BRANCHES
    assert ci[True]["pull_request"]["branches"] == PR_CANARY_BRANCHES
    assert publish[True]["push"]["branches"] == RELEASE_BRANCHES
    assert publish[True]["pull_request"]["branches"] == PR_CANARY_BRANCHES
    assert publish[True]["pull_request"]["types"] == [
        "opened",
        "synchronize",
        "reopened",
        "labeled",
    ]
    assert "tags" not in publish[True]["push"]


def test_release_branch_pushes_publish_alpha_while_stable_publish_is_manual() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]

    for job_name in (
        "publish-alpha-testpypi",
        "publish-alpha-pypi",
        "release-alpha",
        "publish-container",
    ):
        condition = jobs[job_name]["if"]
        assert "github.event_name == 'workflow_dispatch'" in condition
        assert "github.event_name == 'push'" in condition
        assert "github.ref == 'refs/heads/release/3.0'" in condition
        assert "github.event.action == 'closed'" not in condition
    for job_name in ("publish-main-testpypi", "reserve-main-tag", "publish-main-pypi", "release-main"):
        condition = jobs[job_name]["if"]
        assert "github.event_name == 'workflow_dispatch'" in condition
        assert "github.run_attempt == 1" in condition
        assert "github.ref == 'refs/heads/main'" in condition
        assert "github.event.inputs.release_channel == 'stable'" in condition
        assert "github.event.inputs.release_train == 'main'" in condition
        assert "github.event_name == 'push'" not in condition
        assert "needs.build.outputs.channel == 'stable'" in condition
    assert jobs["reserve-main-tag"]["needs"] == ["build", "assemble-native-guard-distributions"]
    assert jobs["reserve-main-tag"]["permissions"] == {"contents": "write"}
    reserve_run = next(
        step["run"]
        for step in jobs["reserve-main-tag"]["steps"]
        if step.get("name") == "Bind stable tag to the exact main source"
    )
    assert "git ls-remote --exit-code origin refs/heads/main" in reserve_run
    assert "git merge-base --is-ancestor" in reserve_run
    assert "Stable tag source is not an ancestor of main" in reserve_run
    assert '-f ref="refs/tags/${tag}"' in reserve_run
    assert '-f sha="$SOURCE_SHA"' in reserve_run
    assert 'git fetch --force --no-tags origin "+refs/tags/${tag}:refs/tags/${tag}"' in reserve_run
    assert 'git rev-parse "${tag}^{commit}"' in reserve_run
    assert "verifying the resulting remote ref" in reserve_run
    assert jobs["publish-main-pypi"]["needs"] == [
        "build",
        "assemble-native-guard-distributions",
        "reserve-main-tag",
    ]
    assert "needs.reserve-main-tag.result == 'success'" in jobs["publish-main-pypi"]["if"]
    assert "needs.publish-main-testpypi.result == 'success'" not in jobs["publish-main-pypi"]["if"]
    assert "vars.MAIN_TESTPYPI_ENABLED == 'true'" in jobs["publish-main-testpypi"]["if"]
    assert jobs["release-main"]["needs"] == [
        "build",
        "assemble-native-guard-distributions",
        "publish-main-pypi",
        "publish-main-assets",
    ]

    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    assert "startsWith(github.ref, 'refs/tags/')" not in workflow_text
    assert "github.ref == 'refs/heads/main'" in workflow_text


def test_stable_dispatch_computes_and_requires_the_registry_derived_version() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    build_steps = workflow["jobs"]["build"]["steps"]
    compute_run = next(step["run"] for step in build_steps if step.get("name") == "Compute publish version")
    stamp_step = next(step for step in build_steps if step.get("name") == "Stamp package version when needed")
    stamp_run = stamp_step["run"]

    assert 'VERSION="$BASE_VERSION"' in compute_run
    assert 'elif [[ "$GITHUB_EVENT_NAME" == "push" && "$GITHUB_REF" == "refs/heads/release/3.0" ]]' in compute_run
    assert "pull_request" in compute_run
    assert "PR_MERGE_SHA" not in compute_run
    assert 'SOURCE_SHA" != "$EXPECTED_SOURCE"' in compute_run
    assert 'TRAIN="3.0"' in compute_run
    assert "compute_alpha_release_version.py" in compute_run
    assert "validate_alpha_release.py" in compute_run
    assert 'elif [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]' in compute_run
    assert 'elif [[ "$CHANNEL" == "stable" && "$TRAIN" == "main" ]]' in compute_run
    assert (
        'if [[ "$GITHUB_REF" != "refs/heads/main" && "$GITHUB_REF" != "refs/tags/v${RELEASE_VERSION}" ]]' in compute_run
    )
    assert 'CHANNEL="$RELEASE_CHANNEL"' in compute_run
    assert "verify_release_registry.py" in compute_run
    assert "list-versions --registry pypi" in compute_run
    assert "list-versions --registry testpypi" in compute_run
    assert "git tag --list 'v*'" in compute_run
    assert "'$pypi + $testpypi + ($tags | map(select(. != $candidate))) | unique'" in compute_run
    assert '--arg candidate "$RELEASE_VERSION"' in compute_run
    assert "compute_main_release_version.py" in compute_run
    assert 'git merge-base --is-ancestor "$tag_sha" HEAD' in compute_run
    assert 'SOURCE_SHA="$tag_sha"' in compute_run
    assert 'if [[ "$RELEASE_VERSION" != "$EXPECTED_VERSION" ]]' in compute_run
    assert 'VERSION="$RELEASE_VERSION"' in compute_run
    assert 'elif [[ "$GITHUB_EVENT_NAME" == "push" && "$GITHUB_REF" == "refs/heads/main" ]]' not in compute_run
    assert "if" not in stamp_step
    assert "sync_repo_version.py --check" in stamp_run
    assert '[[ "$CURRENT_VERSION" == "$VERSION" ]]' in stamp_run
    assert 'sync_repo_version.py --version "$VERSION"' in stamp_run
    condition = '[[ "$CURRENT_VERSION" == "$VERSION" ]]'
    assert stamp_run.index("--check") < stamp_run.index(condition)
    assert stamp_run.index(condition) < stamp_run.index("--version")


def test_manual_release_and_pr_version_stamping_contracts() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    build_steps = workflow["jobs"]["build"]["steps"]
    compute_run = next(step["run"] for step in build_steps if step.get("name") == "Compute publish version")
    stamp_run = next(step["run"] for step in build_steps if step.get("name") == "Stamp package version when needed")

    assert 'if [[ "$CHANNEL" == "alpha" && "$TRAIN" == "3.0" ]]' in compute_run
    assert 'elif [[ "$CHANNEL" == "stable" && "$TRAIN" == "main" ]]' in compute_run
    assert "Unsupported release channel and train" in compute_run
    assert "VERSION=$(uv run --no-sync python scripts/validate_alpha_release.py" in compute_run
    assert 'VERSION=$(BASE_VERSION="$BASE_VERSION" PR_NUMBER="$PR_NUMBER"' in compute_run
    assert 'sync_repo_version.py --version "$VERSION"' in stamp_run and "3.0.0a0" not in stamp_run


def test_release_dispatch_binds_channel_train_version_and_sha() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    inputs = workflow[True]["workflow_dispatch"]["inputs"]
    jobs = workflow["jobs"]
    build_steps = workflow["jobs"]["build"]["steps"]

    assert inputs["release_channel"]["options"] == ["alpha", "stable"]
    assert inputs["release_train"]["options"] == ["3.0", "main"]
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
    assert dispatch_gate["name"] == "Enforce release authority"
    assert dispatch_gate["if"] == "github.event_name == 'workflow_dispatch'"
    assert not any("uses" in step for step in authorize_job["steps"])
    assert '"$GITHUB_RUN_ATTEMPT" != "1"' in dispatch_gate["run"]
    assert '"$GITHUB_ACTOR_ID" != "6068672"' in dispatch_gate["run"]
    assert '"$GITHUB_ACTOR_ID" != "301892678"' in dispatch_gate["run"]
    assert "alpha:3.0:refs/heads/release/3.0" in dispatch_gate["run"]
    assert "stable:main:refs/heads/main" in dispatch_gate["run"]
    assert '"$EXPECTED_SHA" != "$GITHUB_SHA"' in dispatch_gate["run"]
    assert jobs["build"]["needs"] == "authorize-release"
    build_condition = jobs["build"]["if"]
    assert "github.event_name != 'workflow_dispatch' || github.run_attempt == 1" in build_condition
    assert "github.event_name != 'push' || github.run_attempt == 1" in build_condition
    assert "alpha-cross-platform" not in jobs
    for job_name in (
        "publish-alpha-testpypi",
        "publish-alpha-pypi",
        "release-alpha",
        "publish-container",
    ):
        assert "github.run_attempt == 1" in jobs[job_name]["if"]
    compute_run = next(step["run"] for step in build_steps if step.get("name") == "Compute publish version")
    assert 'if [[ "$CHANNEL" == "alpha" && "$TRAIN" == "3.0" ]]' in compute_run
    assert 'elif [[ "$CHANNEL" == "stable" && "$TRAIN" == "main" ]]' in compute_run
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


def test_release_tags_are_bound_to_the_exact_published_source() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]

    alpha_test_run = next(
        step["run"]
        for step in jobs["publish-alpha-testpypi"]["steps"]
        if step.get("name") == "Revalidate alpha source before TestPyPI"
    )
    assert 'git ls-remote --exit-code origin "$train_ref"' in alpha_test_run
    assert '"$remote_train_sha" != "$SOURCE_SHA"' in alpha_test_run
    assert "refs/tags/alpha/v${VERSION}" in alpha_test_run
    assert '"$remote_alpha_tag_sha" != "$SOURCE_SHA"' in alpha_test_run

    alpha_pypi_run = next(
        step["run"]
        for step in jobs["publish-alpha-pypi"]["steps"]
        if step.get("name") == "Revalidate alpha publication authorization"
    )
    assert '"$remote_alpha_tag_sha" != "$SOURCE_SHA"' in alpha_pypi_run

    alpha_run = next(
        step["run"]
        for step in jobs["release-alpha"]["steps"]
        if step.get("name") == "Create discoverable alpha prerelease"
    )
    assert 'gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs"' in alpha_run
    assert '-f ref="refs/tags/${tag}"' in alpha_run
    assert 'remote_tag_sha" != "$SOURCE_SHA"' in alpha_run
    assert 'gh release view "$tag" --json isDraft,isPrerelease' in alpha_run
    assert 'gh release download "$tag"' in alpha_run and "verify_release_asset_inventory.py" in alpha_run
    assert 'cmp --silent "$local_file"' in alpha_run
    assert '"$existing_dir" dist "$VERSION" alpha' in alpha_run
    assert "mapfile -d '' local_files" in alpha_run
    assert 'gh attestation verify "$remote_file"' in alpha_run and '--bundle "$bundle"' in alpha_run
    assert '--source-digest "$SOURCE_SHA"' in alpha_run and "--verify-tag" in alpha_run

    stable_run = next(
        step["run"] for step in jobs["release-main"]["steps"] if step.get("name") == "Create discoverable main release"
    )
    assert 'tag="v${VERSION}"' in stable_run
    assert 'git fetch --force --no-tags origin "+refs/tags/${tag}:refs/tags/${tag}"' in stable_run
    assert 'git rev-parse "${tag}^{commit}"' in stable_run
    assert 'remote_tag_sha" != "$SOURCE_SHA"' in stable_run
    assert 'gh release view "$tag" --json isDraft,isPrerelease,assets' in stable_run
    assert 'gh release upload "$tag"' in stable_run
    assert 'gh release edit "$tag" --notes-file "$RUNNER_TEMP/release-notes.md"' in stable_run
    assert '[[ -s "$RUNNER_TEMP/release-notes.md" ]]' in stable_run
    assert "Existing stable release is a draft or prerelease" in stable_run
    assert "remote_guard_files=" in stable_run and "verify_release_asset_inventory.py" in stable_run
    assert '[[ "${#remote_guard_files[@]}" -gt 0 ]]' in stable_run
    assert 'gh attestation verify "$remote_file"' in stable_run
    assert '--bundle "$bundle" --source-digest "$SOURCE_SHA"' in stable_run
    assert "--verify-tag" in stable_run and '"$existing_dir" dist "$VERSION" stable' in stable_run


def test_release_3x_alpha_branches_remain_automatic_while_main_stable_is_manual() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]
    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert "channel == 'alpha'" in jobs["release-alpha"]["if"]
    assert "github.event_name == 'push'" in jobs["release-alpha"]["if"]
    assert "github.ref == 'refs/heads/release/3.0'" in jobs["release-alpha"]["if"]
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
    inputs = workflow[True]["workflow_dispatch"]["inputs"]
    assert inputs["release_channel"]["options"] == ["alpha", "stable"]
    assert inputs["release_train"]["options"] == ["3.0", "main"]
    assert "github.event.inputs.release_channel == 'stable'" in jobs["publish-container"]["if"]
    assert "github.event.inputs.release_train == 'main'" in jobs["publish-container"]["if"]


def test_release_push_can_be_explicitly_suppressed_by_merge_marker() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    condition = workflow["jobs"]["build"]["if"]

    assert "github.event_name != 'push'" in condition
    assert "github.event.head_commit.message || ''" in condition
    assert "[skip release publish]" in condition
    assert "github.event.action != 'closed'" not in workflow["jobs"]["build"]["if"]


def test_release_branch_push_is_the_single_automatic_alpha_publisher() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]
    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert "closed" not in workflow[True]["pull_request"]["types"]
    assert "github.event.pull_request.merge_commit_sha" not in workflow_text
    assert "group: hol-guard-publish-${{ github.ref }}" in workflow_text
    for job_name in (
        "reserve-alpha-tag",
        "publish-alpha-testpypi",
        "publish-alpha-pypi",
        "release-alpha",
    ):
        condition = jobs[job_name]["if"]
        assert "github.event.action == 'closed'" not in condition
        assert "github.event.pull_request.merged" not in condition
