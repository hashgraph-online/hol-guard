"""Security contracts for release-train publishing."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"
CI_BRANCHES = ["main", "release/3.0", "release/3.1"]
RELEASE_BRANCHES = ["main", "release/3.0"]
PR_CANARY_BRANCHES = ["main", "release/3.0", "release/3.2"]
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


def test_release_branch_pushes_publish_alpha_while_main_pushes_publish_stable() -> None:
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
        assert "github.event_name == 'push'" in condition
        assert "github.run_attempt == 1" in condition
        assert "github.ref == 'refs/heads/main'" in condition
        assert "needs.build.outputs.channel == 'stable'" in condition
    assert jobs["reserve-main-tag"]["needs"] == ["build", "assemble-native-guard-distributions"]
    assert jobs["reserve-main-tag"]["permissions"] == {"contents": "write"}
    reserve_run = next(
        step["run"]
        for step in jobs["reserve-main-tag"]["steps"]
        if step.get("name") == "Bind stable tag to the exact main source"
    )
    assert "git ls-remote --exit-code origin refs/heads/main" in reserve_run
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
    ]

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
    assert 'elif [[ "$GITHUB_EVENT_NAME" == "push" && "$GITHUB_REF" == "refs/heads/release/3.0" ]]' in compute_run
    assert "pull_request" in compute_run
    assert "PR_MERGE_SHA" not in compute_run
    assert 'SOURCE_SHA" != "$EXPECTED_SOURCE"' in compute_run
    assert 'TRAIN="3.0"' in compute_run
    assert "compute_alpha_release_version.py" in compute_run
    assert "validate_alpha_release.py" in compute_run
    assert 'elif [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]' in compute_run
    assert 'elif [[ "$GITHUB_EVENT_NAME" == "push" && "$GITHUB_REF" == "refs/heads/main" ]]' in compute_run
    assert 'CHANNEL="stable"' in compute_run
    assert "verify_release_registry.py" in compute_run
    assert "list-versions --registry pypi" in compute_run
    assert "list-versions --registry testpypi" in compute_run
    assert "git tag --list 'v*'" in compute_run
    assert "'$pypi + $testpypi + $tags | unique'" in compute_run
    assert "compute_main_release_version.py" in compute_run
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
    assert "The release/3.0 train is alpha-only" in compute_run
    assert 'elif [[ "$CHANNEL" == "stable" ]]' not in compute_run
    assert "VERSION=$(uv run --no-sync python scripts/validate_alpha_release.py" in compute_run
    assert 'VERSION=$(BASE_VERSION="$BASE_VERSION" PR_NUMBER="$PR_NUMBER"' in compute_run
    assert 'sync_repo_version.py --version "$VERSION"' in stamp_run and "3.0.0a0" not in stamp_run


def test_release_dispatch_binds_channel_train_version_and_sha() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    inputs = workflow[True]["workflow_dispatch"]["inputs"]
    jobs = workflow["jobs"]
    build_steps = workflow["jobs"]["build"]["steps"]

    assert inputs["release_channel"]["options"] == ["alpha"]
    assert inputs["release_train"]["options"] == ["3.0"]
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
    assert '"$RELEASE_TRAIN" != "3.0"' in dispatch_gate["run"]
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
    assert 'if [[ "$CHANNEL" != "alpha" ]]' in compute_run
    assert 'if [[ "$TRAIN" != "3.0" ]]' in compute_run
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


def test_release_publication_reuses_one_hashed_build_artifact() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    jobs = workflow["jobs"]

    assert "distribution-sha256" in {
        step.get("with", {}).get("name") for step in jobs["build"]["steps"] if isinstance(step, dict)
    }
    native_pin = next(
        step
        for step in jobs["build-native-guard-wheels"]["steps"]
        if step.get("name") == "Verify release approval enrollment root pin"
    )
    assert "--require-release-root" in native_pin["run"]
    assert "canary" in str(native_pin.get("if", ""))
    alpha_needs = ["build", "reserve-alpha-tag", "assemble-native-guard-distributions"]
    assert jobs["publish-alpha-testpypi"]["needs"] == alpha_needs
    assert jobs["publish-alpha-pypi"]["needs"] == alpha_needs
    assemble = jobs["assemble-native-guard-distributions"]
    assert assemble["needs"] == ["build", "build-native-guard-wheels"]
    assert "needs.build.result == 'success'" in assemble["if"]
    assert "needs.build-native-guard-wheels.result == 'success'" in assemble["if"]
    native_if = jobs["build-native-guard-wheels"]["if"]
    assert "channel == 'stable'" in native_if
    assert "refs/heads/main" in native_if
    assemble_steps = assemble["steps"]
    assert any(step.get("with", {}).get("name") == "distributions" for step in assemble_steps)
    assert any(
        step.get("with", {}).get("pattern") == "native-guard-wheel-*"
        and step.get("with", {}).get("merge-multiple") is True
        for step in assemble_steps
    )
    assert any(step.get("with", {}).get("name") == "distributions-native" for step in assemble_steps)
    assert any(step.get("with", {}).get("name") == "distribution-sha256-native" for step in assemble_steps)
    assert "needs.publish-alpha-testpypi" not in jobs["publish-alpha-pypi"]["if"]
    assert "vars.ALPHA_TESTPYPI_ENABLED" not in jobs["publish-alpha-pypi"]["if"]
    assert "vars.ALPHA_TESTPYPI_ENABLED == 'true'" in jobs["publish-alpha-testpypi"]["if"]
    for job_name in ("publish-alpha-testpypi", "publish-alpha-pypi", "publish-main-pypi"):
        steps = jobs[job_name]["steps"]
        assert any(step.get("with", {}).get("name") == "distributions-native" for step in steps)
        assert any(step.get("with", {}).get("name") == "distribution-sha256-native" for step in steps)
        assert any(step.get("run") == "sha256sum --check distribution-sha256-native.txt" for step in steps)

    for job_name in ("publish-alpha-testpypi", "publish-main-testpypi"):
        steps = jobs[job_name]["steps"]
        assert any(
            step.get("name") == "Keep only the Guard release distribution" and "plugin_scanner" in step.get("run", "")
            for step in steps
        )
    release_alpha_steps = jobs["release-alpha"]["steps"]
    assert any(step.get("with", {}).get("name") == "distributions-native" for step in release_alpha_steps)
    assert any(step.get("with", {}).get("name") == "distribution-sha256-native" for step in release_alpha_steps)
    assert any(
        "sha256sum --check distribution-sha256-native.txt" in step.get("run", "") for step in release_alpha_steps
    )
    release_main_steps = jobs["release-main"]["steps"]
    assert any(step.get("with", {}).get("name") == "distributions-native" for step in release_main_steps)
    assert any(step.get("with", {}).get("name") == "distribution-sha256-native" for step in release_main_steps)
    assert any("sha256sum --check distribution-sha256-native.txt" in step.get("run", "") for step in release_main_steps)
    for job_name in ("publish-main-testpypi",):
        steps = jobs[job_name]["steps"]
        assert any(step.get("run") == "sha256sum --check distribution-sha256-native.txt" for step in steps)
        assert any(step.get("with", {}).get("name") == "distributions-native" for step in steps)
        assert any(
            step.get("name") == "Keep only the Guard release distribution" and "plugin_scanner" in step.get("run", "")
            for step in steps
        )

    public_hashes = {
        "publish-alpha-pypi": "sha256sum --check distribution-sha256-native.txt",
        "publish-main-pypi": "sha256sum --check distribution-sha256-native.txt",
    }
    for job_name in ("publish-alpha-pypi", "publish-main-pypi"):
        steps = jobs[job_name]["steps"]
        assert any(step.get("run") == public_hashes[job_name] for step in steps)
        prepare_step = next(step for step in steps if step.get("name") == "Prepare project-specific distributions")
        assert "dist-hol-guard" in prepare_step["run"]
        assert "dist-plugin-scanner" in prepare_step["run"]
        assert not any(step.get("name") == "Keep only the Guard release distribution" for step in steps)

    alpha_prepare = next(
        step
        for step in jobs["publish-alpha-pypi"]["steps"]
        if step.get("name") == "Prepare project-specific distributions"
    )
    assert '"${#guard_files[@]}" -ge "2"' in alpha_prepare["run"]
    stable_prepare = next(
        step
        for step in jobs["publish-main-pypi"]["steps"]
        if step.get("name") == "Prepare project-specific distributions"
    )
    assert '"${#guard_files[@]}" -ge "6"' in stable_prepare["run"]
    main_steps = jobs["publish-main-pypi"]["steps"]
    native_validate = next(step for step in main_steps if step.get("name") == "Validate native Guard release set")
    assert "validate-local" in native_validate["run"] and "--artifact-set full" in native_validate["run"]
    main_quota = next(
        step for step in main_steps if step.get("name") == "Refuse PyPI upload when the project is over quota"
    )
    assert "--pending-dir dist-hol-guard" in main_quota["run"]
    main_verify = next(step for step in main_steps if step.get("name") == "Download and verify exact PyPI artifacts")
    assert "--artifact-set full" in main_verify["run"]
    assert "verify-published" in main_verify["run"]

    stable_native = jobs["build-native-guard-wheels"]["if"]
    assert "needs.build.outputs.channel == 'stable'" in stable_native
    assert "github.ref == 'refs/heads/main'" in stable_native
    for job_name in ("publish-main-testpypi", "publish-main-pypi", "release-main"):
        job = jobs[job_name]
        assert "assemble-native-guard-distributions" in job["needs"]
        assert "needs.assemble-native-guard-distributions.result == 'success'" in job["if"]
        assert any(
            step.get("with", {}).get("name") == "distributions-native"
            for step in job["steps"]
        )

    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    assert "skip-existing" not in workflow_text and "pytest" not in workflow_text


def test_alpha_tag_reservation_binds_version_to_build_source() -> None:
    workflow = _workflow(PUBLISH_WORKFLOW)
    job = workflow["jobs"]["reserve-alpha-tag"]

    assert job["needs"] == ["build", "assemble-native-guard-distributions"]
    assert job["permissions"] == {"contents": "write"}
    assert "needs.build.outputs.channel == 'alpha'" in job["if"]
    reservation_run = next(step["run"] for step in job["steps"] if step.get("name") == "Reserve exact alpha tag")
    script = ROOT.joinpath("scripts", "reserve_alpha_tag.sh").read_text(encoding="utf-8")
    assert reservation_run == "bash scripts/reserve_alpha_tag.sh"
    assert 'tag="alpha/v${VERSION}"' in script
    assert '-f sha="$SOURCE_SHA"' in script


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

    alpha_test_steps = jobs["publish-alpha-testpypi"]["steps"]
    alpha_test_plan = next(step for step in alpha_test_steps if step.get("name") == "Plan TestPyPI release upload")
    alpha_test_publish = next(step for step in alpha_test_steps if str(step.get("uses", "")).startswith("pypa/"))
    alpha_test_cleanup = next(
        step for step in alpha_test_steps if step.get("name") == "Remove generated upload attestations"
    )
    alpha_test_verify = next(
        step for step in alpha_test_steps if step.get("name") == "Download and verify exact TestPyPI artifacts"
    )
    assert "plan-upload --registry testpypi" in alpha_test_plan["run"]
    assert '--source-sha "$SOURCE_SHA"' in alpha_test_plan["run"]
    assert alpha_test_publish["if"] == "steps.testpypi.outputs.upload == 'true'"
    assert alpha_test_publish["with"]["packages-dir"] == "upload-dist/"
    assert alpha_test_cleanup["run"] == "rm -f dist/*.publish.attestation upload-dist/*.publish.attestation"
    assert (
        alpha_test_steps.index(alpha_test_publish)
        < alpha_test_steps.index(alpha_test_cleanup)
        < alpha_test_steps.index(alpha_test_verify)
    )
    assert "--download-dir verified-testpypi" in alpha_test_verify["run"]
    assert "verify-published --registry testpypi" in alpha_test_verify["run"]
    assert 'uv tool run --from "$wheel"' in alpha_test_verify["run"]
    assert 'status" == "exact"' in alpha_test_verify["run"]
    assert 'status" != "absent"' in alpha_test_verify["run"]
    assert "for attempt in {1..60}" in alpha_test_verify["run"]
    assert 'attempt" == "60"' in alpha_test_verify["run"]
    assert '== "hol-guard $VERSION"' in alpha_test_verify["run"]

    main_test_steps = jobs["publish-main-testpypi"]["steps"]
    main_test_inspect = next(step for step in main_test_steps if step.get("name") == "Inspect TestPyPI release state")
    main_test_publish = next(step for step in main_test_steps if str(step.get("uses", "")).startswith("pypa/"))
    main_test_cleanup = next(
        step for step in main_test_steps if step.get("name") == "Remove generated upload attestations"
    )
    main_test_verify = next(
        step for step in main_test_steps if step.get("name") == "Download and verify exact TestPyPI artifacts"
    )
    assert "verify-release --registry testpypi" in main_test_inspect["run"]
    assert main_test_publish["if"] == "steps.testpypi.outputs.upload == 'true'"
    assert main_test_cleanup["run"] == "rm -f dist/*.publish.attestation"
    assert (
        main_test_steps.index(main_test_publish)
        < main_test_steps.index(main_test_cleanup)
        < main_test_steps.index(main_test_verify)
    )
    assert "--download-dir verified-testpypi" in main_test_verify["run"]
    assert 'select(endswith("-py3-none-any.whl"))' in main_test_verify["run"]
    assert '"${#wheels[@]}" == "1"' in main_test_verify["run"]

    main_revalidation = next(
        step["run"] for step in jobs["publish-main-pypi"]["steps"] if step.get("name") == "Revalidate main publication"
    )
    main_testpypi_revalidation = next(
        step["run"]
        for step in jobs["publish-main-testpypi"]["steps"]
        if step.get("name") == "Revalidate main source before TestPyPI"
    )
    assert "git ls-remote --exit-code origin refs/heads/main" in main_testpypi_revalidation
    assert '[[ "$remote_main_sha" != "$SOURCE_SHA" ]]' in main_testpypi_revalidation
    assert "Main publication source is no longer the branch head" in main_testpypi_revalidation
    assert 'git merge-base --is-ancestor "$SOURCE_SHA" refs/remotes/origin/main' not in main_testpypi_revalidation
    assert 'git fetch --no-tags origin "+refs/tags/v${VERSION}:refs/tags/v${VERSION}"' in main_revalidation
    assert 'git rev-parse "v${VERSION}^{commit}"' in main_revalidation
    assert '[[ "$reserved_source_sha" != "$SOURCE_SHA" ]]' in main_revalidation
    assert "Stable tag does not target the exact publication source" in main_revalidation
    assert "refs/heads/main" not in main_revalidation
    assert "compute_main_release_version.py" in main_revalidation
    assert main_revalidation.count("uv run --with packaging==25.0") == 5
    assert "uv run --no-sync" not in main_revalidation
    assert "list-versions --registry pypi" in main_revalidation
    assert "list-versions --registry testpypi" in main_revalidation
    assert "git tag --list 'v*'" in main_revalidation
    assert "'$pypi + $testpypi + $tags + [$version] | unique'" in main_revalidation
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
    assert "list-versions --registry pypi" in alpha_run
    assert 'git ls-remote --exit-code origin "$train_ref"' in alpha_run
    assert '"$remote_train_sha" != "$SOURCE_SHA"' in alpha_run
    assert "validate_alpha_release.py" in alpha_run
    assert "refs/tags/alpha/v${VERSION}" in alpha_run
    assert 'awk -v candidate="$VERSION"' in alpha_run

    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    assert 'for registry in ("pypi.org", "test.pypi.org")' not in workflow_text

    for job_name in ("publish-main-pypi",):
        steps = jobs[job_name]["steps"]
        inspect_step = next(step for step in steps if step.get("name") == "Inspect PyPI release state")
        publish_steps = [step for step in steps if str(step.get("uses", "")).startswith("pypa/")]
        cleanup_step = next(step for step in steps if step.get("name") == "Remove generated upload attestations")
        verify_step = next(step for step in steps if step.get("name") == "Download and verify exact PyPI artifacts")
        assert "--project hol-guard" in inspect_step["run"]
        assert "--project plugin-scanner" in inspect_step["run"]
        assert len(publish_steps) == 2
        assert {step["if"] for step in publish_steps} == {
            "steps.pypi.outputs.hol_guard_upload == 'true'",
            "steps.pypi.outputs.plugin_scanner_upload == 'true'",
        }
        assert {step["with"]["packages-dir"] for step in publish_steps} == {
            "dist-hol-guard/",
            "dist-plugin-scanner/",
        }
        assert "dist-hol-guard/*.publish.attestation" in cleanup_step["run"]
        assert "dist-plugin-scanner/*.publish.attestation" in cleanup_step["run"]
        assert all(steps.index(step) < steps.index(cleanup_step) for step in publish_steps)
        assert steps.index(cleanup_step) < steps.index(verify_step)
        assert "--download-dir verified-pypi" in verify_step["run"]
        assert "--project hol-guard" in verify_step["run"]
        assert "--project plugin-scanner" in verify_step["run"]
        assert 'guard_status" == "exact"' in verify_step["run"]
        assert 'scanner_status" == "exact"' in verify_step["run"]
        assert "for attempt in {1..60}" in verify_step["run"]
        assert 'attempt" == "60"' in verify_step["run"]
        assert '== "hol-guard $VERSION"' in verify_step["run"]
        assert '== "plugin-scanner $VERSION"' in verify_step["run"]
        assert 'select(endswith("-py3-none-any.whl"))' in verify_step["run"]
        assert '"${#guard_wheels[@]}" == "1"' in verify_step["run"]
        assert '"${#scanner_wheels[@]}" == "1"' in verify_step["run"]

    alpha_steps = jobs["publish-alpha-pypi"]["steps"]
    alpha_inspect = next(step for step in alpha_steps if step.get("name") == "Inspect PyPI release state")
    alpha_publishers = [step for step in alpha_steps if str(step.get("uses", "")).startswith("pypa/")]
    alpha_cleanup = next(step for step in alpha_steps if step.get("name") == "Remove generated upload attestations")
    assert "plan-upload --registry pypi" in alpha_inspect["run"]
    assert "--artifact-set pure" in alpha_inspect["run"]
    assert "--project plugin-scanner" in alpha_inspect["run"]
    assert {step["with"]["packages-dir"] for step in alpha_publishers} == {
        "upload-dist-hol-guard/",
        "dist-plugin-scanner/",
    }
    assert "upload-dist-hol-guard/*.publish.attestation" in alpha_cleanup["run"]

    alpha_verify = next(
        step
        for step in jobs["publish-alpha-pypi"]["steps"]
        if step.get("name") == "Download and verify exact PyPI artifacts"
    )
    assert "inspect-release --registry pypi --project hol-guard" in alpha_verify["run"]
    assert "verify-release --registry pypi --project plugin-scanner" in alpha_verify["run"]
    assert "verify-published --registry pypi" in alpha_verify["run"]
    assert "--artifact-set pure" in alpha_verify["run"]
    assert '--source-sha "$SOURCE_SHA"' in alpha_verify["run"]
    assert "dist-hol-guard/*-py3-none-any.whl" in alpha_verify["run"]
    alpha_quota = next(
        step for step in alpha_steps if step.get("name") == "Refuse PyPI upload when the project is over quota"
    )
    assert "scripts/pypi_project_storage.py --fail-if-over-limit" in alpha_quota["run"]
    assert "packaging==25.0" in alpha_quota["run"]


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
    assert 'gh release view "$tag" --json isDraft,isPrerelease' in stable_run
    assert "Existing stable release is a draft or prerelease" in stable_run
    assert "remote_guard_files=" in stable_run and "verify_release_asset_inventory.py" in stable_run
    assert '[[ "${#remote_guard_files[@]}" -gt 0 ]]' in stable_run
    assert 'gh attestation verify "$remote_file"' in stable_run
    assert '--bundle "$bundle" --source-digest "$SOURCE_SHA"' in stable_run
    assert "--verify-tag" in stable_run and '"$existing_dir" dist "$VERSION" stable' in stable_run


def test_release_3x_alpha_branches_remain_alpha_while_main_is_stable() -> None:
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
    assert "--channel stable" not in workflow_text
    inputs = workflow[True]["workflow_dispatch"]["inputs"]
    assert inputs["release_channel"]["options"] == ["alpha"]


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
