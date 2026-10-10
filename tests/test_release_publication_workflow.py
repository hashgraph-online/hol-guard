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
    assert "needs.build.outputs.channel != 'canary'" in str(native_pin.get("if", ""))
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
    release_tooling = next(step for step in release_main_steps if step.get("name") == "Checkout release-notes tooling")
    assert release_tooling["if"] == "needs.publish-main-pypi.outputs.pypi_deferred == 'true'"
    assert release_tooling["with"] == {
        "fetch-depth": 1,
        "ref": "${{ github.event.repository.default_branch }}",
        "path": ".release-tooling",
    }
    release_notes = next(step for step in release_main_steps if step.get("name") == "Generate release notes")
    assert 'notes_script=".release-tooling/scripts/ci/generate_release_notes.py"' in release_notes["run"]
    assert 'notes_script="scripts/ci/generate_release_notes.py"' in release_notes["run"]
    assert "deferred_args+=(--pypi-deferred)" in release_notes["run"]
    assert 'python3 "$notes_script"' in release_notes["run"]
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
    main_quota = next(step for step in main_steps if step.get("name") == "Check PyPI quota admission")
    assert main_quota["id"] == "pypi_quota"
    assert "--fail-if-over-limit --pending-dir dist-hol-guard" in main_quota["run"]
    assert "jq -e '.over_limit == true'" in main_quota["run"]
    assert 'echo "blocked=true"' in main_quota["run"]
    guard_publish = next(step for step in main_steps if step.get("name") == "Publish HOL Guard to PyPI")
    scanner_publish = next(step for step in main_steps if step.get("name") == "Publish plugin-scanner to PyPI")
    assert "steps.pypi_quota.outputs.blocked != 'true'" in guard_publish["if"]
    assert scanner_publish["if"] == "steps.pypi.outputs.plugin_scanner_upload == 'true'"
    main_verify = next(step for step in main_steps if step.get("name") == "Download and verify exact PyPI artifacts")
    assert main_verify["if"] == (
        "steps.pypi_quota.outputs.blocked != 'true' || steps.pypi.outputs.plugin_scanner_upload == 'true'"
    )
    assert jobs["publish-main-pypi"]["outputs"]["pypi_deferred"] == "${{ steps.pypi_quota.outputs.blocked }}"
    assert "--artifact-set full" in main_verify["run"]
    assert (
        main_verify["run"].find("for attempt in {1..60}")
        < main_verify["run"].find("retry_verify_published.py")
        < main_verify["run"].find("\ndone\n")
    )

    stable_native = jobs["build-native-guard-wheels"]["if"]
    assert "needs.build.outputs.channel == 'stable'" in stable_native
    assert "github.ref == 'refs/heads/main'" in stable_native
    for job_name in ("publish-main-testpypi", "publish-main-pypi", "release-main"):
        job = jobs[job_name]
        assert "assemble-native-guard-distributions" in job["needs"]
        assert "needs.assemble-native-guard-distributions.result == 'success'" in job["if"]
        assert any(step.get("with", {}).get("name") == "distributions-native" for step in job["steps"])

    workflow_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    assert "skip-existing" not in workflow_text
    assert "--deferred-pypi" in workflow_text


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
    assert (
        alpha_test_verify["run"].find("for attempt in {1..60}")
        < alpha_test_verify["run"].find("retry_verify_published.py")
        < alpha_test_verify["run"].find("\ndone\n")
    )
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
            "steps.pypi.outputs.hol_guard_upload == 'true' && steps.pypi_quota.outputs.blocked != 'true'",
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
    assert (
        alpha_verify["run"].find("for attempt in {1..60}")
        < alpha_verify["run"].find("retry_verify_published.py")
        < alpha_verify["run"].find("\ndone\n")
    )
    assert "--artifact-set pure" in alpha_verify["run"]
    assert '--source-sha "$SOURCE_SHA"' in alpha_verify["run"]
    assert "dist-hol-guard/*-py3-none-any.whl" in alpha_verify["run"]
    alpha_quota = next(
        step for step in alpha_steps if step.get("name") == "Refuse PyPI upload when the project is over quota"
    )
    assert "scripts/pypi_project_storage.py --fail-if-over-limit" in alpha_quota["run"]
    assert "packaging==25.0" in alpha_quota["run"]


def test_repair_runs_reuse_attested_release_wheels_instead_of_rebuilt_ones() -> None:
    jobs = _workflow(PUBLISH_WORKFLOW)["jobs"]
    steps = jobs["assemble-native-guard-distributions"]["steps"]
    names = [step.get("name") for step in steps]
    reuse_name = "Reuse wheels already attested on the GitHub release"
    assert names.index(reuse_name) < names.index("Validate exact native artifact set")
    assert names.index(reuse_name) < names.index("Record aggregate immutable hashes")
    step = steps[names.index(reuse_name)]
    assert step["if"] == "needs.build.outputs.channel == 'stable'"
    assert step["working-directory"] == "${{ runner.temp }}"
    script = step["run"]
    assert 'gh release download "$tag"' in script
    assert 'gh attestation verify "$release_file"' in script
    assert '--source-digest "$SOURCE_SHA"' in script
    assert "refusing to publish unverified wheels" in script
    assert "Release wheel set does not match" in script
    assert script.index("gh attestation verify") < script.index('cp -f "${release_files[@]}" "$DIST_DIR/"')
