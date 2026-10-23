"""Alpha native wheels use fast codegen and never reach PyPI or stable."""

from __future__ import annotations

import json
import re
from pathlib import Path

from tests.release_workflow_helpers import load_workflow, native_target_matrix

ROOT = Path(__file__).resolve().parents[1]
PUBLISH = load_workflow(ROOT / ".github/workflows/publish.yml")["jobs"]


def test_fast_codegen_is_requested_only_for_alpha_dispatches() -> None:
    precompile = PUBLISH["precompile-native-linux-x64"]
    assert precompile["with"]["fast_codegen"] == "${{ inputs.release_channel == 'alpha' }}"
    condition = " ".join(precompile["if"].split())
    stable = "github.ref == format('refs/tags/v{0}', inputs.release_version) && inputs.release_channel == 'stable'"
    assert stable in condition
    alpha = "inputs.release_channel == 'alpha' && inputs.release_train == 'main' && needs.resolve-alpha-version.result"
    assert alpha in condition
    assert "github.run_attempt == 1" in condition
    # PR canaries precompile through the same path but never request fast codegen, so their
    # wheels are still measured against the PyPI budgets.
    canary = "github.event_name == 'pull_request' &&"
    assert canary in condition
    assert "inputs.release_channel == 'alpha'" not in condition[condition.index(canary) :]


def test_prepare_applies_fast_profile_only_to_canonical_alpha_versions() -> None:
    prepare = load_workflow(ROOT / ".github/workflows/release-native-prepare.yml")
    assert prepare[True]["workflow_call"]["inputs"]["fast_codegen"]["default"] is False
    step = next(s for s in prepare["jobs"]["compile"]["steps"] if s.get("name") == "Compile canonical release inputs")
    script = step["run"]
    guard = script.index('[[ "$FAST_CODEGEN" != "true" ]] || [[ "$VERSION" =~ ')
    assert script.index("a[1-9][0-9]*$ ]]") > guard
    assert script.index("CARGO_PROFILE_RELEASE_LTO=false") > guard
    assert script.index("CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16") > guard
    assert script.index("cargo build") > script.index("CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16")
    assert "CARGO_PROFILE_RELEASE_LTO" not in (ROOT / ".github/workflows/publish.yml").read_text()
    cargo = (ROOT / "rust/Cargo.toml").read_text()
    assert 'lto = "fat"' in cargo and "codegen-units = 1" in cargo


def test_alpha_native_wheels_never_reach_pypi() -> None:
    steps = PUBLISH["publish-alpha-pypi"]["steps"]
    plan = next(s for s in steps if s.get("id") == "pypi")["run"]
    assert "--artifact-set pure" in plan
    publishers = [s for s in steps if "gh-action-pypi-publish" in s.get("uses", "")]
    assert [s["with"]["packages-dir"] for s in publishers] == ["upload-dist-hol-guard/", "dist-plugin-scanner/"]
    verify = "\n".join(
        s.get("run", "") for s in steps if "retry_verify_published.py --registry pypi" in s.get("run", "")
    )
    assert "--artifact-set pure" in verify
    # The only other alpha upload target is the TestPyPI index, never PyPI or a stable release.
    testpypi = [s for s in PUBLISH["publish-alpha-testpypi"]["steps"] if "gh-action-pypi-publish" in s.get("uses", "")]
    assert testpypi and all(s["with"]["repository-url"] == "https://test.pypi.org/legacy/" for s in testpypi)


def test_stable_publishing_never_consumes_fast_binaries() -> None:
    for name in ("publish-main-testpypi", "publish-main-pypi", "publish-main-assets", "release-main"):
        text = json.dumps(PUBLISH[name])
        assert "fast_codegen" not in text


def test_resolve_job_mirrors_build_alpha_version_rules() -> None:
    resolve = PUBLISH["resolve-alpha-version"]
    condition = " ".join(resolve["if"].split())
    for required in (
        "github.event_name == 'workflow_dispatch'",
        "github.run_attempt == 1",
        "github.ref == 'refs/heads/main'",
        "inputs.release_channel == 'alpha'",
        "inputs.release_train == 'main'",
    ):
        assert required in condition
    assert resolve["needs"] == "authorize-release"
    assert resolve["permissions"] == {"contents": "read"}
    script = next(s for s in resolve["steps"] if s.get("id") == "version")["run"]
    build = "\n".join(s.get("run", "") for s in PUBLISH["build"]["steps"])
    for token in (
        "compute_alpha_release_version.py",
        "validate_alpha_release.py",
        "list-versions --registry pypi",
        "list-versions --registry testpypi",
        "alpha/v*",
        "was already published or reserved",
    ):
        assert token in script
        assert token in build


def test_windows_alpha_compile_lowers_only_workspace_opt_level() -> None:
    prepare = load_workflow(ROOT / ".github/workflows/release-native-prepare.yml")["jobs"]["compile"]
    expression = prepare["env"]["ALPHA_WORKSPACE_OPT_LEVEL"]
    assert expression == "${{ endsWith(matrix.target, '-pc-windows-msvc') && '1' || '' }}"
    legs = native_target_matrix(prepare)[""]
    assert len(legs) == 5
    targets = [leg["target"] for leg in legs]
    assert targets.count("x86_64-pc-windows-msvc") == 1
    assert targets.count("aarch64-pc-windows-msvc") == 1
    step = next(s for s in prepare["steps"] if s.get("name") == "Compile canonical release inputs")
    script = step["run"]
    export = script.index("CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16")
    guard = script.index('[[ "$FAST_CODEGEN" == "true" && -n "$ALPHA_WORKSPACE_OPT_LEVEL" ]]')
    assert export < guard < script.index("cargo build")
    assert "workspace_opt_profile.py" in script
    builds = [line for line in script.splitlines() if line.strip().startswith("cargo build")]
    assert len(builds) == 1
    assert '${cargo_config[@]+"${cargo_config[@]}"}' in builds[0]
    # The determinism workflow's compile matrix must stay identical to this one.
    determinism = load_workflow(ROOT / ".github/workflows/release-native-determinism.yml")["jobs"]["compare"]
    assert determinism["strategy"]["matrix"]["include"] == legs


def test_alpha_prerelease_still_waits_for_pypi_while_overlapping_it() -> None:
    job = PUBLISH["release-alpha"]
    assert "publish-alpha-pypi" not in job["needs"]
    assert job["needs"] == ["build", "assemble-native-guard-distributions", "reserve-alpha-tag"]
    condition = " ".join(job["if"].split())
    assert "needs.publish-alpha-pypi" not in condition
    assert "needs.assemble-native-guard-distributions.result == 'success'" in condition
    assert "needs.reserve-alpha-tag.result == 'success'" in condition
    assert job["permissions"]["actions"] == "read"
    names = [step.get("name") for step in job["steps"]]
    wait = next(step for step in job["steps"] if step.get("name") == "Wait for the PyPI publication to succeed")
    assert names.index("Generate release notes") < names.index("Wait for the PyPI publication to succeed")
    assert names.index("Wait for the PyPI publication to succeed") < names.index("Refresh release API token")
    assert names.index("Refresh release API token") < names.index("Create discoverable alpha prerelease")
    assert wait["env"]["GH_TOKEN"] == "${{ github.token }}"
    notes = next(step for step in job["steps"] if step.get("name") == "Generate release notes")
    prerelease = next(step for step in job["steps"] if step.get("name") == "Create discoverable alpha prerelease")
    assert notes["env"]["GH_TOKEN"] == "${{ steps.release-token.outputs.token }}"
    assert prerelease["env"]["GH_TOKEN"] == "${{ steps.release-token-after-pypi.outputs.token }}"
    publish_name = PUBLISH["publish-alpha-pypi"]["name"]
    assert "wait_for_run_job.py" in wait["run"]
    assert f'--job-name "{publish_name}"' in wait["run"]


def test_native_prepare_version_pattern_accepts_only_canonical_alpha_suffix() -> None:
    prepare = (ROOT / ".github/workflows/release-native-prepare.yml").read_text()
    assert "^[0-9]+\\.[0-9]+\\.[0-9]+(a[1-9][0-9]*)?$" in prepare
    pattern = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(a[1-9][0-9]*)?$")
    for good in ("3.35.0", "3.35.0a1", "3.35.0a12"):
        assert pattern.match(good)
    for bad in ("3.35.0a0", "3.35.0a01", "3.35.0rc1", "3.35.0.dev1", "3.35.0a1-x"):
        assert not pattern.match(bad)
    # Only PR canary compiles, which never publish a release, may embed a dev version.
    assert "PR_CANARY: ${{ github.event_name == 'pull_request' }}" in prepare
    assert (
        '! [[ "${PR_CANARY:-}" == "true" && "$RELEASE_VERSION" =~ ^${BASE_VERSION//./\\\\.}\\.dev[0-9]+$ ]]; then'
        in prepare
    )
