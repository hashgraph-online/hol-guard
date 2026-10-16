"""Alpha native wheels use fast codegen and a separate ceiling, and never reach PyPI or stable."""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

import pytest

from scripts.ci.check_wheel_size import ALPHA_VERSION, NATIVE, inspect_wheel
from tests.release_workflow_helpers import load_workflow

ROOT = Path(__file__).resolve().parents[1]
STANDARD = json.loads((ROOT / "ci/package_size/budgets.json").read_text())
ALPHA = json.loads((ROOT / "ci/package_size/alpha-native-budgets.json").read_text())
PUBLISH = load_workflow(ROOT / ".github/workflows/publish.yml")["jobs"]


def _wheel(path: Path, name: str, size: int) -> Path:
    wheel = path / name
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(NATIVE + "hol-guard-runtime", b"x" * size)
    return wheel


def test_alpha_ceiling_is_larger_than_standard_but_still_finite() -> None:
    assert set(ALPHA) == set(STANDARD) - {"any"}
    for platform, limits in ALPHA.items():
        for metric, value in limits.items():
            assert STANDARD[platform][metric] < value <= STANDARD[platform][metric] * 2


def test_alpha_ceiling_accepts_alpha_native_wheel_above_the_standard_budget(tmp_path: Path) -> None:
    size = STANDARD["win_amd64"]["runtime"] + 1024 * 1024
    wheel = _wheel(tmp_path, "hol_guard-3.35.0a1-py3-none-win_amd64.whl", size)
    assert inspect_wheel(wheel, STANDARD)[1]
    assert inspect_wheel(wheel, STANDARD, ALPHA)[1] == []


def test_alpha_ceiling_still_rejects_runaway_growth(tmp_path: Path) -> None:
    size = ALPHA["win_amd64"]["runtime"] + 1
    wheel = _wheel(tmp_path, "hol_guard-3.35.0a1-py3-none-win_amd64.whl", size)
    assert any("runtime exceeds budget" in failure for failure in inspect_wheel(wheel, STANDARD, ALPHA)[1])


@pytest.mark.parametrize("version", ["3.35.0", "3.35.0rc1", "3.35.0a0", "3.35.0.dev1", "3.35.0a1.post1"])
def test_alpha_ceiling_is_refused_for_any_other_version(tmp_path: Path, version: str) -> None:
    wheel = _wheel(tmp_path, f"hol_guard-{version}-py3-none-win_amd64.whl", 1)
    with pytest.raises(ValueError, match="not a canonical alpha"):
        inspect_wheel(wheel, STANDARD, ALPHA)
    assert not ALPHA_VERSION.fullmatch(version)


def test_pure_wheel_keeps_the_pypi_budget_even_with_the_alpha_ceiling(tmp_path: Path) -> None:
    wheel = tmp_path / "hol_guard-3.35.0a1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("data", b"x" * (STANDARD["any"]["unpacked"] + 1))
    failures = inspect_wheel(wheel, STANDARD, ALPHA)[1]
    assert any("unpacked exceeds budget" in failure for failure in failures)


def test_fast_codegen_is_requested_only_for_alpha_dispatches() -> None:
    precompile = PUBLISH["precompile-native"]
    assert precompile["with"]["fast_codegen"] == "${{ inputs.release_channel == 'alpha' }}"
    condition = " ".join(precompile["if"].split())
    stable = "github.ref == format('refs/tags/v{0}', inputs.release_version) && inputs.release_channel == 'stable'"
    assert stable in condition
    alpha = "inputs.release_channel == 'alpha' && inputs.release_train == 'main' && needs.resolve-alpha-version.result"
    assert alpha in condition
    assert "canary" not in condition
    assert "github.run_attempt == 1" in condition


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


def test_alpha_ceiling_applies_only_to_alpha_wheels_from_fast_precompiled_binaries() -> None:
    step = next(s for s in PUBLISH["build-native-guard-wheels"]["steps"] if s.get("name") == "Assemble native wheel")
    assert (
        step["env"]["ALPHA_FAST_CODEGEN"]
        == "${{ needs.precompile-native.result == 'success' && inputs.release_channel == 'alpha' }}"
    )
    run = step["run"]
    assert run.count("--alpha-native-budgets") == 1
    assert run.index('"$ALPHA_FAST_CODEGEN" == "true"') < run.index("--alpha-native-budgets")
    for job in PUBLISH.values():
        for item in job.get("steps", []):
            if item.get("name") != "Assemble native wheel":
                assert "--alpha-native-budgets" not in item.get("run", "")
    # The pure wheel is checked in the build job with the standard budget.
    build = "\n".join(s.get("run", "") for s in PUBLISH["build"]["steps"])
    assert 'python "$HOL_GUARD_WHEEL_SIZE_CHECKER" --dist-dir dist\n' in build


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


def test_stable_publishing_never_consumes_alpha_budgets_or_fast_binaries() -> None:
    for name in ("publish-main-testpypi", "publish-main-pypi", "publish-main-assets", "release-main"):
        text = json.dumps(PUBLISH[name])
        assert "alpha-native-budgets" not in text
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
    legs = prepare["strategy"]["matrix"]["include"]
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
