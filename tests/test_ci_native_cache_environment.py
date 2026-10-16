"""Only compiler inputs, not test scheduling or unrelated tokens, affect the binary key."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scripts.ci.native_cache_environment import fingerprint


@pytest.mark.parametrize(
    "name",
    [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTUP_TOOLCHAIN",
        "RUSTC",
        "RUSTC_WRAPPER",
        "CARGO_BUILD_TARGET",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
        "CARGO_PROFILE_RELEASE_OPT_LEVEL",
        "CARGO_PROFILE_RELEASE_DEBUG",
        "CARGO_PROFILE_RELEASE_PANIC",
        "HOL_GUARD_BUILD_SHA",
        "HOL_GUARD_PACKAGE_VERSION",
        "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX",
        "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_FINGERPRINT_HEX",
    ],
)
def test_compiler_changes_cannot_reuse_a_previous_binary(name: str) -> None:
    assert fingerprint({name: "before"}) != fingerprint({name: "after"})


@pytest.mark.parametrize(
    "name",
    [
        "CI_PYTEST_COVERAGE_SHARDS",
        "GITHUB_RUN_ID",
        "GITHUB_TOKEN",
        "CARGO_PROFILE_RELEASE_LTO",
        "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
    ],
)
def test_unrelated_or_explicitly_unset_inputs_do_not_invalidate_the_build(name: str) -> None:
    assert fingerprint({name: "before"}) == fingerprint({name: "after"}) == fingerprint({})


def test_fingerprint_is_order_independent_and_unambiguous() -> None:
    assert fingerprint({"RUSTC": "compiler", "RUSTFLAGS": "-C opt-level=2"}) == fingerprint(
        {
            "RUSTFLAGS": "-C opt-level=2",
            "RUSTC": "compiler",
        }
    )
    assert fingerprint({"RUSTC": "x:y", "RUSTFLAGS": "z"}) != fingerprint({"RUSTC": "x", "RUSTFLAGS": "y:z"})


def test_shipped_cache_warming_shares_the_exact_recipe_without_delaying_other_warmers() -> None:
    root = Path(__file__).resolve().parents[1]
    warm = yaml.safe_load((root / ".github/workflows/shipped-runtime-cache-warm.yml").read_text())
    ci = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    native = yaml.safe_load((root / ".github/workflows/native-ci-cache-warm.yml").read_text())
    assert warm[True].keys() == {"push"}
    assert warm[True]["push"]["branches"] == ["main"]
    assert warm["permissions"] == {"contents": "read"}
    assert warm["concurrency"]["cancel-in-progress"] is False
    assert warm["concurrency"]["group"] not in {ci["concurrency"]["group"], native["concurrency"]["group"]}
    paths = warm[True]["push"]["paths"]
    for path in (
        "rust/**",
        "contributions/**",
        "contracts/**",
        "spec/**",
        ".cargo/**",
        "scripts/ci/native_cache_environment.py",
        ".github/actions/ci-job-native-release-size/**",
    ):
        assert path in paths
    job = warm["jobs"]["linux"]
    required = ci["jobs"]["native-release-size"]
    assert "needs" not in job and "secrets" not in job
    assert job["runs-on"] == required["runs-on"]
    assert job["timeout-minutes"] == required["timeout-minutes"]
    assert fingerprint(warm.get("env", {})) == fingerprint(ci["env"])
    assert job["steps"][0]["with"] == {"persist-credentials": False}
    assert job["steps"][-1]["uses"] == required["steps"][-1]["uses"] == "./.github/actions/ci-job-native-release-size"
    assert job["concurrency"] == {
        "group": "shipped-native-ci-build-${{ github.sha }}-linux",
        "cancel-in-progress": False,
    }
    assert required["concurrency"] == {
        "group": "${{ (github.event_name == 'push' && github.ref == 'refs/heads/main') "
        "&& format('shipped-native-ci-build-{0}-linux', github.sha) "
        "|| format('shipped-native-ci-build-run-{0}-linux', github.run_id) }}",
        "cancel-in-progress": False,
    }
