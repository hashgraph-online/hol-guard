"""Only compiler inputs, not test scheduling or unrelated tokens, affect the binary key."""

from __future__ import annotations

import pytest

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
