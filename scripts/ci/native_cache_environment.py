"""Fingerprint compiler overrides without coupling native caches to test scheduling."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping

# The shipped build explicitly unsets these two PR-only profile overrides.
IGNORED = frozenset({"CARGO_PROFILE_RELEASE_LTO", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS"})
PREFIXES = ("CARGO_PROFILE_", "CARGO_TARGET_", "CARGO_BUILD_")
NAMES = frozenset(
    {
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTUP_TOOLCHAIN",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "HOL_GUARD_BUILD_SHA",
        "HOL_GUARD_PACKAGE_VERSION",
        "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX",
        "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_FINGERPRINT_HEX",
    }
)


def fingerprint(environment: Mapping[str, str]) -> str:
    inputs = {
        name: value
        for name, value in environment.items()
        if name not in IGNORED and (name in NAMES or name.startswith(PREFIXES))
    }
    encoded = json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


if __name__ == "__main__":
    # Emit only the digest, never environment values.
    print(f"compiler-env={fingerprint(os.environ)}")
