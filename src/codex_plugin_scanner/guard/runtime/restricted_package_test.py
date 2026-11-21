"""Resolve package test scripts without executing a package manager or shell."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from ..native_restricted_pytest import restricted_native

PACKAGE_TEST_REASON = "native_package_test_readonly_containment_required"
PACKAGE_TEST_PROFILE = "package-test-readonly-v1"


KIND_NAMES = frozenset({"inline_eval", "node_test", "vitest", "git", "node_tool", "package_test"})


def resolve_package_test(command: Sequence[str], *, workspace: Path, cwd: Path | None = None) -> tuple[str, ...]:
    """The words the declared test script runs, as native authority reads them.

    Native authority reads the nearest manifest through a verified descriptor
    and turns the script name into its own words, which go back to native
    authority to be read as the run they spell. Windows has no package-test
    containment route, so there the request reports the sandbox unavailable.
    """

    return tuple(
        restricted_native(
            "package_test_command",
            {"command": [str(item) for item in command], "workspace": workspace, "cwd": cwd or workspace},
            list,
        )
    )
