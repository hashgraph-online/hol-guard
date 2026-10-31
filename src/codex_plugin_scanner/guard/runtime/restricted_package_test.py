"""Resolve package test scripts without executing a package manager or shell."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from ..native_restricted_pytest import restricted_native
from .package_evidence_common import read_json_with_integrity
from .restricted_node_test import nearest_project_root
from .restricted_pytest_model import RestrictedPytestError

PACKAGE_TEST_REASON = "native_package_test_readonly_containment_required"
PACKAGE_TEST_PROFILE = "package-test-readonly-v1"
PACKAGE_TEST_INVALID_REASON = "package_test_invalid_command"


KIND_NAMES = frozenset({"inline_eval", "node_test", "vitest", "git", "node_tool", "package_test"})


def is_package_test(command: Sequence[str]) -> bool:
    """True when the command is a package manager running its own test script.

    The answer rides on the reading the sink already asks for, so a contained
    run learns every route its words can take from one call to native
    authority rather than one call per route.
    """

    kinds = restricted_native("contained_kind", {"command": [str(item) for item in command]}, dict)
    answer = kinds.get("package_test")
    if set(kinds) != KIND_NAMES or type(answer) is not bool:
        raise RestrictedPytestError(PACKAGE_TEST_INVALID_REASON, "Guard could not read this command.")
    return answer


def resolve_package_test(command: Sequence[str], *, workspace: Path, cwd: Path | None = None) -> tuple[str, ...]:
    """The words the declared test script runs, as native authority reads them.

    The manifest read stays here: the verified descriptor turns the script name
    into its own words, which go back to native authority to be read as the run
    they spell. Nothing in this module decides whether that run is admissible.
    """

    package = nearest_project_root(cwd or workspace, workspace, "package.json")
    manifest, _digest = read_json_with_integrity(package / "package.json")
    scripts = manifest.get("scripts") if isinstance(manifest, dict) else None
    return tuple(
        restricted_native(
            "package_test_resolve",
            {"command": [str(item) for item in command], "scripts": scripts},
            list,
        )
    )
