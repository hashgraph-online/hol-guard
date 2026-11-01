"""Resolve package test scripts without executing a package manager or shell."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from ..native_restricted_pytest import restricted_native
from .package_evidence_common import read_json_with_integrity
from .restricted_node_test import nearest_project_root

PACKAGE_TEST_REASON = "native_package_test_readonly_containment_required"
PACKAGE_TEST_PROFILE = "package-test-readonly-v1"


KIND_NAMES = frozenset({"inline_eval", "node_test", "vitest", "git", "node_tool", "package_test"})


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
