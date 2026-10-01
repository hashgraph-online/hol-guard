"""Generated-artifact freshness gates for contribution-only changes.

Contributor PRs own the canonical source, portable fixture, and trust entry.
Maintainer automation regenerates the catalog, native program, baselines, and
digest vectors after scope review, so a source-only ref legitimately contains a
contribution id that the checked-in projections do not cover yet. Tests that
assert freshness of generated artifacts stand down while such a pending
contribution exists; every other invariant still runs.

The same stand-down applies whenever a PR cannot carry the artifact at all:
generated-artifacts-guard rejects regen-owned paths in ordinary PR diffs, so a
checked-in projection can only be refreshed on main by the post-merge regen
workflow. Freshness is enforced on main and on regen PRs (whose diffs do carry
the artifacts) and deferred for every ref whose diff omits them.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from scripts.ci.detect_pending_extension_regen import contribution_ids


def pending_contribution_regen() -> bool:
    from codex_plugin_scanner.guard.runtime.command_extensions import (
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    )

    registry_ids = {
        extension.extension_id for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    }
    return bool(contribution_ids() - registry_ids)


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *arguments], check=False, capture_output=True, text=True
        )
    except OSError:
        return subprocess.CompletedProcess(["git", *arguments], 1, "", "")


def _pr_diff_paths() -> list[str] | None:
    """Paths this ref changes relative to the base branch, or None on failure.

    Delegates to the shared detector: PR CI diffs against a depth-1 fetch of
    ``GITHUB_BASE_REF``; local runs fall back to the ``main`` merge-base.
    """

    from scripts.ci.detect_pending_extension_regen import pr_diff_paths

    return pr_diff_paths()


def _regen_paths_absent(*paths: str) -> bool:
    """This ref does not carry any of ``paths`` — drift is regen-owned.

    Generated artifacts cannot be committed by ordinary PRs
    (generated-artifacts-guard enforces it), so freshness belongs to main and
    to regen PRs, whose diffs do carry the artifacts. Locally a feature branch
    without the artifacts defers the same way; a clean ``main`` checkout has an
    empty diff and stays strict.
    """

    diff = _pr_diff_paths()
    if diff is None:
        # Detection failed, so freshness cannot safely be attributed to regen.
        return False
    if not os.environ.get("GITHUB_BASE_REF") and not diff:
        return False
    return not any(
        changed == path or changed.startswith(path.rstrip("/") + "/")
        for changed in diff
        for path in paths
    )


_NATIVE_PROJECTION_PATHS: tuple[str, ...] = (
    "contracts/extensions/native-command-program.v1.json",
    "contracts/extensions/command-catalog.v1.json",
    "contracts/extensions/native-command-control-authority.v1.fixtures.json",
    "contracts/managed-controls/v1/extension-projection-digest-vector.json",
    "contracts/managed-controls/v1/policy-bundle-v2-extension-signature-vector.json",
    "src/codex_plugin_scanner/guard/contracts/data/extensions",
    "src/codex_plugin_scanner/guard/extension_builder",
)


def pending_decision_diff_regen() -> bool:
    """In a PR that does not carry the regen-owned decision-diff report."""

    if pending_contribution_regen():
        return True
    report = "tests/fixtures/guard-command-corpus/decision-diff-report.json"
    try:
        from tests.guard_command_decision_diff import REPO_ROOT, REPORT_PATH

        report = str(REPORT_PATH.relative_to(REPO_ROOT))
    except (ImportError, ValueError):
        pass
    return _regen_paths_absent(report)


def pending_native_projection_regen() -> bool:
    """In a PR that does not carry the regen-owned native projections."""

    if pending_contribution_regen():
        return True
    return _regen_paths_absent(*_NATIVE_PROJECTION_PATHS)


requires_fresh_projections = pytest.mark.skipif(
    pending_native_projection_regen(),
    reason=(
        "checked-in projections are regen-owned; "
        "freshness is enforced on main and after maintainer regeneration"
    ),
)

requires_fresh_decision_diff = pytest.mark.skipif(
    pending_decision_diff_regen(),
    reason="decision-diff report is regen-owned; enforced after maintainer regeneration",
)
