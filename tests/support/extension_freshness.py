"""Generated-artifact freshness gates for contribution-only changes.

Contributor PRs own the canonical source, portable fixture, and trust entry.
Maintainer automation regenerates the catalog, native program, baselines, and
digest vectors after scope review, so a source-only ref legitimately contains a
contribution id that the checked-in projections do not cover yet. Tests that
assert freshness of generated artifacts stand down while such a pending
contribution exists; every other invariant still runs.
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
    """Paths this ref changes relative to the base branch, or None outside PR CI.

    CI checkouts are shallow, so diff against a depth-1 fetch of the base ref —
    tree-to-tree, no merge-base history required. Locally, fall back to the
    merge-base against ``main`` when that ref exists.
    """

    base_ref = os.environ.get("GITHUB_BASE_REF")
    if base_ref:
        probe = _git("rev-parse", "--is-shallow-repository")
        shallow = probe.returncode != 0 or probe.stdout.strip() == "true"
        fetch = [
            "fetch", "-q", *(["--depth=1"] if shallow else []), "origin",
            f"+refs/heads/{base_ref}:refs/remotes/pending-diff/base",
        ]
        if _git(*fetch).returncode:
            return None
        result = _git("diff", "--name-only", "pending-diff/base", "HEAD")
        return result.stdout.splitlines() if result.returncode == 0 else None
    if _git("rev-parse", "--verify", "main").returncode == 0:
        result = _git("diff", "--name-only", "main...HEAD")
        return result.stdout.splitlines() if result.returncode == 0 else None
    return None


def pending_decision_diff_regen() -> bool:
    """In a PR that does not carry the regen-owned decision-diff report.

    The report is maintainer-owned: generated-artifacts-guard rejects it in
    ordinary PR diffs, so a branch can never refresh it, and drift may equally
    be inherited from main (any merged bound-source change restales it until
    the post-merge regen lands). Freshness is enforced where the report can
    actually change — on main and on regen PRs, whose diff carries it — and
    deferred for every other PR.
    """

    if pending_contribution_regen():
        return True
    report = "tests/fixtures/guard-command-corpus/decision-diff-report.json"
    try:
        from tests.guard_command_decision_diff import REPO_ROOT, REPORT_PATH

        report = str(REPORT_PATH.relative_to(REPO_ROOT))
    except (ImportError, ValueError):
        pass
    in_pr = bool(os.environ.get("GITHUB_BASE_REF"))
    diff = _pr_diff_paths()
    if diff is None:
        return in_pr
    if not in_pr and not diff:
        return False
    return report not in diff


requires_fresh_projections = pytest.mark.skipif(
    pending_contribution_regen(),
    reason=(
        "checked-in projections do not cover a pending contribution source; "
        "freshness is enforced after maintainer regeneration"
    ),
)

requires_fresh_decision_diff = pytest.mark.skipif(
    pending_decision_diff_regen(),
    reason="decision-diff report is regen-owned; enforced after maintainer regeneration",
)
