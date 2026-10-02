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

import json
import os
import subprocess
from pathlib import Path

import pytest

from scripts.ci.detect_pending_extension_regen import contribution_ids

ROOT = Path(__file__).resolve().parents[2]


def pending_contribution_regen() -> bool:
    from codex_plugin_scanner.guard.runtime.command_extensions import (
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    )

    registry_ids = {extension.extension_id for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions}
    return bool(contribution_ids() - registry_ids)


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    command = ["git", *arguments]
    try:
        return subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(command, 1, "", "")


def _projection_base_sha() -> str | None:
    """Return the captured base revision for this ref, failing closed in PR CI."""

    base_sha = os.environ.get("HOL_GUARD_BASE_SHA") or os.environ.get("GITHUB_BASE_SHA")
    if base_sha:
        return base_sha

    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        try:
            event = json.loads(Path(event_path).read_text(encoding="utf-8"))
            base_sha = event["pull_request"]["base"]["sha"]
        except (OSError, UnicodeError, KeyError, TypeError, ValueError):
            base_sha = None
        if isinstance(base_sha, str) and base_sha:
            return base_sha

    if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
        raise RuntimeError("Cannot determine pull-request base revision")

    result = _git("merge-base", "HEAD", "main")
    return result.stdout.strip() if result.returncode == 0 else None


def _pr_diff_paths() -> list[str] | None:
    """Paths this ref changes relative to its captured base, or None locally."""

    is_pull_request = os.environ.get("GITHUB_EVENT_NAME") == "pull_request" or bool(os.environ.get("GITHUB_BASE_REF"))
    base_sha = _projection_base_sha()
    if base_sha is None:
        return None

    result = _git("diff", "--name-only", base_sha, "HEAD")
    if result.returncode:
        if not is_pull_request:
            return None
        fetched = _git("fetch", "--depth=1", "origin", base_sha)
        if fetched.returncode:
            raise RuntimeError("Cannot determine pull-request diff")
        result = _git("diff", "--name-only", base_sha, "HEAD")
        if result.returncode:
            raise RuntimeError("Cannot determine pull-request diff")
    return [path for path in result.stdout.splitlines() if path]


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
        # Detection failed: in PR context the artifacts cannot be committed
        # anyway, so deferring cannot mask drift; the post-merge regen check
        # on main still enforces it.
        return bool(os.environ.get("GITHUB_BASE_REF"))
    if not os.environ.get("GITHUB_BASE_REF") and not diff:
        return False
    return not any(changed == path or changed.startswith(path.rstrip("/") + "/") for changed in diff for path in paths)


_NATIVE_PROJECTION_PATHS: tuple[str, ...] = (
    "contracts/extensions/native-command-program.v1.json",
    "contracts/extensions/command-catalog.v1.json",
    "contracts/extensions/native-command-control-authority.v1.fixtures.json",
    "contracts/managed-controls/v1/extension-projection-digest-vector.json",
    "contracts/managed-controls/v1/policy-bundle-v2-extension-signature-vector.json",
    "src/codex_plugin_scanner/guard/contracts/data/extensions",
)


def pending_decision_diff_regen() -> bool:
    """Current decision evidence is evaluated per run and must never be skipped.

    Retained for callers of the former fixture-freshness marker. Source-only
    changes and unavailable Git history do not exempt behavioral evaluation.
    """
    return False


def pending_native_projection_regen() -> bool:
    """In a PR that does not carry the regen-owned native projections.

    Same regen-ownership reasoning as the decision-diff report: ordinary PRs
    cannot commit these projections, so freshness belongs to main and regen
    PRs; every other PR defers.
    """

    if pending_contribution_regen():
        return True
    return _regen_paths_absent(*_NATIVE_PROJECTION_PATHS)


requires_fresh_projections = pytest.mark.skipif(
    pending_native_projection_regen(),
    reason=("checked-in projections are regen-owned; freshness is enforced on main and after maintainer regeneration"),
)

requires_fresh_decision_diff = pytest.mark.skipif(
    pending_decision_diff_regen(),
    reason="current decision evidence has no regeneration exemption",
)
