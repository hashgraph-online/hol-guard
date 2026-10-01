"""Detect canonical inputs awaiting maintainer-owned artifact regeneration.

Prints ``{"pending": ..., "pending_ids": [...]}`` (or a bare ``true``/``false``
with ``--flag``) when any canonical contribution under ``contributions/``
declares an extension id that the checked-in ``command-catalog.v1.json`` does
not contain.
That state means the source-only contribution is awaiting maintainer-owned
projection regeneration, so generated-artifact freshness gates should stand
down for that ref. Rust changes also require regeneration: the native compiler
binds its program identity to implementation sources, manifests and Cargo.lock.
Stdlib only; no repository imports.

A requested base comparison must succeed before the detector can declare
sources unchanged. This module uses only the Python standard library.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "contracts/extensions/command-catalog.v1.json"

# Maintainer-owned generated projections (extension-artifact-regen.yml). The
# generated-artifacts-guard workflow mirrors this list; keep both in sync.
REGEN_OWNED_PATHS: tuple[str, ...] = (
    "contracts/extensions/native-command-program.v1.json",
    "contracts/extensions/command-catalog.v1.json",
    "contracts/extensions/native-command-control-authority.v1.fixtures.json",
    "contracts/managed-controls/v1/extension-projection-digest-vector.json",
    "contracts/managed-controls/v1/policy-bundle-v2-extension-signature-vector.json",
    "docs/guard/extensions/README.md",
    "docs/guard/extensions/catalog.v1.json",
    "docs/guard/extensions/catalog.v2.json",
    "src/codex_plugin_scanner/guard/contracts/data/extensions",
    "src/codex_plugin_scanner/guard/contracts/data/mcp_servers",
    "src/codex_plugin_scanner/guard/extension_builder",
    "tests/fixtures/extension-controls/catalog-baseline.v1.json",
    "tests/fixtures/guard-command-corpus/decision-diff-report.json",
    "tests/fixtures/guard-command-corpus/decision-diff-report.framed-sha256",
    "tests/test_guard_extension_trust.py",
    "tests/test_policy_bundle_delivery_runtime.py",
)

# Canonical inputs whose changes can stale the projections above.
REGEN_INPUT_PREFIXES: tuple[str, ...] = (
    "contributions/",
    "rust/",
    "src/codex_plugin_scanner/guard/",
    "contracts/extensions/",
    "contracts/managed-controls/",
    "docs/guard/",
    "tests/fixtures/",
    "tests/guard_command_",
    "tests/test_guard_",
)


class ContributionDiffError(RuntimeError):
    """The PR base cannot safely establish whether contributions changed."""


def contribution_ids() -> set[str]:
    """Collect canonical extension identities from each contribution format."""
    ids = {str(json.loads(path.read_text())["id"]) for path in (ROOT / "contributions/extensions").glob("*.json")}
    ids.update(
        str(json.loads(path.read_text())["extension"]["extension_id"])
        for path in (ROOT / "contributions/command-sources").glob("command.*.json")
    )
    ids.update(
        "command.mcp-" + str(json.loads(path.read_text())["id"]).removeprefix("mcp.")
        for path in (ROOT / "contributions/mcp-servers").glob("*.json")
    )
    return ids


def catalog_ids() -> set[str]:
    """Read the identities covered by the checked-in generated catalog."""
    catalog = json.loads(CATALOG.read_text())
    return {entry["extension_id"] for entry in catalog["catalog"]}


def _contributions_changed(base_sha: str) -> list[str]:
    """Compare a verified base, fetching it once when a shallow checkout needs it."""
    if re.fullmatch(r"[0-9a-fA-F]{40}", base_sha) is None:
        raise ContributionDiffError("The comparison base must be a full Git commit SHA")
    normalized_sha = base_sha.lower()

    def _diff() -> subprocess.CompletedProcess[str]:
        """Read source changes without exposing Git output in error messages."""
        # Ordinary PRs cannot commit regenerated projections, including Rust
        # identity updates; generated-artifacts-guard enforces that ownership.
        return subprocess.run(
            ["git", "diff", "--name-only", normalized_sha, "HEAD", "--", "contributions/", "rust/"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    try:
        completed = _diff()
        if completed.returncode:
            # Shallow checkouts lack the base commit; fetch it and retry once.
            fetched = subprocess.run(
                ["git", "fetch", "--depth=1", "origin", normalized_sha],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            if fetched.returncode:
                raise ContributionDiffError("Cannot compare contribution sources: fetching the PR base failed")
            completed = _diff()
    except subprocess.TimeoutExpired:
        raise ContributionDiffError("Cannot compare contribution sources: Git timed out [git_timeout]") from None
    except UnicodeError:
        raise ContributionDiffError("Cannot compare contribution sources: Git output unreadable [git_encoding]") from None
    except OSError:
        raise ContributionDiffError("Cannot compare contribution sources: Git unavailable [git_process]") from None
    if completed.returncode:
        raise ContributionDiffError("Cannot compare contribution sources: Git diff failed after fetching the PR base")
    return [line for line in completed.stdout.splitlines() if line.strip()]


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments], cwd=ROOT, check=False, capture_output=True, text=True, timeout=30
    )


def pr_diff_paths() -> list[str] | None:
    """Paths this ref changes relative to the base branch, or None outside PR context.

    CI checkouts are shallow, so diff against a depth-1 fetch of the base ref —
    tree-to-tree, no merge-base history required. Locally, fall back to the
    merge-base against ``main`` when that ref exists.
    """

    import os

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


def _owned_path(path: str) -> bool:
    if path.endswith(".schema.json"):
        return False
    return any(
        path == owned or path.startswith(owned.rstrip("/") + "/")
        for owned in REGEN_OWNED_PATHS
    )


def regen_artifacts_absent_from_diff(diff: list[str] | None = None) -> bool:
    """No regen-owned generated path appears in this PR's diff.

    In PR context an absent artifact can never be refreshed by the author —
    freshness enforcement belongs to main and regen PRs. Outside PR context
    (no diff available) returns False so gates stay strict.
    """

    import os

    if not os.environ.get("GITHUB_BASE_REF") and os.environ.get("CI"):
        return False
    if diff is None:
        diff = pr_diff_paths()
    if diff is None:
        return False
    if not os.environ.get("GITHUB_BASE_REF") and not diff:
        return False
    return not any(_owned_path(path) for path in diff)


def main() -> int:
    """Print regeneration status only after any requested base comparison succeeds."""
    pending_ids = sorted(contribution_ids() - catalog_ids())
    changed: list[str] = []
    if "--changed-from" in sys.argv:
        base = sys.argv[sys.argv.index("--changed-from") + 1]
        try:
            changed = _contributions_changed(base)
        except ContributionDiffError as error:
            print(str(error), file=sys.stderr)
            return 1
    pending = bool(pending_ids) or bool(changed)
    if "--defer-freshness" in sys.argv:
        print("true" if regen_artifacts_absent_from_diff() else "false")
    elif "--flag" in sys.argv:
        print("true" if pending else "false")
    else:
        print(
            json.dumps(
                {
                    "pending": pending,
                    "pending_ids": pending_ids,
                    "changed_sources": changed,
                    "defer_freshness": regen_artifacts_absent_from_diff(),
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
