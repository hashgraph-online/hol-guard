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
    if "--flag" in sys.argv:
        print("true" if pending else "false")
    else:
        print(
            json.dumps(
                {"pending": pending, "pending_ids": pending_ids, "changed_sources": changed},
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
