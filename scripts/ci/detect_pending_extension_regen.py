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
    "docs/guard/extensions/README.md",
    "docs/guard/extensions/catalog.v1.json",
    "docs/guard/extensions/catalog.v2.json",
    "src/codex_plugin_scanner/guard/contracts/data/extensions",
    "src/codex_plugin_scanner/guard/contracts/data/mcp_servers",
)

# Canonical inputs whose changes can stale the projections above.
REGEN_INPUT_PREFIXES: tuple[str, ...] = (
    "contributions/",
    "rust/",
    "scripts/build_native_command_program.py",
    "src/codex_plugin_scanner/guard/",
    "contracts/extensions/",
    "contracts/managed-controls/",
    "docs/guard/",
    "tests/fixtures/",
    "tests/guard_command_",
    "tests/test_guard_",
)
REGEN_INPUT_PATHSPECS: tuple[str, ...] = tuple(
    # Directory prefixes work as pathspecs; file-prefix families need a glob
    # suffix while exact files keep their literal pathspec.
    prefix if prefix.endswith("/") or Path(prefix).suffix else f"{prefix}*"
    for prefix in REGEN_INPUT_PREFIXES
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
            ["git", "diff", "--name-only", normalized_sha, "HEAD", "--", *REGEN_INPUT_PATHSPECS],
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
        raise ContributionDiffError(
            "Cannot compare contribution sources: Git output unreadable [git_encoding]"
        ) from None
    except OSError:
        raise ContributionDiffError("Cannot compare contribution sources: Git unavailable [git_process]") from None
    if completed.returncode:
        raise ContributionDiffError("Cannot compare contribution sources: Git diff failed after fetching the PR base")
    return [line for line in completed.stdout.splitlines() if line.strip()]


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(["git", *arguments], cwd=ROOT, check=False, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(["git", *arguments], 1, "", "")


def pr_diff_paths() -> list[str] | None:
    """Paths this PR changes relative to its base, or None outside PR context.

    Prefers the merge-checkout's first parent — the exact base commit the
    build merged against — so artifact regeneration merged into main after the
    checkout was built is never attributed to the PR. Head checkouts fall back
    to a depth-1 fetch of the base ref tip. Locally, falls back to the
    merge-base against ``main`` when that ref exists.
    """

    import os

    if not os.environ.get("GITHUB_BASE_REF"):
        if _git("rev-parse", "--verify", "main").returncode == 0:
            result = _git("diff", "--name-only", "main...HEAD")
            return result.stdout.splitlines() if result.returncode == 0 else None
        return None
    commit = _git("cat-file", "commit", "HEAD")
    parents = [line.split()[1] for line in commit.stdout.splitlines() if line.startswith("parent ")]
    base_ref = os.environ["GITHUB_BASE_REF"]
    probe = _git("rev-parse", "--is-shallow-repository")
    shallow = probe.returncode != 0 or probe.stdout.strip() == "true"
    fetch = [
        "fetch",
        "-q",
        *(["--depth=1"] if shallow else []),
        "origin",
        f"+refs/heads/{base_ref}:refs/remotes/pending-diff/base",
    ]
    base_tip = "pending-diff/base"
    if _git(*fetch).returncode:
        base_tip = None
    head_sha = None
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        try:
            head_sha = json.loads(Path(event_path).read_text())["pull_request"]["head"]["sha"]
        except (OSError, KeyError, ValueError):
            head_sha = None
    current = _git("rev-parse", "HEAD")
    synthetic_merge = (
        len(parents) >= 2 and head_sha is not None and current.returncode == 0 and current.stdout.strip() != head_sha
    )
    if synthetic_merge:
        # HEAD is the synthetic refs/pull merge, so its first parent is the
        # exact base commit this build merged — diffing it never attributes
        # main-side regeneration to the PR.
        fetched = _git("fetch", "-q", "--depth=1", "origin", parents[0])
        if fetched.returncode == 0:
            result = _git("diff", "--name-only", "FETCH_HEAD", "HEAD")
            if result.returncode == 0:
                return result.stdout.splitlines()
    if base_tip is None:
        return None
    result = _git("diff", "--name-only", base_tip, "HEAD")
    return result.stdout.splitlines() if result.returncode == 0 else None


def _owned_path(path: str) -> bool:
    if path.endswith(".schema.json"):
        return False
    return any(path == owned or path.startswith(owned.rstrip("/") + "/") for owned in REGEN_OWNED_PATHS)


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
        return bool(os.environ.get("GITHUB_BASE_REF"))
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
    defer_freshness = regen_artifacts_absent_from_diff() and not pending
    if "--defer-freshness" in sys.argv:
        print("true" if defer_freshness else "false")
    elif "--flag" in sys.argv:
        print("true" if pending else "false")
    else:
        print(
            json.dumps(
                {
                    "pending": pending,
                    "pending_ids": pending_ids,
                    "changed_sources": changed,
                    "defer_freshness": defer_freshness,
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
