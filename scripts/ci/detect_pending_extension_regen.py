"""Detect contribution sources not covered by the generated catalog.

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


# Paths whose content feeds generated projections.  Contributions are the
# canonical extension sources; ``rust/`` feeds the compiler implementation
# digest (build.rs hashes every crate source, so any Rust change alters
# ``authoring_semantics_digest``); guard runtime/CLI sources, command corpus
# and decision-diff tests, and bound docs feed the decision-diff report's
# ``sources_sha256`` bindings; ``contracts/`` covers authored inputs such as
# the trust map.  A change under any of these legitimately leaves checked-in
# artifacts one maintainer regen behind.
_REGEN_INPUT_PREFIXES = (
    "contributions/",
    "rust/",
    "src/codex_plugin_scanner/guard/",
    "tests/",
    "docs/guard/",
    "contracts/",
)
_REGEN_INPUT_FILES = (
    "scripts/refresh_extension_artifacts.py",
    "scripts/build_native_command_program.py",
    "scripts/render_command_extension_directory.py",
)
# Generated outputs inside the input prefixes must not flag themselves as
# pending inputs when a contribution PR carries them.
_GENERATED_OUTPUTS = frozenset(
    {
        "contracts/extensions/native-command-program.v1.json",
        "tests/fixtures/guard-command-corpus/decision-diff-report.json",
        "tests/fixtures/guard-command-corpus/decision-diff-report.framed-sha256",
    }
)


def _changed_since_base(base_sha: str, paths: tuple[str, ...], subject: str) -> list[str]:
    """Compare a verified base, fetching it once when a shallow checkout needs it."""
    if re.fullmatch(r"[0-9a-fA-F]{40}", base_sha) is None:
        raise ContributionDiffError("The comparison base must be a full Git commit SHA")
    normalized_sha = base_sha.lower()

    def _diff() -> subprocess.CompletedProcess[str]:
        """Read path changes without exposing Git output in error messages."""
        return subprocess.run(
            ["git", "diff", "--name-only", normalized_sha, "HEAD", "--", *paths],
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
                raise ContributionDiffError(f"Cannot compare {subject}: fetching the PR base failed")
            completed = _diff()
    except subprocess.TimeoutExpired:
        raise ContributionDiffError(f"Cannot compare {subject}: Git timed out [git_timeout]") from None
    except UnicodeError:
        raise ContributionDiffError(f"Cannot compare {subject}: Git output unreadable [git_encoding]") from None
    except OSError:
        raise ContributionDiffError(f"Cannot compare {subject}: Git unavailable [git_process]") from None
    if completed.returncode:
        raise ContributionDiffError(f"Cannot compare {subject}: Git diff failed after fetching the PR base")
    return [line for line in completed.stdout.splitlines() if line.strip()]


def _contributions_changed(base_sha: str) -> list[str]:
    """Compare a verified base, fetching it once when a shallow checkout needs it."""
    return _changed_since_base(base_sha, ("contributions/",), "contribution sources")


def _regen_inputs_changed(base_sha: str) -> list[str]:
    """Compare projection inputs against a verified base, excluding generated outputs."""
    changed = _changed_since_base(base_sha, (*_REGEN_INPUT_PREFIXES, *_REGEN_INPUT_FILES), "projection inputs")
    return [path for path in changed if path not in _GENERATED_OUTPUTS]


def main() -> int:
    """Print regeneration status only after any requested base comparison succeeds."""
    pending_ids = sorted(contribution_ids() - catalog_ids())
    changed: list[str] = []
    if "--changed-from" in sys.argv:
        base = sys.argv[sys.argv.index("--changed-from") + 1]
        try:
            changed = sorted(set(_contributions_changed(base)) | set(_regen_inputs_changed(base)))
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
