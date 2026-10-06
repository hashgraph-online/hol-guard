"""Plan which CI lanes a change actually needs, from a trusted merge-base diff.

Shadow-mode contract
---------------------
``ci-plan.json`` classifies the PR's changed files into the validation lanes that
protect them. In shadow mode every lane still runs; the plan is data consumed by
the ``hol-guard / required`` aggregate so it can report *which* lanes were planned
versus required. A later cutover uses the same plan to skip lanes the diff cannot
affect. Escalation is always conservative: anything ambiguous, security-adjacent,
or outside the authored-source set selects the full lane set.

Trusted-base policy
-------------------
The planner runs in the trusted workflow. The comparison base is the strict PR
merge parent from ``pr_merge_base`` (or ``GITHUB_BASE_REF`` for a same-repo merge
SHA already validated by the caller), never a value the contributor controls.
Lane selection is a pure function of the *changed file list* — a malicious PR can
at most cause *more* lanes to run, never fewer than its diff requires, because any
path outside the conservative fast set escalates to full.

# The base must be the strict PR merge parent validated by ``pr_merge_base``
# (or an explicit trusted ``PLAN_BASE_SHA``); ``GITHUB_BASE_REF`` is a mutable
# branch name, never used as a diff anchor.
Lanes
-----
- ``data``: ``contributions/**`` plus ``contracts/**`` schema/test data. Escalates
  to full whenever the same PR also touches code, workflows, trust, activation,
  or packaging — the planner cannot prove a data-only diff is benign in that case.
- ``full``: everything else, plus any data PR that mixes code/workflow changes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

PLAN_VERSION = 1
SHA_RE = re.compile(r"[0-9a-f]{40}")

# Lane identifiers must match the names the aggregate step reads.
LANE_DATA = "data"
LANE_FULL = "full"

# Paths that make a change "data-only". These are authored sources and their
# schemas/fixtures — the fast lane validates their invariants without the full
# native/Python fan-out. Everything NOT matching fast set escalates to full.
_DATA_PREFIXES = (
    "contributions/",
    "contracts/mcp-servers/",
)
_DATA_GLOBS = (
    re.compile(r"^tests/fixtures/command-source-.*\.v1\.json$"),
    re.compile(r"^tests/fixtures/extension-listings/"),
    re.compile(r"^tests/fixtures/mcp-server-.*\.v1\.json$"),
)

# Paths that ALWAYS escalate to full even inside an otherwise-data diff, because
# they carry security/trust/activation semantics a data lane must not shortcut.
_ESCALATE_ALWAYS = (
    re.compile(r"^\.github/workflows/"),
    re.compile(r"^\.github/actions/"),
    re.compile(r"^rust/"),
    re.compile(r"^src/"),
    re.compile(r"^scripts/"),
    re.compile(r"^tests/.*\.py$"),
    re.compile(r"^contracts/.*trust"),
    re.compile(r"^pyproject\.toml$"),
    re.compile(r"^uv\.lock$"),
    re.compile(r"^rust-toolchain"),
    # Authority surface under contracts/extensions/: generated catalog/program,
    # packaging lists, and schemas carry security semantics; changes there take
    # the full lane (maintainer regen PRs intentionally stay full).
    re.compile(r"^contracts/extensions/"),
    re.compile(r"^docs/"),
    re.compile(r"^\.[^/]+$"),
)



# Raw-diff modes that are never data: symlink, gitlink, or a typechange to any
# non-regular file. ``--no-renames`` surfaces renames as delete+add, so the
# deleted source path escalates on its own.
_UNSAFE_MODES = {"120000", "160000"}

@dataclass
class Plan:
    """The emitted plan. ``lanes`` is the set of lanes the diff requires."""

    version: int = PLAN_VERSION
    base: str = ""
    head: str = ""
    lanes: list[str] = field(default_factory=list)
    data_only: bool = False
    escalate_reason: str = ""
    changed: list[str] = field(default_factory=list)


def _is_data_path(path: str) -> bool:
    if any(path.startswith(prefix) for prefix in _DATA_PREFIXES):
        return True
    return any(pattern.match(path) for pattern in _DATA_GLOBS)


def _escalates(path: str) -> str:
    for pattern in _ESCALATE_ALWAYS:
        if pattern.match(path):
            return pattern.pattern
    return ""




def plan(base: str, head: str, *, root: Path) -> Plan:
    raw = subprocess.run(
        ["git", "-C", str(root), "diff", "--raw", "--no-renames", "--diff-filter=ACDMRT", base, head],
        capture_output=True, text=True, check=True, timeout=60,
    )
    files: list[str] = []
    unsafe: list[str] = []
    for line in raw.stdout.splitlines():
        meta, _, path = line.partition("\t")
        if not meta.startswith(":") or not path:
            continue
        parts = meta[1:].split()
        dst_mode = parts[1] if len(parts) > 1 else ""
        status = parts[4][:1] if len(parts) > 4 else ""
        files.append(path)
        if status != "D" and dst_mode != "100644":
            unsafe.append(path)
    files = sorted(set(files))
    result = Plan(base=base, head=head, changed=files)
    if not files:
        # Empty/ambiguous diff: never hand out the cheap lane blind.
        result.lanes = [LANE_FULL]
        result.data_only = False
        result.escalate_reason = "empty-diff"
        return result
    for path in unsafe:
        result.lanes = [LANE_FULL]
        result.data_only = False
        result.escalate_reason = f"unsafe-file-mode: {path}"
        return result
    for path in files:
        reason = _escalates(path)
        if reason or not _is_data_path(path):
            result.lanes = [LANE_FULL]
            result.data_only = False
            result.escalate_reason = reason or f"non-data path: {path}"
            return result
    result.lanes = [LANE_DATA]
    result.data_only = True
    return result


def resolve_base(environment: dict, *, root: Path) -> tuple[str, str]:
    """Return (base, head) from trusted event data, validating a PR merge checkout."""
    head = environment.get("PLAN_PR_HEAD_SHA") or environment.get("GITHUB_SHA", "")
    explicit_base = environment.get("PLAN_BASE_SHA", "")
    if explicit_base:
        if not SHA_RE.fullmatch(explicit_base):
            raise ValueError("PLAN_BASE_SHA is not a full SHA")
        return explicit_base, head
    # Reuse the strict PR merge-base resolver: two-parent merge, exact head+merge.
    from scripts.ci.pr_merge_base import comparison_base

    merge = environment.get("GITHUB_SHA", "")
    pr_head = environment.get("PLAN_PR_HEAD_SHA", "")
    if pr_head:
        base = comparison_base(pr_head, merge, root=root)
        return base, pr_head
    raise ValueError("No comparison base: set PLAN_BASE_SHA, or PR head via PLAN_PR_HEAD_SHA")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="ci-plan.json")
    parser.add_argument("--base", default=None, help="Trusted base SHA (else resolved)")
    parser.add_argument("--head", default=None, help="Head SHA (else GITHUB_SHA)")
    parser.add_argument("--root", default=None, help="Repo root (default: script's repo)")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    if args.base:
        env["PLAN_BASE_SHA"] = args.base
    if args.head:
        env["PLAN_PR_HEAD_SHA"] = args.head
    base, head = (args.base, args.head) if args.base and args.head else resolve_base(env, root=root)
    result = plan(base, head, root=root)
    Path(args.output).write_text(json.dumps(asdict(result), indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"lanes": result.lanes, "data_only": result.data_only}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
