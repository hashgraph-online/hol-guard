"""Prepare a maintainer-owned intake branch for a contribution PR we cannot push to.

GitHub cannot grant upstream maintainers push access to organization-owned
forks, and some contributors disable maintainer edits. For those PRs the
maintainer lifecycle runs on an upstream intake branch instead:

1. Fetch the contributor's exact head commits (authorship preserved verbatim).
2. Branch ``intake/pr-NNNN`` from those commits, merge ``origin/main``.
3. Resolve generated-artifact conflicts and run the full artifact refresh.
4. Push the intake branch and open (or update) an upstream PR targeting main.

``--pr`` accepts several PR numbers to batch a landing: every contributor head
is merged onto one ``intake/batch-...`` branch, so a single artifact refresh
covers all of them instead of regenerating per contribution.

Because the contributor commit SHAs remain ancestors, merging the intake PR
with a merge commit marks the original PRs merged. With squash merge, close the
original PRs manually with a reference comment.

The refresh step executes code from the merged tree (``src/`` imports, test
build tooling), so the contribution diff is gated: paths inside
``contributions/`` and ``tests/fixtures/`` pass as contributor-owned, and
machine-managed paths (generated projections, rendered docs, and refresh
inputs such as the trust-class map and ``extension_builder`` modules) pass because the
script resets them to ``origin/main`` — restoring trusted content and
deleting planted files — before refresh runs. Anything else is refused
unless ``--trust-tooling-changes`` is passed after manual review. Reviewed test
code and managed-controls vectors are not machine-owned; they require that
explicit tooling review or ``--skip-regen`` and are preserved rather than reset.
Portable fixtures remain contributor-owned and are never rewritten by refresh.

Requires ``gh`` authenticated as a maintainer and push access to origin.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(command: list[str], *, capture: bool = True) -> str:
    completed = subprocess.run(command, cwd=ROOT, capture_output=capture, text=True, check=False)
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise SystemExit(f"intake failed: {' '.join(command)}\n{detail[:2048]}")
    # Only the trailing newline is stripped: git -z path lists are consumed
    # verbatim and must not lose leading/trailing whitespace in filenames.
    return (completed.stdout or "").rstrip("\n")


def _gh(*args: str) -> str:
    return _run(["gh", *args])


MACHINE_DIRS = (
    "contracts/extensions/",
    "docs/guard/extensions/",
    "src/codex_plugin_scanner/guard/contracts/data/extensions/",
    "src/codex_plugin_scanner/guard/extension_builder/",
)


def is_machine_managed(path: str) -> bool:
    """Separate generated product paths from independently reviewed expectations."""
    return path.startswith(MACHINE_DIRS)


def main() -> int:
    """Prepare a contributor intake branch while preserving reviewed expectations and ancestry."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", type=int, nargs="+", required=True)
    parser.add_argument("--repo", default="hashgraph-online/hol-guard")
    parser.add_argument("--skip-regen", action="store_true")
    parser.add_argument("--push", action="store_true", help="push the intake branch to origin")
    parser.add_argument(
        "--trust-tooling-changes",
        action="store_true",
        help="allow refresh to run when the contribution modifies build/tooling files",
    )
    parser.add_argument(
        "--salvage",
        action="store_true",
        help="land only the contributor-owned diff: every path outside "
        "contributions/ and tests/fixtures/ is reset to origin/main after the "
        "merge, before refresh runs",
    )
    args = parser.parse_args()

    contributions = []
    for pr_number in args.pr:
        pr = _gh(
            "pr",
            "view",
            str(pr_number),
            "--repo",
            args.repo,
            "--json",
            "number,title,headRefName,headRepository,headRepositoryOwner,author,state,isDraft",
        )
        info = json.loads(pr)
        if info["state"] != "OPEN":
            raise SystemExit(f"PR #{pr_number} is {info['state']}")
        head_repo = info["headRepository"]
        if head_repo is None:
            raise SystemExit(f"PR #{pr_number} head repository is gone")
        clone_url = f"https://github.com/{info['headRepositoryOwner']['login']}/{head_repo['name']}.git"
        contributions.append((pr_number, clone_url, info["headRefName"]))

    if len(contributions) == 1:
        branch = f"intake/pr-{contributions[0][0]}"
    else:
        branch = "intake/batch-" + "-".join(str(pr_number) for pr_number, _, _ in contributions)
    pr_refs = ", ".join(f"#{pr_number}" for pr_number, _, _ in contributions)

    if _run(["git", "status", "--porcelain"]):
        raise SystemExit("worktree or index is not clean; commit or stash before intake")

    contributor_heads = []
    for _pr_number, clone_url, head_branch in contributions:
        _run(["git", "fetch", clone_url, head_branch])
        contributor_heads.append(_run(["git", "rev-parse", "FETCH_HEAD"]))
    _run(["git", "fetch", "origin", "main"])

    contributor_owned = ("contributions/", "tests/fixtures/")
    # Only generated product data and existing credential-sensitive tooling
    # are reset. Reviewed fixture/vector/test edits are no longer regenerated.
    machine_touched: set[str] = set()
    salvaged: set[str] = set()

    for (pr_number, _, _), contributor_head in zip(contributions, contributor_heads, strict=True):
        merge_base = _run(["git", "merge-base", contributor_head, "origin/main"])
        # --no-renames -z keeps literal paths: a renamed managed file must show
        # its source path so the reset below restores it rather than leaving a
        # trusted file deleted, and -z avoids quoted/octal-escaped names.
        changed = [
            p
            for p in _run(["git", "diff", "--name-only", "--no-renames", "-z", merge_base, contributor_head]).split(
                "\0"
            )
            if p
        ]
        machine_touched.update(p for p in changed if is_machine_managed(p))
        outside = [p for p in changed if not p.startswith(contributor_owned) and not is_machine_managed(p)]
        if outside:
            if args.salvage:
                # Non-contributor edits are reverted after the merge, before
                # refresh runs: the contributor commits stay ancestors (so the
                # original PR still marks merged), but only their
                # contributions/ and tests/fixtures/ payload lands.
                salvaged.update(outside)
            elif not (args.trust_tooling_changes or args.skip_regen):
                raise SystemExit(
                    f"PR #{pr_number} changes files outside contributions/, tests/fixtures/, "
                    "and machine-managed paths; refresh executes src/, tests/, scripts/, and "
                    "build tooling from the merged tree with maintainer credentials. Review "
                    "the diff, then rerun with --trust-tooling-changes, --skip-regen, or "
                    "--salvage:\n" + "\n".join(outside)
                )

    if _run(["git", "branch", "--list", branch]):
        _run(["git", "checkout", branch])
        foreign = _run(
            [
                "git",
                "rev-list",
                "--no-merges",
                "--invert-grep",
                "--grep=regenerate artifacts for intake",
                branch,
                "--not",
                "origin/main",
                *contributor_heads,
            ]
        )
        if foreign:
            print(
                f"intake branch {branch} contains commits outside origin/main, the "
                "current contributor heads, and this script's regeneration commits "
                "(a contributor likely rebased, or the branch has manual commits). "
                f"Rebuild with:\n  git checkout main && git branch -D {branch} && "
                "rerun this script\nforeign commits:\n" + foreign,
                file=sys.stderr,
            )
            return 1
        pending_heads = contributor_heads
    else:
        _run(["git", "checkout", "-b", branch, contributor_heads[0]])
        pending_heads = contributor_heads[1:]

    def salvage_conflicts() -> bool:
        """Under --salvage, resolve conflicts on non-contributor paths to the
        incoming side — the reset below normalizes them to origin/main anyway.
        Conflicts inside contributor-owned fixtures stay manual: refresh does
        not generate their independently reviewed expectations."""
        unmerged = [p for p in _run(["git", "diff", "--name-only", "--diff-filter=U", "-z"]).split("\0") if p]
        resolvable = [p for p in unmerged if not p.startswith(contributor_owned) or is_machine_managed(p)]
        if len(resolvable) != len(unmerged):
            return False
        checked_out = []
        for path in resolvable:
            probe = subprocess.run(
                ["git", "checkout", "--theirs", "--", path],
                cwd=ROOT,
                capture_output=True,
                check=False,
            )
            if probe.returncode:
                # modify/delete conflicts have no --theirs stage; the incoming
                # side deleted it
                _run(["git", "rm", "-f", "-q", "--ignore-unmatch", "--", path])
            else:
                checked_out.append(path)
        if checked_out:
            _run(["git", "add", "-A", "--", *checked_out])
        _run(["git", "commit", "--no-edit"])
        return True

    for contributor_head in pending_heads:
        head_merge = subprocess.run(
            ["git", "merge", "--no-edit", contributor_head],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if head_merge.returncode and not (args.salvage and salvage_conflicts()):
            print(
                "conflicts merging a contributor head: resolve, commit, then rerun:\n"
                "  git add -A && git commit && python scripts/intake_contribution_pr.py ...",
                file=sys.stderr,
            )
            return 1

    merge = subprocess.run(
        ["git", "merge", "--no-edit", "origin/main"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if merge.returncode and not (args.salvage and salvage_conflicts()):
        print(
            "merge conflicts: resolve generated artifacts by regeneration, then run\n"
            "  git checkout --theirs/ours as needed && git commit && "
            "python scripts/refresh_extension_artifacts.py",
            file=sys.stderr,
        )
        return 1

    # Reset every machine-managed path the contributions touched to main's
    # content before anything from the merged tree executes: refresh outputs
    # get rebuilt below, refresh inputs revert to trusted main content, and
    # files planted under managed directories are deleted.
    # The reset is sanitization, not regeneration — it applies even under
    # --skip-regen and --trust-tooling-changes, which concern tooling paths
    # and the refresh step, not machine ownership. Under --salvage it also
    # covers every non-contributor path the PRs touched.
    reset_paths = machine_touched | salvaged
    for path in sorted(reset_paths):
        probe = subprocess.run(
            ["git", "cat-file", "-e", f"origin/main:{path}"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        if probe.returncode == 0:
            _run(["git", "checkout", "origin/main", "--", path])
        else:
            _run(["git", "rm", "-f", "-q", "--ignore-unmatch", "--", path])
    if reset_paths and _run(["git", "status", "--porcelain"]):
        _run(
            [
                "git",
                "commit",
                "-m",
                "chore(extensions): reset managed and salvaged paths "
                f"before regenerate artifacts for intake of PRs {pr_refs}",
            ]
        )

    print(f"intake branch {branch} prepared at {'+'.join(head[:9] for head in contributor_heads)} + origin/main")
    if not args.skip_regen:
        _run([sys.executable, "scripts/refresh_extension_artifacts.py"], capture=False)
        _run(
            [
                "git",
                "add",
                "-A",
                "contracts/extensions",
                "docs/guard/extensions",
                "contributions/extensions",
                "src/codex_plugin_scanner/guard/contracts/data/extensions",
                "src/codex_plugin_scanner/guard/extension_builder",
            ]
        )
        if _run(["git", "status", "--porcelain"]):
            _run(
                [
                    "git",
                    "commit",
                    "-m",
                    f"chore(extensions): regenerate artifacts for intake of PRs {pr_refs}",
                ]
            )
        else:
            print("regeneration produced no changes")
    if args.push:
        _run(["git", "push", "--force-with-lease", "-u", "origin", branch], capture=False)
        print(f"open a PR from {branch} to main; prefer a merge commit so {pr_refs} auto-close as merged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
