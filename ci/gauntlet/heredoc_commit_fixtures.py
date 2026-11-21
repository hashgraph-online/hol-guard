"""A README change for the case that commits it with a here-document message.

Agents pass a multi-line commit message as ``git commit -m "$(cat <<'EOF' ...
EOF)"``. Guard runs that commit in the workspace sandbox, so the case only
shows the contained commit works when there is something to commit: with an
unchanged README, ``git commit`` answers "nothing to commit" with exit 1 on
the host and in the sandbox alike, and the case proves nothing either way.
The fixture therefore leaves an unstaged README edit for the command's own
``git add`` to stage, and the checks require that the commit landed with the
message the here-document carried.

Oh My Pi agents also commit through the eval tool's ``commit`` prelude, which
runs Git from the harness process rather than a shell. The eval case gets the
same README edit, and its checks require the commit to land with the subject
the program passed. The prelude formats the body itself, so only the subject
is compared.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

HEREDOC_COMMIT_CASE = "omp-native-git-commit-heredoc-substitution-message"
EVAL_COMMIT_CASE = "omp-native-eval-commit-draft"
HEREDOC_COMMIT_README_LINE = "The retry window is five seconds.\n"
# What ``git log --format=%B`` prints for the case's message, trailing newline stripped.
HEREDOC_COMMIT_MESSAGE = "Add notes\n\nExplain the retry window."
EVAL_COMMIT_SUBJECT = "Add notes"


def add_heredoc_commit_change(worktree: Path, scenario_id: str | None) -> None:
    """Append one line to the tracked README, leaving it for the case's command to stage."""
    if scenario_id not in (HEREDOC_COMMIT_CASE, EVAL_COMMIT_CASE):
        return
    readme = worktree / "README.md"
    with readme.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(HEREDOC_COMMIT_README_LINE)


def _git(worktree: Path, *args: str) -> str | None:
    """Read the checkout without the fixture's user configuration."""
    environment = {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    try:
        completed = subprocess.run(
            ["git", "-C", str(worktree), *args],
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout


def heredoc_commit_checks(workspace: Path, scenario_id: str) -> dict[str, bool]:
    """The README edit is committed, with the here-document's message, and nothing of it is left over."""
    if scenario_id not in (HEREDOC_COMMIT_CASE, EVAL_COMMIT_CASE):
        return {}
    message = _git(workspace, "log", "-1", "--format=%B")
    if scenario_id == EVAL_COMMIT_CASE:
        message = None if message is None else message.split("\n", 1)[0] + "\n"
        expected = EVAL_COMMIT_SUBJECT
    else:
        expected = HEREDOC_COMMIT_MESSAGE
    committed = _git(workspace, "show", "HEAD:README.md")
    leftover = _git(workspace, "status", "--porcelain", "--", "README.md")
    return {
        "heredoc-commit-message-exact": message is not None and message.rstrip("\n") == expected,
        "heredoc-commit-readme-committed": committed is not None and committed.endswith(HEREDOC_COMMIT_README_LINE),
        "heredoc-commit-readme-clean": leftover == "",
    }
