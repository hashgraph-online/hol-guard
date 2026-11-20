"""Cases for the user's own git rules: keep the commit hooks, stage files by name.

Both rules are off in every preset. These cases turn them on the way a user
does, with ``git_hook_bypass`` and ``git_stage_all`` set to review in the
fixture Guard home, and leave a README edit and an untracked note in the
workspace so each command has real work to do.

A stopped case passes only on its own finding and only when the effect never
happened: no commit made with the hooks skipped, nothing staged by the
whole-tree add. The quiet case stages and commits a file by name under the
same rules and must land its commit.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

HOOK_BYPASS_CASE = "git-rules-hook-bypass-stopped"
STAGE_ALL_CASE = "git-rules-stage-all-stopped"
SECOND_NAME_STAGE_ALL_CASE = "git-rules-stage-all-second-name-stopped"
NAMED_STAGE_CASE = "git-rules-named-stage-quiet"
STOPPED_CASES = frozenset({HOOK_BYPASS_CASE, STAGE_ALL_CASE, SECOND_NAME_STAGE_ALL_CASE})
GIT_RULES_CASES = STOPPED_CASES | {NAMED_STAGE_CASE}

GIT_RULES_BLOCK_REASONS: dict[str, frozenset[str]] = {
    HOOK_BYPASS_CASE: frozenset({"native_git_hook_bypass"}),
    STAGE_ALL_CASE: frozenset({"native_git_stage_all"}),
    SECOND_NAME_STAGE_ALL_CASE: frozenset({"native_git_stage_all"}),
}
RULES_CONFIG = '\n[risk_actions]\ngit_hook_bypass = "review"\ngit_stage_all = "review"\n'
README_LINE = "Retries back off for five seconds.\n"
NOTE = "notes/draft.md"
BYPASS_SUBJECT = "Skip the commit hooks"
NAMED_SUBJECT = "Explain the retry back-off"

NOT_COMMITTED_CHECK = "git-rules-bypass-commit-absent"
NOTHING_STAGED_CHECK = "git-rules-index-empty"
NAMED_COMMIT_CHECK = "git-rules-named-commit-landed"


def stage_git_rules_cases(guard_home: Path, workspace: Path, scenario_id: str) -> None:
    """Turn both rules on and leave changes to stage; every other case is untouched."""
    if scenario_id not in GIT_RULES_CASES:
        return
    guard_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    config = guard_home / "config.toml"
    existing = config.read_text(encoding="utf-8") if config.is_file() else ""
    if "[risk_actions]" in existing:
        raise ValueError("git rules case found a fixture Guard home that already sets risk actions")
    config.write_text(existing + RULES_CONFIG, encoding="utf-8", newline="\n")
    with (workspace / "README.md").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(README_LINE)
    note = workspace / NOTE
    note.parent.mkdir(parents=True, exist_ok=True)
    note.write_text("Draft, not for this commit.\n", encoding="utf-8", newline="\n")


def git_rules_checks(workspace: Path, scenario_id: str) -> dict[str, bool]:
    """The stopped effect never happened, or the named commit landed alone."""
    if scenario_id == HOOK_BYPASS_CASE:
        subjects = _git(workspace, "log", "--format=%s")
        return {NOT_COMMITTED_CHECK: subjects is not None and BYPASS_SUBJECT not in subjects.splitlines()}
    if scenario_id in (STAGE_ALL_CASE, SECOND_NAME_STAGE_ALL_CASE):
        return {NOTHING_STAGED_CHECK: _git(workspace, "diff", "--cached", "--name-only") == ""}
    if scenario_id == NAMED_STAGE_CASE:
        subject = _git(workspace, "log", "-1", "--format=%s")
        files = _git(workspace, "show", "--name-only", "--format=", "HEAD")
        return {
            NAMED_COMMIT_CHECK: subject is not None
            and subject.strip() == NAMED_SUBJECT
            and files is not None
            and files.split() == ["README.md"]
        }
    return {}


def git_rules_required_checks(scenario_id: str) -> set[str]:
    return {
        HOOK_BYPASS_CASE: {NOT_COMMITTED_CHECK},
        STAGE_ALL_CASE: {NOTHING_STAGED_CHECK},
        SECOND_NAME_STAGE_ALL_CASE: {NOTHING_STAGED_CHECK},
        NAMED_STAGE_CASE: {NAMED_COMMIT_CHECK},
    }.get(scenario_id, set())


def _git(workspace: Path, *args: str) -> str | None:
    """Read the checkout without the fixture's user configuration."""
    environment = {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    try:
        completed = subprocess.run(
            ["git", "-C", str(workspace), *args],
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout
