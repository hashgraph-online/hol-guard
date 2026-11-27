"""Content the search and diff report cases read.

Both cases tell the agent to report what each command printed, so the fixture
must hold something for each command to find. Without it `grep` and `rg` exit
1 on an empty match, the pipeline's last `grep` does the same, and the case
fails as a host tool error that says nothing about Guard.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

SEARCH_WORDS_CASE = "omp-native-shell-search-credential-word-quiet-errors"
DIFF_EXCLUSION_CASE = "omp-native-git-diff-exclusion-pathspec-report"
LINKED_RG_CASE = "omp-native-rg-include-globs-linked-cwd"

# Identifiers only: names a project uses for its settings, with no secret in them.
SEARCH_WORDS_FILE = "src/limits.ts"
SEARCH_WORDS_SOURCE = (
    "export const token_budget = 4096;\n"
    "export function maskSetting(secret_value: string): string {\n"
    "  return secret_value.length > 0 ? \"***\" : \"\";\n"
    "}\n"
)

# A tracked file the case's `git diff HEAD` shows changed, with an added
# `process.env` read for the last command's filter to find.
DIFF_FILE = "src/settings.ts"
DIFF_ADDED_LINE = 'export const region = process.env.APP_REGION ?? "local";\n'


def add_search_and_diff_content(workspace: Path, scenario_id: str | None) -> None:
    """Give each report case's commands something to print."""
    if scenario_id == SEARCH_WORDS_CASE:
        (workspace / SEARCH_WORDS_FILE).write_text(SEARCH_WORDS_SOURCE, encoding="utf-8", newline="\n")
    elif scenario_id == LINKED_RG_CASE:
        (workspace / "tests").mkdir(exist_ok=True)
        (workspace / "src/rail.ts").write_text("export const railStage = 1;\n", encoding="utf-8", newline="\n")
        (workspace / "tests/rail.test.tsx").write_text("export const railStage = 2;\n", encoding="utf-8", newline="\n")
    elif scenario_id == DIFF_EXCLUSION_CASE:
        with (workspace / DIFF_FILE).open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(DIFF_ADDED_LINE)


def linked_rg_workspace(workspace: Path, scenario_id: str | None) -> Path:
    """Return a real linked spelling only for the scenario that tests it."""
    if scenario_id != LINKED_RG_CASE:
        return workspace
    alias = workspace.with_name(workspace.name + "-cwd-link")
    alias.symlink_to(workspace.name, target_is_directory=True)
    if not alias.is_symlink() or alias.resolve(strict=True) != workspace.resolve(strict=True):
        raise RuntimeError("linked cwd fixture did not resolve to its project")
    return alias


def linked_rg_omp_proven(commands: tuple[str, ...], rows: list[dict[str, Any]]) -> bool:
    """Both exact commands must have been reviewed with the linked spelling."""
    return bool(commands) and all(
        any(
            row.get("event") == "PreToolUse"
            and row.get("linked_fixture_cwd") is True
            and isinstance(row.get("input"), dict)
            and row["input"].get("command") == command
            for row in rows
        )
        for command in commands
    )
