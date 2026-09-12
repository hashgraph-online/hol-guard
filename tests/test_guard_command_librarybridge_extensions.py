"""Structured LibraryBridge command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command

LIBRARYBRIDGE_MUTATIONS: tuple[tuple[str, str, str], ...] = (
    ("librarybridge fix 01234567 --force", "LibraryBridge fix command", "command.librarybridge.fix"),
    ("librarybridge undo 01234567", "LibraryBridge undo command", "command.librarybridge.undo"),
    ("librarybridge backup 01234567", "LibraryBridge backup command", "command.librarybridge.backup"),
    (
        "librarybridge lutris import --plan /tmp/librarybridge-plan.json",
        "LibraryBridge Lutris import command",
        "command.librarybridge.lutris-import",
    ),
)


def test_librarybridge_mutations_review_but_dry_runs_do_not(tmp_path: Path) -> None:
    """Mutating LibraryBridge commands review while previews stay automatic."""

    for command, action_class, rule_id in LIBRARYBRIDGE_MUTATIONS:
        reviewed = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert reviewed["status"] == "review", command
        assert reviewed["classification"]["action_class"] == action_class, command
        assert reviewed["controlling_rule_id"] == rule_id, command

        preview = inspect_command(f"{command} --dry-run", cwd=tmp_path, home_dir=tmp_path)
        assert preview["status"] == "no_match", command

    for command in ("librarybridge scan", "librarybridge storage"):
        observer = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert observer["status"] == "no_match", command
