"""Structured backup command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize(
    ("command", "action_class", "rule_id"),
    [
        ("rclone sync source: destination:", "Rclone destructive command", "command.backup.rclone.mutation"),
        ("rclone.exe move source: destination:", "Rclone destructive command", "command.backup.rclone.mutation"),
        (
            "rclone --config --dry-run purge remote:archive",
            "Rclone destructive command",
            "command.backup.rclone.mutation",
        ),
        (
            "rclone --log-level DEBUG purge remote:archive",
            "Rclone destructive command",
            "command.backup.rclone.mutation",
        ),
        (
            "rclone --log-level=DEBUG purge remote:archive",
            "Rclone destructive command",
            "command.backup.rclone.mutation",
        ),
        (
            "rclone --future-global-option --dry-run purge remote:archive",
            "Rclone destructive command",
            "command.backup.rclone.mutation",
        ),
        ("restic -r s3:archive forget latest --prune", "Restic destructive command", "command.backup.restic.mutation"),
        (
            "restic --compression max forget latest --prune",
            "Restic destructive command",
            "command.backup.restic.mutation",
        ),
        (
            "restic --compression=max forget latest --prune",
            "Restic destructive command",
            "command.backup.restic.mutation",
        ),
        (
            "restic --future-global-option --dry-run forget latest --prune",
            "Restic destructive command",
            "command.backup.restic.mutation",
        ),
        ("restic rewrite --forget latest", "Restic destructive command", "command.backup.restic.mutation"),
        ("borg.cmd prune --keep-daily 7 /archive", "Borg destructive command", "command.backup.borg.mutation"),
        ("borg delete /archive::old", "Borg destructive command", "command.backup.borg.mutation"),
        ("borg --repo /archive prune --keep-daily 7", "Borg destructive command", "command.backup.borg.mutation"),
        ("borg -r/archive delete old", "Borg destructive command", "command.backup.borg.mutation"),
        (
            "borg --remote-ratelimit 1000 delete /archive::old",
            "Borg destructive command",
            "command.backup.borg.mutation",
        ),
        (
            "borg --remote-ratelimit=1000 delete /archive::old",
            "Borg destructive command",
            "command.backup.borg.mutation",
        ),
        (
            "borg --future-global-option --dry-run delete /archive::old",
            "Borg destructive command",
            "command.backup.borg.mutation",
        ),
        ("velero backup delete release-1", "Velero destructive command", "command.backup.velero.deletion"),
        (
            "velero --namespace prod backup delete release-1",
            "Velero destructive command",
            "command.backup.velero.deletion",
        ),
        (
            "velero --kubeconfig=config-file restore delete release-1",
            "Velero destructive command",
            "command.backup.velero.deletion",
        ),
        ("velero -nprod schedule delete nightly", "Velero destructive command", "command.backup.velero.deletion"),
        (
            "velero --future-global-option cluster backup delete release-1",
            "Velero destructive command",
            "command.backup.velero.deletion",
        ),
        (
            "velero --future-global-option=cluster backup delete release-1",
            "Velero destructive command",
            "command.backup.velero.deletion",
        ),
        (
            "velero --future-global-option --help backup delete release-1",
            "Velero destructive command",
            "command.backup.velero.deletion",
        ),
    ],
)
def test_backup_rules_feed_runtime_hooks(
    command: str,
    action_class: str,
    rule_id: str,
    tmp_path: Path,
) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["classification"]["action_class"] == action_class
    assert payload["controlling_rule_id"] == rule_id
    runtime_match = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert runtime_match is not None
    assert runtime_match.action_class == action_class


@pytest.mark.parametrize(
    "command",
    [
        "rclone sync source: destination: --dry-run",
        "rclone -n purge remote:archive",
        "restic -r s3:archive forget latest --dry-run",
        "restic rewrite --forget latest --dry-run",
        "borg prune --keep-daily 7 /archive --dry-run",
        "borg recreate /archive --dry-run",
        "borg --repo /archive prune --keep-daily 7 --dry-run",
        "velero backup delete --help",
        "rclone --log-level DEBUG purge remote:archive --dry-run",
        "restic --compression max forget latest --dry-run",
        "borg --remote-ratelimit 1000 prune --keep-daily 7 /archive --dry-run",
        "velero --future-global-option cluster backup delete release-1 --help",
        "rclone lsl remote:archive",
        "rclone --log-level DEBUG lsl remote:archive",
        "restic snapshots",
        "restic --compression max snapshots",
        "borg list /archive",
        "borg --remote-ratelimit 1000 list /archive",
        "velero backup describe release-1",
        "velero --future-global-option cluster backup describe release-1",
        "grep 'rclone sync|restic forget|borg prune|velero backup delete' docs",
    ],
)
def test_backup_preview_and_read_commands_remain_safe(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "no_match"
    assert (
        extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


def test_backup_interactive_mode_remains_reviewable(tmp_path: Path) -> None:
    payload = inspect_command("rclone purge remote:archive --interactive", cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["controlling_rule_id"] == "command.backup.rclone.mutation"


def test_backup_extensions_publish_official_references() -> None:
    for extension_id in (
        "command.backup.rclone",
        "command.backup.restic",
        "command.backup.borg",
        "command.backup.velero",
    ):
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)

        assert extension is not None
        assert extension.reference_urls
        assert all(url.startswith("https://") for url in extension.reference_urls)
