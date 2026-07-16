"""Structured backup command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import command_option_parsing
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.command_option_parsing import (
    flags_present_in_all_option_parses,
    matches_subcommands_conservatively,
)
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
        (
            "rclone -ab value purge remote:archive",
            "Rclone destructive command",
            "command.backup.rclone.mutation",
        ),
        (
            "rclone -ab --dry-run purge remote:archive",
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
        (
            "restic -qr repository forget latest --prune",
            "Restic destructive command",
            "command.backup.restic.mutation",
        ),
        (
            "restic -qrs3:archive forget latest --prune",
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
        (
            "borg -Pfoo-n prune --keep-daily 7 /archive",
            "Borg destructive command",
            "command.backup.borg.mutation",
        ),
        (
            "borg -afoo-n prune --keep-daily 7 /archive",
            "Borg destructive command",
            "command.backup.borg.mutation",
        ),
        (
            "borg -efoo-n recreate /archive",
            "Borg destructive command",
            "command.backup.borg.mutation",
        ),
        (
            "borg -vr /archive prune --keep-daily 7",
            "Borg destructive command",
            "command.backup.borg.mutation",
        ),
        (
            "borg -vr/archive prune --keep-daily 7",
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
            "velero -vnprod backup delete release-1",
            "Velero destructive command",
            "command.backup.velero.deletion",
        ),
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
        "rclone -ab value lsl remote:archive",
        "rclone -vn purge remote:archive",
        "restic snapshots",
        "restic --compression max snapshots",
        "restic -qr forget snapshots",
        "restic -qrforget snapshots",
        "borg list /archive",
        "borg --remote-ratelimit 1000 list /archive",
        "borg prune -Pfoo -n --keep-daily 7 /archive",
        "borg prune -afoo -n --keep-daily 7 /archive",
        "borg recreate -efoo -n /archive",
        "borg -vr prune list",
        "velero backup describe release-1",
        "velero --future-global-option cluster backup describe release-1",
        "velero -vnprod backup describe release-1",
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


def test_backup_option_parsing_handles_deep_option_sequences(tmp_path: Path) -> None:
    repeated_options = " ".join("--x=y" for _ in range(1200))
    destructive_command = f"rclone {repeated_options} purge remote:archive"
    safe_command = f"rclone {repeated_options} -n purge remote:archive"

    destructive_payload = inspect_command(destructive_command, cwd=tmp_path, home_dir=tmp_path)
    destructive_runtime = extract_sensitive_tool_action_request(
        "Shell",
        {"command": destructive_command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    safe_payload = inspect_command(safe_command, cwd=tmp_path, home_dir=tmp_path)
    safe_runtime = extract_sensitive_tool_action_request(
        "Shell",
        {"command": safe_command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert destructive_payload["status"] == "review"
    assert destructive_runtime is not None
    assert safe_payload["status"] == "no_match"
    assert safe_runtime is None


def test_backup_option_parse_limit_fails_secure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(command_option_parsing, "_MAX_OPTION_PARSE_STATES", 1)
    arguments = ("--future=value", "purge", "remote:archive")

    assert matches_subcommands_conservatively(
        arguments,
        ("purge",),
        options_with_values=frozenset(),
        known_flags=frozenset({"-n"}),
    )
    assert not flags_present_in_all_option_parses(
        arguments,
        frozenset({"-n"}),
        options_with_values=frozenset(),
        known_flags=frozenset({"-n"}),
    )


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
