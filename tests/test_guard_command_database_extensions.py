"""Structured database command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_database_matchers import LeadingSubcommandMatcher
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize(
    ("command", "action_class", "rule_id"),
    [
        ("dropdb production", "PostgreSQL destructive command", "command.database.postgresql.drop"),
        (
            "dropdb.exe -h db.example -U admin production",
            "PostgreSQL destructive command",
            "command.database.postgresql.drop",
        ),
        ("mysqladmin drop production", "MySQL destructive command", "command.database.mysql.drop"),
        ("mysqladmin status drop production", "MySQL destructive command", "command.database.mysql.drop"),
        ("mysqladmin dr production", "MySQL destructive command", "command.database.mysql.drop"),
        (
            "mysqladmin.cmd -P 3306 -u root drop production",
            "MySQL destructive command",
            "command.database.mysql.drop",
        ),
        (
            "mysqladmin --connect-timeout 5 status drop production",
            "MySQL destructive command",
            "command.database.mysql.drop",
        ),
        (
            "mongorestore --drop --archive=backup.archive",
            "MongoDB destructive command",
            "command.database.mongodb.restore-drop",
        ),
        ("redis-cli FLUSHALL", "Redis destructive command", "command.database.redis.delete"),
        ("redis-cli -n 3 DEL session:1", "Redis destructive command", "command.database.redis.delete"),
        ("redis-cli -a secret -n 3 FLUSHDB", "Redis destructive command", "command.database.redis.delete"),
        ("redis-cli -t 1 FLUSHALL", "Redis destructive command", "command.database.redis.delete"),
        ("redis-cli -X tag DEL key", "Redis destructive command", "command.database.redis.delete"),
        ("redis-cli --show-pushes no FLUSHDB", "Redis destructive command", "command.database.redis.delete"),
        ("redis-cli.exe --raw UNLINK queue:1", "Redis destructive command", "command.database.redis.delete"),
        (
            'sqlite3 app.db ".restore backup.db"',
            "SQLite destructive command",
            "command.database.sqlite.restore",
        ),
        ('sqlite3.cmd app.db ".rest backup.db"', "SQLite destructive command", "command.database.sqlite.restore"),
        ("supabase db reset --linked", "Supabase destructive command", "command.database.supabase.reset"),
        (
            "supabase --workdir ./backend db reset --linked",
            "Supabase destructive command",
            "command.database.supabase.reset",
        ),
        (
            "supabase --agent yes db reset --linked",
            "Supabase destructive command",
            "command.database.supabase.reset",
        ),
        (
            "npx supabase db reset --linked",
            "Supabase destructive command",
            "command.database.supabase.reset",
        ),
        (
            "pnpm supabase migration down --linked --last 1",
            "Supabase destructive command",
            "command.database.supabase.reset",
        ),
        (
            "yarn dlx supabase db reset --linked",
            "Supabase destructive command",
            "command.database.supabase.reset",
        ),
        (
            "supabase.exe migration down --linked --last 1",
            "Supabase destructive command",
            "command.database.supabase.reset",
        ),
    ],
)
def test_database_rules_feed_runtime_hooks(
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
        "dropdb --help production",
        "dropdb -V production",
        "mysqladmin --help drop production",
        "mysqladmin -? drop production",
        "mysqladmin password drop",
        "mysqladmin status",
        "mongorestore --drop --dryRun --archive=backup.archive",
        "mongorestore --drop --help",
        "mongorestore --archive=backup.archive",
        "redis-cli --help FLUSHALL",
        "redis-cli GET session:1",
        "redis-cli --eval readonly.lua FLUSHALL",
        "sqlite3 app.db '.help .restore'",
        "sqlite3 .help .restore",
        "sqlite3 app.db .restore backup.db",
        "supabase db reset --help",
        "supabase db dump --linked",
        "grep 'dropdb|mysqladmin drop|mongorestore --drop|redis-cli FLUSHALL|sqlite3 .restore' docs",
    ],
)
def test_database_observer_and_preview_commands_remain_safe(command: str, tmp_path: Path) -> None:
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


@pytest.mark.parametrize(
    "command",
    [
        "mongorestore --drop --dryRun=false --archive=backup.archive",
        "mongorestore --drop --dryRun --dryRun=false --archive=backup.archive",
    ],
)
def test_mongodb_false_or_overridden_dry_run_remains_live_execution(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert (
        extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is not None
    )


@pytest.mark.parametrize(
    "command",
    [
        "mongorestore --drop --dryRun=true --archive=backup.archive",
        "mongorestore --drop --dryRun=false --dryRun --archive=backup.archive",
    ],
)
def test_mongodb_truthy_or_effective_dry_run_remains_quiet(command: str, tmp_path: Path) -> None:
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


def test_database_extensions_publish_official_references() -> None:
    for extension_id in (
        "command.database.postgresql",
        "command.database.mysql",
        "command.database.mongodb",
        "command.database.redis",
        "command.database.sqlite",
        "command.database.supabase",
    ):
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)

        assert extension is not None
        assert extension.reference_urls
        assert all(url.startswith("https://") for url in extension.reference_urls)


def test_database_matcher_does_not_treat_attached_option_values_as_flags(tmp_path: Path) -> None:
    matcher = LeadingSubcommandMatcher(
        executables=frozenset({"db-admin"}),
        subcommands=("drop",),
        options_with_values=frozenset({"-u"}),
        required_flags_anywhere=frozenset({"-r"}),
    )
    command = parse_shell_command("db-admin -uroot drop production", cwd=tmp_path, home_dir=tmp_path)

    assert matcher.match(command) == ()
