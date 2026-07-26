"""Structured database command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_database_matchers import LeadingSubcommandMatcher
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.command_extension_contracts import (
    assert_review_required_cases,
    assert_reviewed_command_cases,
    assert_safe_command_cases,
)

DATABASE_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
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
)


def test_database_rules_feed_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(DATABASE_REVIEW_CASES, tmp_path)


DATABASE_SAFE_COMMANDS: tuple[str, ...] = (
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
)


def test_database_observer_and_preview_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(DATABASE_SAFE_COMMANDS, tmp_path)


def test_mongodb_false_or_overridden_dry_run_remains_live_execution(tmp_path: Path) -> None:
    assert_review_required_cases(
        (
            "mongorestore --drop --dryRun=false --archive=backup.archive",
            "mongorestore --drop --dryRun --dryRun=false --archive=backup.archive",
        ),
        tmp_path,
    )


def test_mongodb_truthy_or_effective_dry_run_remains_quiet(tmp_path: Path) -> None:
    assert_safe_command_cases(
        (
            "mongorestore --drop --dryRun=true --archive=backup.archive",
            "mongorestore --drop --dryRun=false --dryRun --archive=backup.archive",
        ),
        tmp_path,
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
