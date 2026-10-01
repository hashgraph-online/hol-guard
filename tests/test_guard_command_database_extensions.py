"""Structured database command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_database_matchers import (
    ArgumentCommandMatcher,
    CommandSequenceMatcher,
    LeadingSubcommandMatcher,
    database_matcher_index_hints,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_rules import ExecutableMatcher
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


def test_database_matcher_rejects_combined_exit_flag_before_execution(tmp_path: Path) -> None:
    matcher = LeadingSubcommandMatcher(
        executables=frozenset({"db-admin"}),
        subcommands=("run",),
        forbidden_flags_before_delimiter=frozenset({"-h"}),
    )
    command = parse_shell_command("db-admin -vh run", cwd=tmp_path, home_dir=tmp_path)

    assert matcher.match(command) == ()


@pytest.mark.parametrize(
    ("executables", "command", "minimum_abbreviation_length", "minimum_position", "message"),
    (
        (frozenset(), ".restore", 5, 0, "requires executables and a command"),
        (frozenset({"sqlite3"}), " ", 1, 0, "requires executables and a command"),
        (frozenset({"sqlite3"}), ".restore", 0, 0, "invalid minimum abbreviation length"),
        (frozenset({"sqlite3"}), ".restore", 9, 0, "invalid minimum abbreviation length"),
        (frozenset({"sqlite3"}), ".restore", 5, -1, "minimum position cannot be negative"),
    ),
)
def test_argument_command_matcher_rejects_invalid_configuration(
    executables: frozenset[str],
    command: str,
    minimum_abbreviation_length: int,
    minimum_position: int,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        ArgumentCommandMatcher(
            executables=executables,
            command=command,
            minimum_abbreviation_length=minimum_abbreviation_length,
            minimum_position=minimum_position,
        )


def test_argument_command_matcher_requires_a_minimum_abbreviation_and_payload(tmp_path: Path) -> None:
    matcher = ArgumentCommandMatcher(
        executables=frozenset({"sqlite3"}),
        command=".restore",
        minimum_abbreviation_length=5,
        minimum_position=1,
    )

    matched = parse_shell_command("sqlite3 app.db '.rest backup.db'", cwd=tmp_path, home_dir=tmp_path)
    assert len(matcher.match(matched)) == 1

    for text in (
        "sqlite3 app.db '.res backup.db'",
        "sqlite3 app.db '.repair backup.db'",
        "sqlite3 app.db .restore",
        "psql app.db '.restore backup.db'",
    ):
        command = parse_shell_command(text, cwd=tmp_path, home_dir=tmp_path)
        assert matcher.match(command) == ()


@pytest.mark.parametrize(
    ("executables", "command_arities", "target_commands", "message"),
    (
        (frozenset(), (("drop", 1),), frozenset({"drop"}), "requires executables, commands, and targets"),
        (frozenset({"mysqladmin"}), (), frozenset({"drop"}), "requires executables, commands, and targets"),
        (frozenset({"mysqladmin"}), (("drop", 1),), frozenset(), "requires executables, commands, and targets"),
        (
            frozenset({"mysqladmin"}),
            (("drop", 1), ("drop", 0)),
            frozenset({"drop"}),
            "unique commands with non-negative arities",
        ),
        (
            frozenset({"mysqladmin"}),
            (("drop", -1),),
            frozenset({"drop"}),
            "unique commands with non-negative arities",
        ),
        (
            frozenset({"mysqladmin"}),
            (("drop", 1),),
            frozenset({"truncate"}),
            "targets must exist in the command grammar",
        ),
    ),
)
def test_command_sequence_matcher_rejects_invalid_grammar(
    executables: frozenset[str],
    command_arities: tuple[tuple[str, int], ...],
    target_commands: frozenset[str],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        CommandSequenceMatcher(
            executables=executables,
            command_arities=command_arities,
            target_commands=target_commands,
        )


def test_command_sequence_matcher_skips_declared_arguments_and_rejects_ambiguous_or_forbidden_commands(
    tmp_path: Path,
) -> None:
    matcher = CommandSequenceMatcher(
        executables=frozenset({"mysqladmin"}),
        command_arities=(("create", 1), ("drop", 1), ("dry-run", 0), ("status", 0)),
        target_commands=frozenset({"drop"}),
        options_with_values=frozenset({"--host"}),
        forbidden_flags=frozenset({"--help"}),
    )

    matched = parse_shell_command(
        "mysqladmin --host db.example create scratch status drop production",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert len(matcher.match(matched)) == 1

    for text in (
        "mysqladmin d production",
        "mysqladmin status",
        "mysqladmin --help drop production",
    ):
        command = parse_shell_command(text, cwd=tmp_path, home_dir=tmp_path)
        assert matcher.match(command) == ()


def test_database_matcher_index_hints_cover_each_supported_matcher() -> None:
    argument_matcher = ArgumentCommandMatcher(
        executables=frozenset({"sqlite3"}),
        command=".restore",
        minimum_abbreviation_length=5,
    )
    sequence_matcher = CommandSequenceMatcher(
        executables=frozenset({"mysqladmin"}),
        command_arities=(("drop", 1), ("status", 0)),
        target_commands=frozenset({"drop"}),
    )
    leading_matcher = LeadingSubcommandMatcher(
        executables=frozenset({"redis-cli"}),
        subcommands=("flushall", "flushdb"),
    )

    assert database_matcher_index_hints(argument_matcher) == (frozenset({"sqlite3"}), frozenset({".restore"}))
    assert database_matcher_index_hints(sequence_matcher) == (frozenset({"mysqladmin"}), frozenset({"drop"}))
    assert database_matcher_index_hints(leading_matcher) == (
        frozenset({"redis-cli"}),
        frozenset({"flushall", "flushdb"}),
    )
    assert database_matcher_index_hints(ExecutableMatcher(executables=frozenset({"echo"}))) is None
