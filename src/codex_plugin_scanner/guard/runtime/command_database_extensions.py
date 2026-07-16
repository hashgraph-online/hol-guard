"""Structured rules and metadata for database administration commands."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, executable_names, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import (
    AnyMatcher,
    ArgumentPositionMatcher,
    CommandMatcher,
    CommandSafetyRule,
    CommandSafeVariant,
    LeadingOperandCountMatcher,
    LeadingSubcommandMatcher,
)

_POSTGRES_OPTIONS_WITH_VALUES = frozenset({"-h", "-p", "-U", "--host", "--maintenance-db", "--port", "--username"})
_MYSQL_GLOBAL_OPTIONS = frozenset(
    {
        "-h",
        "--host",
        "-P",
        "--port",
        "-S",
        "--socket",
        "-u",
        "--user",
        "--defaults-file",
        "--defaults-extra-file",
        "--login-path",
    }
)
_REDIS_GLOBAL_OPTIONS = frozenset(
    {
        "-a",
        "-d",
        "-D",
        "-h",
        "-i",
        "-n",
        "-p",
        "-r",
        "-s",
        "-u",
        "--cacert",
        "--cacertdir",
        "--cert",
        "--eval",
        "--key",
        "--pass",
        "--sni",
        "--user",
    }
)
_SUPABASE_GLOBAL_OPTIONS = frozenset({"--workdir", "--dns-resolver"})
_POSTGRES_DROP = LeadingOperandCountMatcher(
    executables=executable_names("dropdb"),
    minimum_operands=1,
    options_with_values=_POSTGRES_OPTIONS_WITH_VALUES,
    forbidden_flags=frozenset({"--help", "--version"}),
)
_MYSQL_DROP = AnyMatcher(
    matchers=(
        LeadingSubcommandMatcher(
            executables=executable_names("mysqladmin"),
            subcommands=("drop",),
            options_with_values=_MYSQL_GLOBAL_OPTIONS,
            forbidden_flags=frozenset({"--help", "--version"}),
        ),
    )
)
_MONGO_RESTORE_DROP = AnyMatcher(matchers=(executable_matcher("mongorestore", required_flags=frozenset({"--drop"})),))
_REDIS_MUTATION = AnyMatcher(
    matchers=tuple(
        LeadingSubcommandMatcher(
            executables=executable_names("redis-cli"),
            subcommands=(command,),
            options_with_values=_REDIS_GLOBAL_OPTIONS,
            forbidden_flags=frozenset({"--help", "--version"}),
        )
        for command in ("flushall", "flushdb", "del", "unlink")
    )
)
_SQLITE_RESTORE = ArgumentPositionMatcher(
    executables=executable_names("sqlite3"),
    required_argument=".restore",
    positions=frozenset({0, 1}),
    forbidden_arguments=frozenset({".help"}),
)
_SUPABASE_RESET = AnyMatcher(
    matchers=(
        LeadingSubcommandMatcher(
            executables=executable_names("supabase"),
            subcommands=("db", "reset"),
            options_with_values=_SUPABASE_GLOBAL_OPTIONS,
        ),
    )
)
_SUPABASE_MUTATION = AnyMatcher(
    matchers=(
        *_SUPABASE_RESET.matchers,
        LeadingSubcommandMatcher(
            executables=executable_names("supabase"),
            subcommands=("migration", "down"),
            options_with_values=_SUPABASE_GLOBAL_OPTIONS,
        ),
    )
)
_SUPABASE_RESET_DRY_RUN = LeadingSubcommandMatcher(
    executables=executable_names("supabase"),
    subcommands=("db", "reset"),
    options_with_values=_SUPABASE_GLOBAL_OPTIONS,
    required_flags_anywhere=frozenset({"--dry-run"}),
)


def _database_rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    matcher: CommandMatcher,
    action_class: str,
    safer_alternative: str,
    risk_classes: tuple[str, ...] = ("destructive_shell", "network_egress"),
    safe_variants: tuple[CommandSafeVariant, ...] = (),
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity="critical",
        risk_classes=risk_classes,
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        safe_variants=safe_variants,
    )


DATABASE_COMMAND_RULES = (
    _database_rule(
        rule_id="command.database.postgresql.drop",
        title="PostgreSQL database removal",
        description="Identifies dropdb invocations that remove a PostgreSQL database.",
        matcher=_POSTGRES_DROP,
        action_class="PostgreSQL destructive command",
        safer_alternative="List the target database, active connections, and a current backup before removal.",
    ),
    _database_rule(
        rule_id="command.database.mysql.drop",
        title="MySQL database removal",
        description="Identifies mysqladmin drop operations that remove a database and its tables.",
        matcher=_MYSQL_DROP,
        action_class="MySQL destructive command",
        safer_alternative="List the target schema and verify a current backup before removal.",
    ),
    _database_rule(
        rule_id="command.database.mongodb.restore-drop",
        title="MongoDB destructive restore",
        description="Identifies mongorestore --drop operations that replace target collections.",
        matcher=_MONGO_RESTORE_DROP,
        action_class="MongoDB destructive command",
        safer_alternative="Run mongorestore with --dryRun and inspect the selected database collections first.",
        safe_variants=(
            safe_flag_variant(
                _MONGO_RESTORE_DROP,
                variant_id="dry-run",
                title="MongoDB restore dry run",
                flag="--dryRun",
            ),
        ),
    ),
    _database_rule(
        rule_id="command.database.redis.delete",
        title="Redis key deletion",
        description="Identifies Redis commands that delete keys from one or every database.",
        matcher=_REDIS_MUTATION,
        action_class="Redis destructive command",
        safer_alternative="Inspect the selected database and exact keys before deleting them.",
    ),
    _database_rule(
        rule_id="command.database.sqlite.restore",
        title="SQLite database restore",
        description="Identifies SQLite .restore operations that replace database content from a backup.",
        matcher=_SQLITE_RESTORE,
        action_class="SQLite destructive command",
        safer_alternative="Restore into a new database file and compare its contents before replacement.",
        risk_classes=("destructive_shell",),
    ),
    _database_rule(
        rule_id="command.database.supabase.reset",
        title="Supabase database reset",
        description="Identifies Supabase reset and migration-down operations that discard database state.",
        matcher=_SUPABASE_MUTATION,
        action_class="Supabase destructive command",
        safer_alternative="Run the documented dry run and confirm whether the target is local, linked, or explicit.",
        safe_variants=(
            CommandSafeVariant(
                variant_id="dry-run",
                title="Supabase database dry run",
                matcher=_SUPABASE_RESET_DRY_RUN,
            ),
        ),
    ),
)


DATABASE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.database.postgresql",
        name="PostgreSQL command protection",
        description="Reviews explicit PostgreSQL database removal commands.",
        action_classes=("PostgreSQL destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Verify active connections and a current backup before running dropdb.",),
        reference_urls=("https://www.postgresql.org/docs/current/app-dropdb.html",),
    ),
    CommandExtensionSpec(
        extension_id="command.database.mysql",
        name="MySQL command protection",
        description="Reviews mysqladmin database removal operations.",
        action_classes=("MySQL destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Inspect the target schema and backup state before removal.",),
        reference_urls=("https://dev.mysql.com/doc/refman/8.4/en/mysqladmin.html",),
    ),
    CommandExtensionSpec(
        extension_id="command.database.mongodb",
        name="MongoDB command protection",
        description="Reviews restore operations that drop and replace collections.",
        action_classes=("MongoDB destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Use mongorestore --dryRun and inspect selected database collections first.",),
        reference_urls=("https://www.mongodb.com/docs/database-tools/mongorestore/",),
    ),
    CommandExtensionSpec(
        extension_id="command.database.redis",
        name="Redis command protection",
        description="Reviews Redis key deletion and database flush commands.",
        action_classes=("Redis destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Inspect the selected database and exact key set before deletion.",),
        reference_urls=("https://redis.io/docs/latest/commands/",),
    ),
    CommandExtensionSpec(
        extension_id="command.database.sqlite",
        name="SQLite command protection",
        description="Reviews SQLite restore operations that replace database content.",
        action_classes=("SQLite destructive command",),
        risk_classes=("destructive_shell",),
        safer_alternatives=("Restore into a new database file and compare it before replacement.",),
        reference_urls=("https://www.sqlite.org/cli.html",),
    ),
    CommandExtensionSpec(
        extension_id="command.database.supabase",
        name="Supabase command protection",
        description="Reviews database reset and migration rollback commands.",
        action_classes=("Supabase destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Use --dry-run and verify the selected database target first.",),
        reference_urls=("https://supabase.com/docs/reference/cli/supabase-db-reset",),
    ),
)
