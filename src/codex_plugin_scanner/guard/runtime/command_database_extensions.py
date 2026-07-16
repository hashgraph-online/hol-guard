"""Structured rules and metadata for database administration commands."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, executable_names, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import (
    AnyMatcher,
    ArgumentCommandMatcher,
    CommandMatcher,
    CommandSafetyRule,
    CommandSafeVariant,
    CommandSequenceMatcher,
    ExecutableMatcher,
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
        "--bind-address",
        "--character-sets-dir",
        "--compression-algorithms",
        "--connect-timeout",
        "--count",
        "--default-auth",
        "--login-path",
        "--max-allowed-packet",
        "--plugin-dir",
        "--protocol",
        "--server-public-key-path",
        "--shared-memory-base-name",
        "--shutdown-timeout",
        "--sleep",
        "--ssl-ca",
        "--ssl-capath",
        "--ssl-cert",
        "--ssl-cipher",
        "--ssl-crl",
        "--ssl-crlpath",
        "--ssl-key",
        "--tls-ciphersuites",
        "--tls-sni-servername",
        "--tls-version",
        "--zstd-compression-level",
        "-i",
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
        "-t",
        "-u",
        "-X",
        "--cacert",
        "--cacertdir",
        "--cert",
        "--eval",
        "--key",
        "--pass",
        "--sni",
        "--show-pushes",
        "--user",
    }
)
_SUPABASE_GLOBAL_OPTIONS = frozenset(
    {"--agent", "--dns-resolver", "--network-id", "--output", "--profile", "--workdir", "-o"}
)
_SUPABASE_GLOBAL_FLAGS = frozenset({"--create-ticket", "--debug", "--experimental", "--yes"})
_SUPABASE_FORBIDDEN_FLAGS = frozenset({"--help", "--version", "-h", "-v"})
_RUNNER_OPTIONS_WITH_VALUES = frozenset(
    {"--cache", "--call", "--dir", "--filter", "--package", "--reporter", "--workspace", "-C", "-F", "-c", "-p", "-w"}
)
_RUNNER_FLAGS = frozenset(
    {"--aggregate-output", "--silent", "--stream", "--use-stderr", "--workspace-root", "--yes", "-y"}
)
_POSTGRES_DROP = LeadingOperandCountMatcher(
    executables=executable_names("dropdb"),
    minimum_operands=1,
    options_with_values=_POSTGRES_OPTIONS_WITH_VALUES,
    forbidden_flags=frozenset({"--help", "--version", "-?", "-V"}),
)
_MYSQL_DROP = CommandSequenceMatcher(
    executables=executable_names("mysqladmin"),
    command_arities=(
        ("create", 1),
        ("debug", 0),
        ("drop", 1),
        ("extended-status", 0),
        ("flush-hosts", 0),
        ("flush-logs", 0),
        ("flush-privileges", 0),
        ("flush-status", 0),
        ("kill", 1),
        ("password", 1),
        ("ping", 0),
        ("processlist", 0),
        ("reload", 0),
        ("refresh", 0),
        ("shutdown", 0),
        ("start-replica", 0),
        ("start-slave", 0),
        ("status", 0),
        ("stop-replica", 0),
        ("stop-slave", 0),
        ("variables", 0),
        ("version", 0),
    ),
    target_commands=frozenset({"drop"}),
    options_with_values=_MYSQL_GLOBAL_OPTIONS,
    forbidden_flags=frozenset({"--help", "--version", "-?", "-V"}),
)
_MONGO_RESTORE_DROP = AnyMatcher(
    matchers=(
        executable_matcher(
            "mongorestore",
            required_flags=frozenset({"--drop"}),
            forbidden_flags=frozenset({"--help", "--version"}),
        ),
    )
)
_REDIS_MUTATION = AnyMatcher(
    matchers=tuple(
        LeadingSubcommandMatcher(
            executables=executable_names("redis-cli"),
            subcommands=(command,),
            options_with_values=_REDIS_GLOBAL_OPTIONS,
            forbidden_flags=frozenset({"--eval", "--help", "--version", "-?"}),
        )
        for command in ("flushall", "flushdb", "del", "unlink")
    )
)
_SQLITE_RESTORE = ArgumentCommandMatcher(
    executables=executable_names("sqlite3"),
    command=".restore",
    minimum_abbreviation_length=len(".rest"),
    minimum_position=1,
)


def _supabase_matchers(*subcommands: str) -> tuple[ExecutableMatcher, ...]:
    interspersed_options = _SUPABASE_GLOBAL_OPTIONS | _RUNNER_OPTIONS_WITH_VALUES
    interspersed_flags = _SUPABASE_GLOBAL_FLAGS | _RUNNER_FLAGS
    return (
        ExecutableMatcher(
            executables=executable_names("supabase"),
            subcommands=subcommands,
            forbidden_flags=_SUPABASE_FORBIDDEN_FLAGS,
            interspersed_options_with_values=_SUPABASE_GLOBAL_OPTIONS,
            interspersed_flags=_SUPABASE_GLOBAL_FLAGS,
        ),
        ExecutableMatcher(
            executables=executable_names("npx") | executable_names("bunx"),
            subcommands=("supabase", *subcommands),
            forbidden_flags=_SUPABASE_FORBIDDEN_FLAGS,
            interspersed_options_with_values=interspersed_options,
            interspersed_flags=interspersed_flags,
        ),
        ExecutableMatcher(
            executables=executable_names("pnpm") | executable_names("yarn"),
            subcommands=("supabase", *subcommands),
            forbidden_flags=_SUPABASE_FORBIDDEN_FLAGS,
            interspersed_options_with_values=interspersed_options,
            interspersed_flags=interspersed_flags,
        ),
        ExecutableMatcher(
            executables=executable_names("npm") | executable_names("pnpm"),
            subcommands=("exec", "supabase", *subcommands),
            forbidden_flags=_SUPABASE_FORBIDDEN_FLAGS,
            interspersed_options_with_values=interspersed_options,
            interspersed_flags=interspersed_flags,
        ),
        ExecutableMatcher(
            executables=executable_names("pnpm"),
            subcommands=("dlx", "supabase", *subcommands),
            forbidden_flags=_SUPABASE_FORBIDDEN_FLAGS,
            interspersed_options_with_values=interspersed_options,
            interspersed_flags=interspersed_flags,
        ),
    )


_SUPABASE_RESET = AnyMatcher(matchers=_supabase_matchers("db", "reset"))
_SUPABASE_MUTATION = AnyMatcher(
    matchers=(
        *_SUPABASE_RESET.matchers,
        *_supabase_matchers("migration", "down"),
    )
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
        safer_alternative="Confirm the target and create a database dump before resetting or rolling back migrations.",
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
