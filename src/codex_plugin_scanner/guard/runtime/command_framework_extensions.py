"""Structured rules and metadata for web application framework command extensions."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import (
    AnyMatcher,
    CommandRuleSeverity,
    CommandSafetyRule,
    CommandSafeVariant,
    ExecutableMatcher,
)

_ARTISAN_GLOBAL_OPTIONS = frozenset({"--env"})
_ARTISAN_GLOBAL_FLAGS = frozenset(
    {
        "-h",
        "-n",
        "-q",
        "-v",
        "-vv",
        "-vvv",
        "--ansi",
        "--help",
        "--no-ansi",
        "--no-interaction",
        "--quiet",
        "--silent",
        "--verbose",
    }
)


def _artisan_matchers(*subcommands: str) -> tuple[ExecutableMatcher, ...]:
    return (
        executable_matcher(
            "artisan",
            *subcommands,
            global_options_with_values=_ARTISAN_GLOBAL_OPTIONS,
            global_flags=_ARTISAN_GLOBAL_FLAGS,
        ),
        executable_matcher(
            "php",
            "artisan",
            *subcommands,
            global_options_with_values=_ARTISAN_GLOBAL_OPTIONS,
            global_flags=_ARTISAN_GLOBAL_FLAGS,
        ),
    )


_LARAVEL_DB_WIPE = AnyMatcher(matchers=_artisan_matchers("db:wipe"))
_LARAVEL_MIGRATE_FRESH = AnyMatcher(matchers=_artisan_matchers("migrate:fresh"))
_LARAVEL_MIGRATE_RESET = AnyMatcher(
    matchers=(
        *_artisan_matchers("migrate:reset"),
        *_artisan_matchers("migrate:refresh"),
    )
)
_LARAVEL_MIGRATE_ROLLBACK = AnyMatcher(matchers=_artisan_matchers("migrate:rollback"))
_LARAVEL_QUEUE_PURGE = AnyMatcher(
    matchers=(
        *_artisan_matchers("queue:clear"),
        *_artisan_matchers("queue:flush"),
    )
)


def _framework_rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    matcher: AnyMatcher,
    action_class: str,
    safer_alternative: str,
    severity: CommandRuleSeverity,
    safe_variants: tuple[CommandSafeVariant, ...],
    example_command: str,
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        safe_variants=safe_variants,
        example_command=example_command,
    )


FRAMEWORK_COMMAND_RULES = (
    _framework_rule(
        rule_id="command.framework.laravel.database-wipe",
        title="Laravel database wipe",
        description="Identifies Artisan db:wipe operations that drop all database tables, views, and types.",
        matcher=_LARAVEL_DB_WIPE,
        action_class="Laravel database wipe command",
        severity="critical",
        example_command="php artisan db:wipe",
        safer_alternative=(
            "Inspect migrations with migrate:status and confirm a current backup before wiping the database."
        ),
        safe_variants=(
            safe_flag_variant(_LARAVEL_DB_WIPE, variant_id="help", title="Command help", flag="--help"),
            safe_flag_variant(_LARAVEL_DB_WIPE, variant_id="short-help", title="Command help", flag="-h"),
        ),
    ),
    _framework_rule(
        rule_id="command.framework.laravel.migrate-fresh",
        title="Laravel destructive rebuild",
        description="Identifies Artisan migrate:fresh operations that drop every table and re-run all migrations.",
        matcher=_LARAVEL_MIGRATE_FRESH,
        action_class="Laravel destructive rebuild command",
        severity="critical",
        example_command="php artisan migrate:fresh --seed",
        safer_alternative=(
            "Run migrate:status and review pending migrations before rebuilding the database from scratch."
        ),
        safe_variants=(
            safe_flag_variant(_LARAVEL_MIGRATE_FRESH, variant_id="help", title="Command help", flag="--help"),
            safe_flag_variant(_LARAVEL_MIGRATE_FRESH, variant_id="short-help", title="Command help", flag="-h"),
        ),
    ),
    _framework_rule(
        rule_id="command.framework.laravel.migrate-reset",
        title="Laravel migration reset",
        description="Identifies Artisan migrate:reset and migrate:refresh operations that roll back every migration.",
        matcher=_LARAVEL_MIGRATE_RESET,
        action_class="Laravel migration reset command",
        severity="critical",
        example_command="php artisan migrate:reset",
        safer_alternative="Review the rollback SQL with migrate:reset --pretend before resetting every migration.",
        safe_variants=(
            safe_flag_variant(_LARAVEL_MIGRATE_RESET, variant_id="help", title="Command help", flag="--help"),
            safe_flag_variant(_LARAVEL_MIGRATE_RESET, variant_id="short-help", title="Command help", flag="-h"),
            safe_flag_variant(
                _LARAVEL_MIGRATE_RESET,
                variant_id="dry-run",
                title="Migration dry run",
                flag="--pretend",
            ),
        ),
    ),
    _framework_rule(
        rule_id="command.framework.laravel.migrate-rollback",
        title="Laravel migration rollback",
        description="Identifies Artisan migrate:rollback operations that revert the last migration batch.",
        matcher=_LARAVEL_MIGRATE_ROLLBACK,
        action_class="Laravel migration rollback command",
        severity="high",
        example_command="php artisan migrate:rollback",
        safer_alternative="Inspect pending batches with migrate:status and dump the rollback SQL with --pretend first.",
        safe_variants=(
            safe_flag_variant(_LARAVEL_MIGRATE_ROLLBACK, variant_id="help", title="Command help", flag="--help"),
            safe_flag_variant(_LARAVEL_MIGRATE_ROLLBACK, variant_id="short-help", title="Command help", flag="-h"),
            safe_flag_variant(
                _LARAVEL_MIGRATE_ROLLBACK,
                variant_id="dry-run",
                title="Migration dry run",
                flag="--pretend",
            ),
        ),
    ),
    _framework_rule(
        rule_id="command.framework.laravel.queue-purge",
        title="Laravel queue purge",
        description="Identifies Artisan queue:clear and queue:flush operations that delete queued or failed jobs.",
        matcher=_LARAVEL_QUEUE_PURGE,
        action_class="Laravel queue purge command",
        severity="high",
        example_command="php artisan queue:clear redis --queue=emails",
        safer_alternative="Inspect queued and failed jobs before clearing or flushing queue state.",
        safe_variants=(
            safe_flag_variant(_LARAVEL_QUEUE_PURGE, variant_id="help", title="Command help", flag="--help"),
            safe_flag_variant(_LARAVEL_QUEUE_PURGE, variant_id="short-help", title="Command help", flag="-h"),
        ),
    ),
)


FRAMEWORK_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.framework.laravel",
        name="Laravel command protection",
        description="Reviews destructive Artisan database wipes, migration resets, and queue purges.",
        action_classes=(
            "Laravel database wipe command",
            "Laravel destructive rebuild command",
            "Laravel migration reset command",
            "Laravel migration rollback command",
            "Laravel queue purge command",
        ),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Inspect migration status and queue depth before destructive Artisan operations.",),
        reference_urls=(
            "https://laravel.com/docs/13.x/migrations",
            "https://laravel.com/docs/13.x/queues",
            "https://laravel.com/docs/13.x/artisan",
        ),
    ),
)
