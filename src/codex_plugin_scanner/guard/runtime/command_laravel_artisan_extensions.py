"""Structured rules and metadata for Laravel Artisan command safety."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

# Current Laravel framework source defines `migrate:fresh` as dropping all
# tables before re-running migrations, and `db:wipe` as dropping all tables
# (plus views/types when requested). Keep this first extension deliberately
# narrow around those explicit destructive database-reset operations.
#
# Supported launchers cover the ordinary Laravel application entry point,
# direct executable Artisan scripts, and Laravel Sail's Artisan forwarding.
_PHP_LEADING_OPTIONS_WITH_VALUES = frozenset({"-c", "-d"})
_PHP_GLOBAL_FLAGS = frozenset({"-n"})


def _artisan_command(command: str) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            executable_matcher(
                "php",
                "artisan",
                command,
                allow_leading_options=True,
                leading_options_with_values=_PHP_LEADING_OPTIONS_WITH_VALUES,
                global_flags=_PHP_GLOBAL_FLAGS,
            ),
            executable_matcher("artisan", command),
            executable_matcher("sail", "artisan", command),
        )
    )


_LARAVEL_MIGRATE_FRESH = _artisan_command("migrate:fresh")
_LARAVEL_DB_WIPE = _artisan_command("db:wipe")


def _help_variants(matcher: AnyMatcher, prefix: str) -> tuple:
    return (
        safe_flag_variant(
            matcher,
            variant_id=f"{prefix}-help",
            title="Laravel Artisan command help",
            flag="--help",
        ),
        safe_flag_variant(
            matcher,
            variant_id=f"{prefix}-short-help",
            title="Laravel Artisan short command help",
            flag="-h",
        ),
    )


LARAVEL_ARTISAN_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.laravel-artisan.migrate-fresh",
        title="Laravel fresh migration database reset",
        description=(
            "Identifies Laravel Artisan `migrate:fresh`, which drops every table on the selected database "
            "before running migrations again."
        ),
        severity="critical",
        risk_classes=("destructive_shell",),
        action_classes=("Laravel fresh migration database reset command",),
        safer_alternatives=(
            "Run `php artisan migrate:status` first and confirm the selected database connection.",
            "Use ordinary `php artisan migrate` when the goal is to apply pending migrations without dropping existing tables.",
        ),
        matcher=_LARAVEL_MIGRATE_FRESH,
        default_mode="review",
        safe_variants=_help_variants(_LARAVEL_MIGRATE_FRESH, "migrate-fresh"),
    ),
    CommandSafetyRule(
        rule_id="command.laravel-artisan.db-wipe",
        title="Laravel database wipe",
        description=(
            "Identifies Laravel Artisan `db:wipe`, which drops all tables and may also drop views or database types."
        ),
        severity="critical",
        risk_classes=("destructive_shell",),
        action_classes=("Laravel database wipe command",),
        safer_alternatives=(
            "Confirm the selected database connection before wiping it.",
            "Use schema inspection or migration status commands when only database state needs to be reviewed.",
        ),
        matcher=_LARAVEL_DB_WIPE,
        default_mode="review",
        safe_variants=_help_variants(_LARAVEL_DB_WIPE, "db-wipe"),
    ),
)

LARAVEL_ARTISAN_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.laravel-artisan",
        name="Laravel Artisan command protection",
        description=(
            "Reviews Laravel Artisan database-reset commands that can drop application tables, views, or types."
        ),
        action_classes=(
            "Laravel fresh migration database reset command",
            "Laravel database wipe command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Inspect migration status and the active database connection before destructive database resets.",
            "Prefer ordinary migrations when existing application data should be preserved.",
        ),
        reference_urls=(
            "https://github.com/laravel/framework/blob/13.x/src/Illuminate/Database/Console/Migrations/FreshCommand.php",
            "https://github.com/laravel/framework/blob/13.x/src/Illuminate/Database/Console/WipeCommand.php",
            "https://laravel.com/ai/boost",
        ),
        ecosystem_ids=("laravel",),
        executables=("php", "artisan", "sail"),
        project_markers=("artisan", "composer.json"),
        example_command="php artisan migrate:fresh",
    ),
)
