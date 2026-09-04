"""Structured rules and metadata for web application framework command extensions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

from .command_extension_matchers import executable_matcher, with_required_flag
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import CommandMatcher, MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import (
    AnyMatcher,
    CommandRuleSeverity,
    CommandSafetyRule,
    CommandSafeVariant,
    ExecutableMatcher,
)
from .command_structured_matchers import leading_flags_and_operands

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
_PHP_OPTIONS_WITH_VALUES = frozenset({"-c", "-d", "-z", "--define", "--php-ini"})
_PHP_LAUNCHER_BASENAMES = frozenset({"php", "php.cmd", "php.exe"})


@final
@dataclass(frozen=True, slots=True)
class PhpArtisanScriptMatcher:
    """Match php-launched artisan scripts across interpreter options and script paths."""

    subcommands: tuple[str, ...]
    required_flags: frozenset[str] = frozenset()

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            executable = segment.executable
            if executable is None:
                continue
            if executable.replace("\\", "/").rsplit("/", 1)[-1].lower() not in _PHP_LAUNCHER_BASENAMES:
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            _php_flags, operands = leading_flags_and_operands(
                lowered_arguments,
                options_with_values=_PHP_OPTIONS_WITH_VALUES,
            )
            if not operands or operands[0].replace("\\", "/").rsplit("/", 1)[-1] != "artisan":
                continue
            artisan_arguments = operands[1:]
            if not self.required_flags <= frozenset(artisan_arguments):
                continue
            _artisan_flags, subcommand_operands = leading_flags_and_operands(
                artisan_arguments,
                options_with_values=_ARTISAN_GLOBAL_OPTIONS,
            )
            if subcommand_operands[: len(self.subcommands)] != self.subcommands:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=executable,
                    detail="Matched php-launched artisan script and structured subcommand constraints.",
                )
            )
        return tuple(evidence)


def framework_matcher_index_hints(matcher: CommandMatcher) -> tuple[frozenset[str], frozenset[str]] | None:
    """Return conservative registry hints for the php-launched artisan matcher."""

    if not isinstance(matcher, PhpArtisanScriptMatcher):
        return None
    return _PHP_LAUNCHER_BASENAMES, frozenset(matcher.subcommands)


def _artisan_matchers(*subcommands: str) -> tuple[ExecutableMatcher, ...]:
    return (
        executable_matcher(
            "artisan",
            *subcommands,
            global_options_with_values=_ARTISAN_GLOBAL_OPTIONS,
            global_flags=_ARTISAN_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "php",
            "artisan",
            *subcommands,
            global_options_with_values=_ARTISAN_GLOBAL_OPTIONS,
            global_flags=_ARTISAN_GLOBAL_FLAGS,
            allow_leading_options=True,
            leading_options_with_values=_PHP_OPTIONS_WITH_VALUES,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "php",
            "./artisan",
            *subcommands,
            global_options_with_values=_ARTISAN_GLOBAL_OPTIONS,
            global_flags=_ARTISAN_GLOBAL_FLAGS,
            allow_leading_options=True,
            leading_options_with_values=_PHP_OPTIONS_WITH_VALUES,
            fail_secure_unknown_options=True,
        ),
    )


def _artisan_safe_variant(
    executable_matcher_bundle: AnyMatcher,
    *subcommands: str,
    variant_id: str,
    title: str,
    flag: str,
) -> CommandSafeVariant:
    return CommandSafeVariant(
        variant_id=variant_id,
        title=title,
        matcher=AnyMatcher(
            matchers=(
                *with_required_flag(executable_matcher_bundle, flag).matchers,
                *(
                    PhpArtisanScriptMatcher(subcommands=(subcommand,), required_flags=frozenset({flag}))
                    for subcommand in subcommands
                ),
            )
        ),
    )


_LARAVEL_DB_WIPE_EXEC = AnyMatcher(matchers=_artisan_matchers("db:wipe"))
_LARAVEL_DB_WIPE = AnyMatcher(
    matchers=(
        *_LARAVEL_DB_WIPE_EXEC.matchers,
        PhpArtisanScriptMatcher(subcommands=("db:wipe",)),
    )
)
_LARAVEL_MIGRATE_FRESH_EXEC = AnyMatcher(matchers=_artisan_matchers("migrate:fresh"))
_LARAVEL_MIGRATE_FRESH = AnyMatcher(
    matchers=(
        *_LARAVEL_MIGRATE_FRESH_EXEC.matchers,
        PhpArtisanScriptMatcher(subcommands=("migrate:fresh",)),
    )
)
_LARAVEL_MIGRATE_RESET_EXEC = AnyMatcher(
    matchers=(
        *_artisan_matchers("migrate:reset"),
        *_artisan_matchers("migrate:refresh"),
    )
)
_LARAVEL_MIGRATE_RESET = AnyMatcher(
    matchers=(
        *_LARAVEL_MIGRATE_RESET_EXEC.matchers,
        PhpArtisanScriptMatcher(subcommands=("migrate:reset",)),
        PhpArtisanScriptMatcher(subcommands=("migrate:refresh",)),
    )
)
_LARAVEL_MIGRATE_ROLLBACK_EXEC = AnyMatcher(matchers=_artisan_matchers("migrate:rollback"))
_LARAVEL_MIGRATE_ROLLBACK = AnyMatcher(
    matchers=(
        *_LARAVEL_MIGRATE_ROLLBACK_EXEC.matchers,
        PhpArtisanScriptMatcher(subcommands=("migrate:rollback",)),
    )
)
_LARAVEL_QUEUE_PURGE_EXEC = AnyMatcher(
    matchers=(
        *_artisan_matchers("queue:clear"),
        *_artisan_matchers("queue:flush"),
    )
)
_LARAVEL_QUEUE_PURGE = AnyMatcher(
    matchers=(
        *_LARAVEL_QUEUE_PURGE_EXEC.matchers,
        PhpArtisanScriptMatcher(subcommands=("queue:clear",)),
        PhpArtisanScriptMatcher(subcommands=("queue:flush",)),
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
            _artisan_safe_variant(
                _LARAVEL_DB_WIPE_EXEC,
                "db:wipe",
                variant_id="help",
                title="Command help",
                flag="--help",
            ),
            _artisan_safe_variant(
                _LARAVEL_DB_WIPE_EXEC,
                "db:wipe",
                variant_id="short-help",
                title="Command help",
                flag="-h",
            ),
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
            _artisan_safe_variant(
                _LARAVEL_MIGRATE_FRESH_EXEC,
                "migrate:fresh",
                variant_id="help",
                title="Command help",
                flag="--help",
            ),
            _artisan_safe_variant(
                _LARAVEL_MIGRATE_FRESH_EXEC,
                "migrate:fresh",
                variant_id="short-help",
                title="Command help",
                flag="-h",
            ),
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
            _artisan_safe_variant(
                _LARAVEL_MIGRATE_RESET_EXEC,
                "migrate:reset",
                "migrate:refresh",
                variant_id="help",
                title="Command help",
                flag="--help",
            ),
            _artisan_safe_variant(
                _LARAVEL_MIGRATE_RESET_EXEC,
                "migrate:reset",
                "migrate:refresh",
                variant_id="short-help",
                title="Command help",
                flag="-h",
            ),
            _artisan_safe_variant(
                _LARAVEL_MIGRATE_RESET_EXEC,
                "migrate:reset",
                "migrate:refresh",
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
            _artisan_safe_variant(
                _LARAVEL_MIGRATE_ROLLBACK_EXEC,
                "migrate:rollback",
                variant_id="help",
                title="Command help",
                flag="--help",
            ),
            _artisan_safe_variant(
                _LARAVEL_MIGRATE_ROLLBACK_EXEC,
                "migrate:rollback",
                variant_id="short-help",
                title="Command help",
                flag="-h",
            ),
            _artisan_safe_variant(
                _LARAVEL_MIGRATE_ROLLBACK_EXEC,
                "migrate:rollback",
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
            _artisan_safe_variant(
                _LARAVEL_QUEUE_PURGE_EXEC,
                "queue:clear",
                "queue:flush",
                variant_id="help",
                title="Command help",
                flag="--help",
            ),
            _artisan_safe_variant(
                _LARAVEL_QUEUE_PURGE_EXEC,
                "queue:clear",
                "queue:flush",
                variant_id="short-help",
                title="Command help",
                flag="-h",
            ),
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
