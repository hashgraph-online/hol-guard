"""Structured rules and metadata for Laravel Artisan command safety."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand, CommandSegment
from .command_rules import CommandSafeVariant, CommandSafetyRule, _segment_matches_executable

# Current Laravel framework source defines `migrate:fresh` as dropping all
# tables before re-running migrations, and `db:wipe` as dropping all tables
# (plus views/types when requested). Keep this first extension deliberately
# narrow around those explicit destructive database-reset operations.
#
# Laravel adds --env to Symfony Console's global option surface. The matcher
# accepts those global options before the command and supports the ordinary PHP,
# direct Artisan, and Laravel Sail launch paths without retokenizing shell text.
_ARTISAN_EXECUTABLES = frozenset({"artisan", "artisan.cmd", "artisan.exe"})
_PHP_EXECUTABLES = frozenset({"php", "php.exe"})
_SAIL_EXECUTABLES = frozenset({"sail", "sail.cmd", "sail.exe"})
_ARTISAN_GLOBAL_FLAGS = frozenset(
    {
        "--ansi",
        "--no-ansi",
        "--no-interaction",
        "--quiet",
        "--verbose",
        "-n",
        "-q",
        "-v",
        "-vv",
        "-vvv",
    }
)
_ARTISAN_GLOBAL_OPTIONS_WITH_VALUES = frozenset({"--env"})
_HELP_FLAGS = frozenset({"--help", "-h"})
_PHP_FLAG_OPTIONS = frozenset({"-n", "-q"})
_PHP_VALUE_OPTIONS = frozenset({"-c", "-d"})


def _basename(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _php_artisan_arguments(arguments: tuple[str, ...]) -> tuple[str, ...] | None:
    """Return Artisan arguments for supported PHP file-execution forms."""

    index = 0
    while index < len(arguments):
        token = arguments[index].lower()
        if token in _PHP_FLAG_OPTIONS:
            index += 1
            continue
        if token in _PHP_VALUE_OPTIONS:
            if index + 1 >= len(arguments):
                return None
            index += 2
            continue
        if any(token.startswith(option) and len(token) > len(option) for option in _PHP_VALUE_OPTIONS):
            index += 1
            continue
        if token == "-f":
            if index + 1 >= len(arguments) or _basename(arguments[index + 1]) != "artisan":
                return None
            return arguments[index + 2 :]
        if token.startswith("-f") and len(token) > 2:
            if _basename(token[2:]) != "artisan":
                return None
            return arguments[index + 1 :]
        if token.startswith("-"):
            # Other PHP modes such as -r/-B/-R/-F do not execute the following
            # token as the application script, so do not infer an Artisan run.
            return None
        if _basename(arguments[index]) != "artisan":
            return None
        return arguments[index + 1 :]
    return None


def _artisan_arguments(segment: CommandSegment) -> tuple[str, ...] | None:
    if _segment_matches_executable(segment, _ARTISAN_EXECUTABLES):
        return segment.arguments
    if _segment_matches_executable(segment, _PHP_EXECUTABLES):
        return _php_artisan_arguments(segment.arguments)
    if _segment_matches_executable(segment, _SAIL_EXECUTABLES):
        if not segment.arguments or _basename(segment.arguments[0]) != "artisan":
            return None
        return segment.arguments[1:]
    return None


def _contains_artisan_command(arguments: tuple[str, ...], command: str) -> bool:
    """Find a command while respecting known global option values."""

    index = 0
    while index < len(arguments):
        token = arguments[index].lower()
        if token in _ARTISAN_GLOBAL_OPTIONS_WITH_VALUES:
            if index + 1 >= len(arguments):
                return False
            index += 2
            continue
        if any(token.startswith(f"{option}=") for option in _ARTISAN_GLOBAL_OPTIONS_WITH_VALUES):
            index += 1
            continue
        if token in _ARTISAN_GLOBAL_FLAGS or token in _HELP_FLAGS:
            index += 1
            continue
        if token == command:
            return True
        if not token.startswith("-"):
            # The first non-option token is the Symfony command name. Once it is
            # another command, later arguments cannot turn this invocation into
            # the destructive command we are protecting.
            return False
        # Unknown leading options fail secure: keep scanning for the explicit
        # destructive command rather than treating an unfamiliar option as a
        # reason to silently bypass review.
        index += 1
    return False


@dataclass(frozen=True, slots=True)
class LaravelArtisanCommandMatcher:
    """Match one Laravel Artisan command across supported launcher forms."""

    command_name: str
    require_help: bool = False

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            artisan_arguments = _artisan_arguments(segment)
            if artisan_arguments is None:
                continue
            lowered_arguments = tuple(argument.lower() for argument in artisan_arguments)
            if not _contains_artisan_command(lowered_arguments, self.command_name):
                continue
            if self.require_help and not _HELP_FLAGS.intersection(lowered_arguments):
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail=f"Matched Laravel Artisan {self.command_name} command.",
                )
            )
        return tuple(evidence)


_LARAVEL_MIGRATE_FRESH = LaravelArtisanCommandMatcher("migrate:fresh")
_LARAVEL_DB_WIPE = LaravelArtisanCommandMatcher("db:wipe")


def _help_variant(command: str, prefix: str) -> tuple[CommandSafeVariant, ...]:
    return (
        CommandSafeVariant(
            variant_id=f"{prefix}-help",
            title="Laravel Artisan command help",
            matcher=LaravelArtisanCommandMatcher(command, require_help=True),
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
            (
                "Use ordinary `php artisan migrate` when the goal is to apply pending migrations "
                "without dropping existing tables."
            ),
        ),
        matcher=_LARAVEL_MIGRATE_FRESH,
        default_mode="review",
        safe_variants=_help_variant("migrate:fresh", "migrate-fresh"),
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
        safe_variants=_help_variant("db:wipe", "db-wipe"),
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
            (
                "https://github.com/laravel/framework/blob/13.x/src/Illuminate/Database/Console/Migrations/"
                "FreshCommand.php"
            ),
            "https://github.com/laravel/framework/blob/13.x/src/Illuminate/Database/Console/WipeCommand.php",
            "https://github.com/laravel/framework/blob/13.x/src/Illuminate/Console/Application.php",
            "https://laravel.com/ai/boost",
        ),
        ecosystem_ids=("laravel",),
        executables=("php", "artisan", "sail"),
        project_markers=("artisan",),
        example_command="php artisan migrate:fresh",
    ),
)
