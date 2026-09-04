"""Structured Laravel Artisan command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

LARAVEL_ARTISAN_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "php artisan migrate:fresh",
        "Laravel fresh migration database reset command",
        "command.laravel-artisan.migrate-fresh",
    ),
    (
        "php artisan migrate:fresh --force",
        "Laravel fresh migration database reset command",
        "command.laravel-artisan.migrate-fresh",
    ),
    (
        "php ./artisan migrate:fresh",
        "Laravel fresh migration database reset command",
        "command.laravel-artisan.migrate-fresh",
    ),
    (
        "php /srv/app/artisan migrate:fresh",
        "Laravel fresh migration database reset command",
        "command.laravel-artisan.migrate-fresh",
    ),
    (
        "php -d memory_limit=-1 artisan migrate:fresh --seed",
        "Laravel fresh migration database reset command",
        "command.laravel-artisan.migrate-fresh",
    ),
    (
        "php -dmemory_limit=-1 artisan migrate:fresh",
        "Laravel fresh migration database reset command",
        "command.laravel-artisan.migrate-fresh",
    ),
    (
        "php -c php.ini artisan migrate:fresh",
        "Laravel fresh migration database reset command",
        "command.laravel-artisan.migrate-fresh",
    ),
    (
        "php -cphp.ini artisan migrate:fresh",
        "Laravel fresh migration database reset command",
        "command.laravel-artisan.migrate-fresh",
    ),
    (
        "php -n artisan migrate:fresh",
        "Laravel fresh migration database reset command",
        "command.laravel-artisan.migrate-fresh",
    ),
    (
        "php -f ./artisan migrate:fresh",
        "Laravel fresh migration database reset command",
        "command.laravel-artisan.migrate-fresh",
    ),
    (
        "php --file ./artisan migrate:fresh",
        "Laravel fresh migration database reset command",
        "command.laravel-artisan.migrate-fresh",
    ),
    (
        "php --file=artisan db:wipe",
        "Laravel database wipe command",
        "command.laravel-artisan.db-wipe",
    ),
    (
        "./artisan --env=production migrate:fresh",
        "Laravel fresh migration database reset command",
        "command.laravel-artisan.migrate-fresh",
    ),
    (
        "artisan --no-ansi migrate:fresh",
        "Laravel fresh migration database reset command",
        "command.laravel-artisan.migrate-fresh",
    ),
    (
        "sail artisan --ansi migrate:fresh",
        "Laravel fresh migration database reset command",
        "command.laravel-artisan.migrate-fresh",
    ),
    (
        "php artisan db:wipe",
        "Laravel database wipe command",
        "command.laravel-artisan.db-wipe",
    ),
    (
        "php /srv/app/artisan db:wipe --drop-views",
        "Laravel database wipe command",
        "command.laravel-artisan.db-wipe",
    ),
    (
        "php artisan db:wipe --drop-views --drop-types --force",
        "Laravel database wipe command",
        "command.laravel-artisan.db-wipe",
    ),
    (
        "artisan --env production db:wipe",
        "Laravel database wipe command",
        "command.laravel-artisan.db-wipe",
    ),
    (
        "sail artisan --no-interaction db:wipe --drop-views",
        "Laravel database wipe command",
        "command.laravel-artisan.db-wipe",
    ),
)


def test_laravel_artisan_destructive_database_commands_reach_review(tmp_path: Path) -> None:
    assert_reviewed_command_cases(LARAVEL_ARTISAN_REVIEW_CASES, tmp_path)


LARAVEL_ARTISAN_SAFE_COMMANDS: tuple[str, ...] = (
    "php artisan migrate",
    "php artisan migrate:status",
    "php artisan migrate --pretend",
    "php artisan migrate:fresh --help",
    "php artisan migrate:fresh -h",
    "php ./artisan db:wipe --help",
    "sail artisan --env=production db:wipe -h",
    "sail artisan migrate:status",
    "artisan list",
    "artisan --env=migrate:fresh migrate:status",
    "artisan --env migrate:fresh migrate:status",
    "php -d auto_prepend_file=migrate:fresh artisan migrate:status",
    "php -r 'echo 1;' artisan migrate:fresh",
    'echo "php artisan migrate:fresh"',
)


def test_laravel_artisan_observer_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(LARAVEL_ARTISAN_SAFE_COMMANDS, tmp_path)


def test_laravel_artisan_extension_publishes_official_references() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.laravel-artisan")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
    assert "laravel" in extension.ecosystem_ids
    assert extension.project_markers == ("artisan",)
