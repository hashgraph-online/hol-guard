"""Web application framework command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

FRAMEWORK_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("php artisan db:wipe", "Laravel database wipe command", "command.framework.laravel.database-wipe"),
    ("artisan db:wipe --force", "Laravel database wipe command", "command.framework.laravel.database-wipe"),
    (
        "php artisan db:wipe --drop-views --drop-types",
        "Laravel database wipe command",
        "command.framework.laravel.database-wipe",
    ),
    ("./artisan db:wipe", "Laravel database wipe command", "command.framework.laravel.database-wipe"),
    (
        "php artisan --env=testing db:wipe",
        "Laravel database wipe command",
        "command.framework.laravel.database-wipe",
    ),
    (
        "php artisan migrate:fresh",
        "Laravel destructive rebuild command",
        "command.framework.laravel.migrate-fresh",
    ),
    (
        "php artisan migrate:fresh --seed",
        "Laravel destructive rebuild command",
        "command.framework.laravel.migrate-fresh",
    ),
    (
        "artisan migrate:fresh --force --drop-views",
        "Laravel destructive rebuild command",
        "command.framework.laravel.migrate-fresh",
    ),
    (
        "php artisan migrate:reset",
        "Laravel migration reset command",
        "command.framework.laravel.migrate-reset",
    ),
    (
        "php artisan migrate:refresh --step=5",
        "Laravel migration reset command",
        "command.framework.laravel.migrate-reset",
    ),
    (
        "artisan migrate:refresh",
        "Laravel migration reset command",
        "command.framework.laravel.migrate-reset",
    ),
    (
        "php artisan migrate:rollback",
        "Laravel migration rollback command",
        "command.framework.laravel.migrate-rollback",
    ),
    (
        "php artisan migrate:rollback --batch=3",
        "Laravel migration rollback command",
        "command.framework.laravel.migrate-rollback",
    ),
    (
        "artisan migrate:rollback --step=2",
        "Laravel migration rollback command",
        "command.framework.laravel.migrate-rollback",
    ),
    ("php artisan queue:clear", "Laravel queue purge command", "command.framework.laravel.queue-purge"),
    (
        "php artisan queue:clear redis --queue=emails",
        "Laravel queue purge command",
        "command.framework.laravel.queue-purge",
    ),
    ("artisan queue:flush", "Laravel queue purge command", "command.framework.laravel.queue-purge"),
    (
        "php artisan queue:flush --hours=48",
        "Laravel queue purge command",
        "command.framework.laravel.queue-purge",
    ),
    ("artisan.exe db:wipe", "Laravel database wipe command", "command.framework.laravel.database-wipe"),
    ("php.cmd artisan migrate:fresh", "Laravel destructive rebuild command", "command.framework.laravel.migrate-fresh"),
    (
        "php -d memory_limit=-1 artisan db:wipe",
        "Laravel database wipe command",
        "command.framework.laravel.database-wipe",
    ),
    (
        "php -c php.ini artisan migrate:fresh",
        "Laravel destructive rebuild command",
        "command.framework.laravel.migrate-fresh",
    ),
    ("php ./artisan db:wipe", "Laravel database wipe command", "command.framework.laravel.database-wipe"),
    (
        "php /app/artisan migrate:fresh",
        "Laravel destructive rebuild command",
        "command.framework.laravel.migrate-fresh",
    ),
    (
        "php /var/www/app/artisan migrate:reset",
        "Laravel migration reset command",
        "command.framework.laravel.migrate-reset",
    ),
    (
        "php -d memory_limit=1G artisan queue:flush",
        "Laravel queue purge command",
        "command.framework.laravel.queue-purge",
    ),
    (
        "php -c --help artisan db:wipe",
        "Laravel database wipe command",
        "command.framework.laravel.database-wipe",
    ),
    (
        "php -d --help artisan migrate:fresh",
        "Laravel destructive rebuild command",
        "command.framework.laravel.migrate-fresh",
    ),
    (
        "php artisan --env --help db:wipe",
        "Laravel database wipe command",
        "command.framework.laravel.database-wipe",
    ),
    (
        "php /app/artisan --env --pretend migrate:rollback",
        "Laravel migration rollback command",
        "command.framework.laravel.migrate-rollback",
    ),
)


def test_framework_rules_feed_inspection_and_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(FRAMEWORK_REVIEW_CASES, tmp_path)


FRAMEWORK_SAFE_COMMANDS: tuple[str, ...] = (
    "php artisan db:wipe --help",
    "artisan migrate:fresh -h",
    "php artisan db:wipe -h",
    "php artisan migrate:reset --pretend",
    "php artisan migrate:rollback --pretend --batch=3",
    "php -d memory_limit=-1 artisan db:wipe --help",
    "php /app/artisan db:wipe --help",
    "php ./artisan migrate:reset --pretend",
    "php artisan migrate:status",
    "php artisan migrate",
    "php artisan db:seed",
    "php artisan db:show",
    "php artisan queue:failed",
    "php artisan queue:retry 1",
    "php artisan queue:restart",
    "php artisan cache:clear",
    "php artisan config:clear",
    "php artisan route:clear",
    "php artisan view:clear",
    "php artisan optimize:clear",
    "php artisan serve",
    "php artisan about",
    "php artisan list",
    "php artisan make:model Flight",
    "grep 'db:wipe' deploy-notes.md",
    "printf '%s\\n' 'php artisan migrate:fresh'",
)


def test_framework_help_preview_and_read_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(FRAMEWORK_SAFE_COMMANDS, tmp_path)


def test_framework_safe_variant_does_not_hide_destructive_segment(tmp_path: Path) -> None:
    payload = inspect_command(
        "php artisan db:wipe --help && php artisan migrate:fresh",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert [rule["rule_id"] for rule in payload["rules"]] == ["command.framework.laravel.migrate-fresh"]

    script_path_payload = inspect_command(
        "php ./artisan db:wipe --help && php artisan migrate:fresh",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert [rule["rule_id"] for rule in script_path_payload["rules"]] == ["command.framework.laravel.migrate-fresh"]


def test_framework_pipelines_and_wrappers_preserve_review(tmp_path: Path) -> None:
    pipeline_payload = inspect_command(
        "echo yes | php artisan db:wipe",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert pipeline_payload["status"] == "review"
    assert [rule["rule_id"] for rule in pipeline_payload["rules"]] == ["command.framework.laravel.database-wipe"]


def test_framework_extensions_publish_primary_references() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.framework.laravel")

    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
