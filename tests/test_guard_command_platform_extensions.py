"""Structured hosting platform command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

PLATFORM_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("vercel remove app.example.test", "Vercel destructive command", "command.platform.vercel.deletion"),
    ("vercel rm app.example.test", "Vercel destructive command", "command.platform.vercel.deletion"),
    ("vercel project rm web", "Vercel destructive command", "command.platform.vercel.deletion"),
    ("vercel promote deployment-id", "Vercel production command", "command.platform.vercel.production-change"),
    (
        "vercel -t token-value -S team promote deployment-id",
        "Vercel production command",
        "command.platform.vercel.production-change",
    ),
    ("vercel rollback deployment-id", "Vercel production command", "command.platform.vercel.production-change"),
    ("vercel deploy --prod", "Vercel production command", "command.platform.vercel.production-change"),
    ("vercel deploy -p", "Vercel production command", "command.platform.vercel.production-change"),
    ("vercel --prod", "Vercel production command", "command.platform.vercel.production-change"),
    ("vercel -p", "Vercel production command", "command.platform.vercel.production-change"),
    (
        "vercel --scope team --prod",
        "Vercel production command",
        "command.platform.vercel.production-change",
    ),
    (
        "netlify sites:delete --site site-id",
        "Netlify destructive command",
        "command.platform.netlify.site-deletion",
    ),
    (
        "netlify deploy --prod --dir dist",
        "Netlify production command",
        "command.platform.netlify.production-deploy",
    ),
    ("netlify deploy -p --dir dist", "Netlify production command", "command.platform.netlify.production-deploy"),
    ("heroku apps:destroy --app web", "Heroku destructive command", "command.platform.heroku.app-destruction"),
    ("heroku pipelines:promote -a web", "Heroku release command", "command.platform.heroku.release-change"),
    ("heroku releases:rollback v42 -a web", "Heroku release command", "command.platform.heroku.release-change"),
    ("vercel.cmd --scope team project rm web", "Vercel destructive command", "command.platform.vercel.deletion"),
    (
        "netlify.exe deploy --site site-id --prod",
        "Netlify production command",
        "command.platform.netlify.production-deploy",
    ),
    (
        "netlify --auth token-value deploy --prod",
        "Netlify production command",
        "command.platform.netlify.production-deploy",
    ),
)


def test_platform_rules_feed_inspection_and_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(PLATFORM_REVIEW_CASES, tmp_path)


PLATFORM_SAFE_COMMANDS: tuple[str, ...] = (
    "vercel remove --help",
    "vercel --prod --help",
    "vercel promote status web",
    "vercel project inspect web",
    "vercel list --prod",
    "netlify sites:delete --help",
    "netlify deploy --dir dist",
    "netlify build --dry",
    "heroku apps:destroy --help",
    "heroku apps:info -a web",
    "heroku releases:info v42 -a web",
    "grep 'vercel remove|netlify sites:delete' scripts/checks.sh",
    "printf '%s\\n' 'heroku apps:destroy -a web'",
)


def test_platform_help_preview_and_read_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(PLATFORM_SAFE_COMMANDS, tmp_path)


def test_platform_safe_variant_does_not_hide_destructive_segment(tmp_path: Path) -> None:
    payload = inspect_command(
        "vercel remove --help && heroku apps:destroy -a web",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert [rule["rule_id"] for rule in payload["rules"]] == ["command.platform.heroku.app-destruction"]


def test_default_production_deploy_does_not_hide_later_destructive_segment(tmp_path: Path) -> None:
    payload = inspect_command(
        "vercel --prod && netlify sites:delete site-id",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert [rule["rule_id"] for rule in payload["rules"]] == [
        "command.platform.netlify.site-deletion",
        "command.platform.vercel.production-change",
    ]


def test_platform_extensions_publish_primary_references() -> None:
    for extension_id in ("command.platform.vercel", "command.platform.netlify", "command.platform.heroku"):
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)

        assert extension is not None
        assert extension.reference_urls
        assert all(url.startswith("https://") for url in extension.reference_urls)
