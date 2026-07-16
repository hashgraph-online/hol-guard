"""Structured hosting platform command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize(
    ("command", "action_class", "rule_id"),
    [
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
    ],
)
def test_platform_rules_feed_inspection_and_runtime_hooks(
    command: str,
    action_class: str,
    rule_id: str,
    tmp_path: Path,
) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["classification"]["action_class"] == action_class
    assert payload["controlling_rule_id"] == rule_id
    runtime_match = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert runtime_match is not None
    assert runtime_match.action_class == action_class


@pytest.mark.parametrize(
    "command",
    [
        "vercel remove --help",
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
    ],
)
def test_platform_help_preview_and_read_commands_remain_safe(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "no_match"
    assert (
        extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


def test_platform_safe_variant_does_not_hide_destructive_segment(tmp_path: Path) -> None:
    payload = inspect_command(
        "vercel remove --help && heroku apps:destroy -a web",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert [rule["rule_id"] for rule in payload["rules"]] == ["command.platform.heroku.app-destruction"]


def test_platform_extensions_publish_primary_references() -> None:
    for extension_id in ("command.platform.vercel", "command.platform.netlify", "command.platform.heroku"):
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)

        assert extension is not None
        assert extension.reference_urls
        assert all(url.startswith("https://") for url in extension.reference_urls)
