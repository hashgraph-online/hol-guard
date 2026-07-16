"""Structured remote administration command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_rules import LeadingOperandCountMatcher
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize(
    ("command", "action_class", "rule_id"),
    [
        ("ssh host.example uptime", "SSH remote execution command", "command.remote.ssh.execution"),
        (
            "ssh -p 2222 host.example sudo systemctl restart api",
            "SSH remote execution command",
            "command.remote.ssh.execution",
        ),
        (
            "ssh.exe -oStrictHostKeyChecking=no host.example -- uname -a",
            "SSH remote execution command",
            "command.remote.ssh.execution",
        ),
        ("ssh -g host.example uptime", "SSH remote execution command", "command.remote.ssh.execution"),
        ("scp artifact.zip host.example:/srv/app/", "SCP overwrite command", "command.remote.scp.transfer"),
        ("scp -p artifact.zip host.example:/srv/app/", "SCP overwrite command", "command.remote.scp.transfer"),
        (
            "scp.cmd -P2222 host.example:/srv/app/config ./config",
            "SCP overwrite command",
            "command.remote.scp.transfer",
        ),
        (
            "rsync -av --delete ./out/ host.example:/srv/app/",
            "Rsync destructive command",
            "command.remote.rsync.deletion",
        ),
        (
            "rsync.exe --remove-source-files ./queue/ host.example:/archive/",
            "Rsync destructive command",
            "command.remote.rsync.deletion",
        ),
    ],
)
def test_remote_rules_feed_runtime_hooks(
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
        "ssh host.example",
        "ssh -G host.example uptime",
        "ssh -vG host.example uptime",
        "ssh -V",
        "scp -h",
        "rsync -av ./out/ host.example:/srv/app/",
        "rsync -av --delete ./out/ host.example:/srv/app/ --dry-run",
        "rsync -avn --delete ./out/ host.example:/srv/app/",
        "grep 'ssh host command|scp source target|rsync --delete' docs",
        "echo ssh host.example uptime",
    ],
)
def test_remote_observer_and_preview_commands_remain_safe(command: str, tmp_path: Path) -> None:
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


def test_remote_extensions_publish_official_references() -> None:
    for extension_id in ("command.remote.ssh", "command.remote.scp", "command.remote.rsync"):
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)

        assert extension is not None
        assert extension.reference_urls
        assert all(url.startswith("https://") for url in extension.reference_urls)


def test_leading_operand_matcher_consumes_separate_long_option_value(tmp_path: Path) -> None:
    matcher = LeadingOperandCountMatcher(
        executables=frozenset({"remote-admin"}),
        minimum_operands=2,
        options_with_values=frozenset({"--profile"}),
    )
    command = parse_shell_command("remote-admin --profile production delete item", cwd=tmp_path, home_dir=tmp_path)

    assert matcher.match(command)
