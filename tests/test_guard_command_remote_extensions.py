"""Structured remote administration command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_structured_matchers import (
    LeadingOperandCountMatcher,
    OptionValueKeyMatcher,
)
from tests.command_extension_contracts import (
    assert_review_required_cases,
    assert_reviewed_command_cases,
    assert_safe_command_cases,
)

REMOTE_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
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
    (
        "ssh -o 'RemoteCommand=uname -a' host.example",
        "SSH configured execution command",
        "command.remote.ssh.configured-execution",
    ),
    (
        "ssh -oProxyCommand='sh -c id' host.example",
        "SSH configured execution command",
        "command.remote.ssh.configured-execution",
    ),
    (
        "ssh -oKnownHostsCommand='sh -c id' host.example",
        "SSH configured execution command",
        "command.remote.ssh.configured-execution",
    ),
    (
        "ssh -voProxyCommand='sh -c id' host.example",
        "SSH configured execution command",
        "command.remote.ssh.configured-execution",
    ),
    (
        "ssh -4oRemoteCommand='id' host.example",
        "SSH configured execution command",
        "command.remote.ssh.configured-execution",
    ),
    (
        "ssh -oLocalCommand='sh -c id' -oPermitLocalCommand=yes host.example",
        "SSH configured execution command",
        "command.remote.ssh.configured-execution",
    ),
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
    (
        "rsync --rsync-path='sh -c id' ./out/ host.example:/srv/app/",
        "Rsync remote shell command",
        "command.remote.rsync.remote-shell",
    ),
    (
        "rsync -e 'sh -c id' ./out/ host.example:/srv/app/",
        "Rsync remote shell command",
        "command.remote.rsync.remote-shell",
    ),
    (
        "RSYNC_RSH='sh -c id' rsync ./out/ host.example:/srv/app/",
        "Rsync remote shell command",
        "command.remote.rsync.remote-shell",
    ),
    (
        "env RSYNC_RSH='sh -c id' rsync ./out/ host.example:/srv/app/",
        "Rsync remote shell command",
        "command.remote.rsync.remote-shell",
    ),
)


def test_remote_rules_feed_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(REMOTE_REVIEW_CASES, tmp_path)


REMOTE_SAFE_COMMANDS: tuple[str, ...] = (
    "ssh host.example",
    "ssh -G host.example uptime",
    "ssh -vG host.example uptime",
    "ssh -vGoProxyCommand='sh -c id' host.example",
    "ssh -V",
    "ssh -V host.example uptime",
    "ssh -Q cipher host.example uptime",
    "ssh -N host.example uptime",
    "ssh -W jump.example:22 host.example uptime",
    "ssh -O check host.example uptime",
    "ssh -o StrictHostKeyChecking=no host.example",
    "ssh -vo StrictHostKeyChecking=no host.example",
    "ssh -voStrictHostKeyChecking=no host.example",
    "ssh -voProxyCommand=none host.example",
    "ssh -G -oProxyCommand='sh -c id' host.example",
    "ssh -oProxyCommand=none host.example",
    "ssh -oLocalCommand='sh -c id' host.example",
    "ssh -oPermitLocalCommand=no -oLocalCommand='sh -c id' host.example",
    "scp -h",
    "scp -vo StrictHostKeyChecking=no source",
    "rsync -av ./out/ host.example:/srv/app/",
    "rsync -av --delete ./out/ host.example:/srv/app/ --dry-run",
    "rsync -avn --delete ./out/ host.example:/srv/app/",
    "rsync -av --delete ./out/ host.example:/srv/app/ --no-dry-run --dry-run",
    "rsync -av --delete ./out/ host.example:/srv/app/ --no-dry-run -n",
    "grep 'ssh host command|scp source target|rsync --delete' docs",
    "echo ssh host.example uptime",
)


def test_remote_observer_and_preview_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(REMOTE_SAFE_COMMANDS, tmp_path)


def test_rsync_disabled_preview_aliases_remain_live_execution(tmp_path: Path) -> None:
    assert_review_required_cases(
        (
            "rsync -av --delete ./out/ host.example:/srv/app/ --dry-run --no-dry-run",
            "rsync -avn --delete ./out/ host.example:/srv/app/ --no-dry-run",
        ),
        tmp_path,
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


def test_leading_operand_matcher_parses_numeric_clustered_flags(tmp_path: Path) -> None:
    matcher = LeadingOperandCountMatcher(
        executables=frozenset({"remote-admin"}),
        minimum_operands=2,
        forbidden_flags=frozenset({"-N"}),
    )
    command = parse_shell_command("remote-admin -4N host action", cwd=tmp_path, home_dir=tmp_path)

    assert matcher.match(command) == ()


def test_option_key_matcher_prefers_longest_overlapping_option(tmp_path: Path) -> None:
    matcher = OptionValueKeyMatcher(
        executables=frozenset({"remote-admin"}),
        option_names=frozenset({"-o", "-option"}),
        value_keys=frozenset({"proxycommand"}),
    )
    command = parse_shell_command(
        "remote-admin -optionProxyCommand='sh -c id' host",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert matcher.match(command)


def test_remote_execution_actions_publish_risk_classes() -> None:
    assert risk_classes_for_command_action("SSH configured execution command") == (
        "execution",
        "network_egress",
    )
    assert risk_classes_for_command_action("Rsync remote shell command") == (
        "execution",
        "network_egress",
    )


def test_rsync_option_values_cannot_forge_dry_run(tmp_path: Path) -> None:
    for command in (
        "rsync --delete --exclude -n src/ dst/",
        "rsync --delete --exclude=-n src/ dst/",
        "rsync --delete -f -n src/ dst/",
        "rsync --delete --log-format -n src/ dst/",
    ):
        payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

        assert payload["status"] == "review", command
        assert payload["controlling_rule_id"] == "command.remote.rsync.deletion", command
