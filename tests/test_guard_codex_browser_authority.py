"""Codex live browser approval authority and receipt finalization regressions."""

from __future__ import annotations

import argparse

from codex_plugin_scanner.guard.cli.commands import add_guard_root_parser
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from tests.guard_cli_facade_isolation import restore_cli_facade_approval_hooks


def teardown_module() -> None:
    """Reset facade overrides propagated into lazily imported CLI modules."""

    restore_cli_facade_approval_hooks()


def _artifact() -> GuardArtifact:
    return GuardArtifact(
        artifact_id="codex:project:Bash",
        name="Bash request",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=".codex/config.toml",
        command="printf ok",
    )


def _action_envelope() -> GuardActionEnvelope:
    return GuardActionEnvelope(
        schema_version=1,
        action_id="action-browser-review",
        harness="codex",
        event_name="PostToolUse",
        action_type="shell_command",
        workspace="/workspace",
        workspace_hash="workspace-hash",
        tool_name="Bash",
        command="printf ok",
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        raw_payload_redacted={"tool_name": "Bash"},
    ).with_pre_execution_result("review")


def _parse_guard_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    return parser.parse_args(argv)
