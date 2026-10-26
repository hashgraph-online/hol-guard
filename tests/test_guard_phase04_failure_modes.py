"""Phase 04 hook failure-mode proof tests."""

from __future__ import annotations

import argparse
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands import add_guard_root_parser, run_guard_command

pytestmark = pytest.mark.usefixtures("approval_questionnaire_mode")


def _parse_guard_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    return parser.parse_args(argv)


def _run_hook(
    tmp_path: Path,
    *,
    harness: str,
    payload: dict[str, object],
    json_output: bool = True,
) -> tuple[int, str]:
    output = StringIO()
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    argv = [
        "hook",
        "--home",
        str(tmp_path / "home"),
        "--guard-home",
        str(tmp_path / "guard-home"),
        "--harness",
        harness,
        "--workspace",
        str(workspace_dir),
    ]
    if json_output:
        argv.append("--json")
    stdout = StringIO()
    with redirect_stdout(stdout):
        exit_code = run_guard_command(
            _parse_guard_args(argv),
            input_text=json.dumps(payload),
            output_stream=output,
        )
    output.write(stdout.getvalue())
    return exit_code, output.getvalue()


def _json_line(output: str) -> dict[str, object]:
    lines = [line for line in output.splitlines() if line.strip()]
    assert lines
    payload = json.loads(output)
    assert isinstance(payload, dict)
    return payload


@pytest.mark.usefixtures("native_hook_force")
def test_gr098_permissive_hook_failure_preserves_existing_deny_decision(tmp_path: Path) -> None:
    exit_code, output = _run_hook(
        tmp_path,
        harness="claude-code",
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cat ~/.npmrc"},
            "policy_action": "require-reapproval",
            "daemon_status": "unreachable",
            "fail_mode": "permissive",
        },
    )

    payload = _json_line(output)

    assert exit_code == 0
    assert payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "HOL Guard" in str(payload["hookSpecificOutput"]["permissionDecisionReason"])
