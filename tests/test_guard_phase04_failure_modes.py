"""Phase 04 hook failure-mode proof tests."""

from __future__ import annotations

import argparse
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from codex_plugin_scanner.guard.cli.commands import add_guard_root_parser, run_guard_command


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


def test_gr098_hook_failures_fail_safe_in_strict_and_explain_permissive(tmp_path: Path) -> None:
    strict_exit_code, strict_output = _run_hook(
        tmp_path,
        harness="claude-code",
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "printf safe"},
            "daemon_status": "unreachable",
            "fail_mode": "strict",
            "decision_v2_json": {"harness_message": "Approve it in HOL Guard, then retry."},
        },
    )
    permissive_exit_code, permissive_output = _run_hook(
        tmp_path,
        harness="claude-code",
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "printf safe"},
            "daemon_status": "unreachable",
            "fail_mode": "permissive",
            "decision_v2_json": {"harness_message": "No daemon copy should be hidden."},
        },
    )

    strict_payload = _json_line(strict_output)
    permissive_payload = _json_line(permissive_output)

    assert strict_exit_code == 0
    assert strict_payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "fail safe" in str(strict_payload["hookSpecificOutput"]).lower()
    assert "Approve it in HOL Guard" not in str(strict_payload["hookSpecificOutput"])
    assert permissive_exit_code == 0
    assert permissive_payload["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert "daemon" in str(permissive_payload["hookSpecificOutput"]).lower()
    assert "No daemon copy should be hidden" not in str(permissive_payload["hookSpecificOutput"])


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


def test_gr098_codex_strict_daemon_failure_points_to_daemon_recovery(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))

    exit_code, output = _run_hook(
        tmp_path,
        harness="codex",
        json_output=False,
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "printf safe"},
            "daemon_status": "unreachable",
            "fail_mode": "strict",
            "decision_v2_json": {"harness_message": "Approve it in HOL Guard, then retry."},
        },
    )

    stderr = capsys.readouterr().err

    assert exit_code == 2
    assert output == ""
    assert "Restart HOL Guard" in stderr
    assert "Approve it in HOL Guard" not in stderr
