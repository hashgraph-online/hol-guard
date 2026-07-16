from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize(
    "command",
    [
        "git clean --no-dry-run -nfdx",
        "git push origin main --force --no-dry-run --dry-run",
    ],
)
def test_effective_git_preview_aliases_remain_runtime_safe(command: str, tmp_path: Path) -> None:
    assert inspect_command(command, cwd=tmp_path, home_dir=tmp_path)["status"] == "no_match"
    assert (
        extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


@pytest.mark.parametrize(
    "command",
    [
        "git clean -nfdx --no-dry-run",
        "git clean --dry-run -fdx --no-dry-run",
        "git push origin main --force --dry-run --no-dry-run",
    ],
)
def test_disabled_git_preview_aliases_remain_runtime_sensitive(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
    match = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert payload["status"] == "review"
    assert match is not None
    assert match.action_class == "git destructive command"


@pytest.mark.parametrize(
    ("command", "expected_status", "expected_matched"),
    [
        (
            "aws ec2 terminate-instances --instance-ids i-123 --dry-run --no-dry-run",
            "review",
            True,
        ),
        (
            "aws ec2 terminate-instances --instance-ids i-123 --no-dry-run --dry-run",
            "no_match",
            False,
        ),
        ("aws rds delete-db-instance --generate-cli-skeleton=output", "no_match", False),
    ],
)
def test_command_test_cli_honors_effective_safe_option_semantics(
    command: str,
    expected_status: str,
    expected_matched: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))

    exit_code = main(["guard", "command", "test", "--json", command])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["status"] == expected_status
    assert payload["classification"]["matched"] is expected_matched
