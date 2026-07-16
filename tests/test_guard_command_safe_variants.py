from __future__ import annotations

from pathlib import Path

import pytest

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
