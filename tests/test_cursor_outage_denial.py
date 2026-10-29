"""A generated Cursor client reached without the native bridge never allows a gated action."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source


def _run_client(tmp_path: Path, event: str) -> subprocess.CompletedProcess[str]:
    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=tmp_path)
    unavailable = [sys.executable, "-S", "-c", "raise AssertionError('The client must not invoke Guard')"]
    script = tmp_path / "cursor-hook.py"
    script.write_text(
        cursor_hook_script_source(context, guard_cli=unavailable, recovery_command=unavailable), encoding="utf-8"
    )
    command = [sys.executable, "-S", str(script)]
    if event:
        command.extend(["--cursor-hook-event", event])
    return subprocess.run(
        command,
        input='{"command": "rm -rf /"}',
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(context.home_dir)},
        timeout=10,
        check=False,
    )


@pytest.mark.parametrize(
    "event",
    ["beforeReadFile", "beforeShellExecution", "beforeMCPExecution", "beforeWriteFile", ""],
)
def test_generated_cursor_client_denies_a_gated_action(tmp_path: Path, event: str) -> None:
    result = _run_client(tmp_path, event)

    assert result.returncode == 2, result.stderr
    assert json.loads(result.stdout) == {
        "permission": "deny",
        "user_message": "HOL Guard could not complete the native hook decision safely.",
    }


@pytest.mark.parametrize("event", ["afterShellExecution", "afterMCPExecution"])
def test_generated_cursor_client_lets_an_observer_continue(tmp_path: Path, event: str) -> None:
    result = _run_client(tmp_path, event)

    assert (result.returncode, result.stdout) == (0, "{}\n"), result.stderr
