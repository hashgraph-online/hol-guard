"""A resident built in process reaches the CLI helpers it settles Claude turns with."""

from __future__ import annotations

import subprocess
import sys

_SCRIPT = """
import sys
from types import SimpleNamespace

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker

assert "codex_plugin_scanner.guard.cli.commands_support" not in sys.modules
print(HookWorker._claude_lifecycle_response(SimpleNamespace(store=None), "PostToolUse", {}))
"""


def test_an_in_process_resident_answers_a_claude_turn_without_the_cli_loaded() -> None:
    # A fresh interpreter, because the test session has usually loaded the CLI
    # command registry already, which hides a helper whose names it supplies.
    result = subprocess.run(
        [sys.executable, "-c", _SCRIPT],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "None"
