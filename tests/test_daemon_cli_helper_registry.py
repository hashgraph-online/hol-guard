"""A resident built in process reaches the CLI helpers it settles Claude turns with."""

from __future__ import annotations

import subprocess
import sys

_SCRIPT = """
import sys
import tempfile
from pathlib import Path

from codex_plugin_scanner.guard.hook_review.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore

assert "codex_plugin_scanner.guard.cli.commands_support" not in sys.modules
with tempfile.TemporaryDirectory() as directory:
    worker = HookWorker(store=GuardStore(Path(directory) / "guard-home"), wait_for_native_policy=False)
    try:
        response = worker.review_http_payload(
            payload={
                "hook_event_name": "PostToolUse",
                "tool_name": "AskUserQuestion",
                "session_id": "fresh-interpreter-session",
                "tool_input": {"questions": []},
                "tool_response": {"answers": {}},
            },
            params={},
            default_harness="claude-code",
            home_dir=Path(directory),
            guard_home=worker.store.guard_home,
            workspace=None,
        )
    finally:
        worker.close()
assert isinstance(response, dict)
print("ok")
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
    assert result.stdout.strip() == "ok"
