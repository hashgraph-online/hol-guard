"""Fallback hook evidence is handed to the native writer as one submission."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

from codex_plugin_scanner.guard.hook_review.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore


def test_failed_post_tool_event_reaches_the_native_writer_without_reclassification(tmp_path: Path) -> None:
    writer = Mock()
    worker = HookWorker(store=GuardStore(tmp_path), activity_writer=writer, start_native_policy=False)
    try:
        payload = {"tool_name": "Bash", "tool_input": {"command": "pwd"}}
        worker._record_post_tool_activity(harness="claude-code", event="PostToolUseFailure", payload=payload)
        writer.submit_post_tool_activity.assert_called_once_with(
            harness="claude-code", event="PostToolUseFailure", payload=payload
        )
        writer.submit_command_activity.assert_not_called()
        writer.submit_composio_discovery.assert_not_called()
    finally:
        worker.close()
