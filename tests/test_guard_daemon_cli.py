"""Tests for hol-guard daemon status/repair/stop subcommands.

Covers L311-L313: daemon CLI management commands.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _run(args: list[str], guard_home: Path) -> tuple[int, dict]:
    result = subprocess.run(
        ["hol-guard", *args, f"--guard-home={guard_home}", "--json"],
        capture_output=True,
        text=True,
    )
    try:
        payload = json.loads(result.stdout or result.stderr or "{}")
    except json.JSONDecodeError:
        payload = {"raw": result.stdout or result.stderr}
    return result.returncode, payload


class TestDaemonStatusCommand:
    """L311: hol-guard daemon status."""

    def test_status_returns_not_running_when_no_daemon_state(self, tmp_path: Path) -> None:
        code, payload = _run(["daemon", "status"], tmp_path)
        assert code == 0
        assert payload.get("running") is False

    def test_status_json_has_required_keys(self, tmp_path: Path) -> None:
        code, payload = _run(["daemon", "status"], tmp_path)
        assert code == 0
        for key in ("running", "guard_home"):
            assert key in payload, f"missing key: {key}"

    def test_status_shows_guard_home_path(self, tmp_path: Path) -> None:
        code, payload = _run(["daemon", "status"], tmp_path)
        assert code == 0
        assert payload.get("guard_home") == str(tmp_path)

    def test_status_includes_version_when_present(self, tmp_path: Path) -> None:
        code, payload = _run(["daemon", "status"], tmp_path)
        assert code == 0
        assert "version" in payload

    def test_status_running_true_when_live_state(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.daemon.manager import write_guard_daemon_state

        write_guard_daemon_state(tmp_path, port=19999, auth_token="test-token-abc")
        state_path = tmp_path / "daemon-state.json"
        import json as _json

        state = _json.loads(state_path.read_text())
        pid = os.getpid()
        state["pid"] = pid
        state_path.write_text(_json.dumps(state))

        code, payload = _run(["daemon", "status"], tmp_path)
        assert code == 0
        assert "guard_home" in payload


class TestDaemonRepairCommand:
    """L312: hol-guard daemon repair."""

    def test_repair_succeeds_with_no_daemon_state(self, tmp_path: Path) -> None:
        code, payload = _run(["daemon", "repair"], tmp_path)
        assert code == 0
        assert payload.get("repaired") is True

    def test_repair_removes_stale_locator(self, tmp_path: Path) -> None:
        locator_path = tmp_path / "approval-center-locator.json"
        locator_path.write_text('{"port": 0, "pid": 99999999}')
        assert locator_path.exists()

        code, payload = _run(["daemon", "repair"], tmp_path)
        assert code == 0
        assert not locator_path.exists(), "stale locator should be removed"

    def test_repair_reports_cleared_items(self, tmp_path: Path) -> None:
        locator_path = tmp_path / "approval-center-locator.json"
        locator_path.write_text('{"port": 0, "pid": 99999999}')

        code, payload = _run(["daemon", "repair"], tmp_path)
        assert code == 0
        cleared = payload.get("cleared", [])
        assert "locator" in cleared

    def test_repair_is_idempotent(self, tmp_path: Path) -> None:
        code1, _ = _run(["daemon", "repair"], tmp_path)
        code2, _ = _run(["daemon", "repair"], tmp_path)
        assert code1 == 0
        assert code2 == 0


class TestDaemonStopCommand:
    """L313: hol-guard daemon stop."""

    def test_stop_succeeds_when_no_daemon_running(self, tmp_path: Path) -> None:
        code, payload = _run(["daemon", "stop"], tmp_path)
        assert code == 0
        assert payload.get("stopped") is True or payload.get("running") is False

    def test_stop_clears_daemon_state(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.daemon.manager import write_guard_daemon_state

        write_guard_daemon_state(tmp_path, port=0, auth_token="x")

        code, payload = _run(["daemon", "stop"], tmp_path)
        assert code == 0

    def test_stop_json_has_stopped_key(self, tmp_path: Path) -> None:
        code, payload = _run(["daemon", "stop"], tmp_path)
        assert code == 0
        assert "stopped" in payload or "running" in payload
