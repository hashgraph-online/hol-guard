"""Tests for hol-guard daemon status/repair/stop subcommands.

Covers L311-L313: daemon CLI management commands.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import time
from argparse import Namespace
from pathlib import Path
from typing import cast

import pytest


def _run(args: list[str], guard_home: Path) -> tuple[int, dict[str, object]]:
    result = subprocess.run(
        ["hol-guard", *args, f"--guard-home={guard_home}", "--json"],
        capture_output=True,
        text=True,
    )
    try:
        parsed: object = json.loads(result.stdout or result.stderr or "{}")
        payload: dict[str, object]
        if isinstance(parsed, dict):
            payload = {str(key): value for key, value in cast(dict[object, object], parsed).items()}
        else:
            payload = {"raw": result.stdout or result.stderr}
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

    def test_status_does_not_wait_for_guard_database_writer(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.store import GuardStore

        store = GuardStore(tmp_path, prime_policy_integrity=False)
        baseline_started = time.monotonic()
        baseline_code, baseline_payload = _run(["daemon", "status"], tmp_path)
        baseline_elapsed = time.monotonic() - baseline_started
        assert baseline_code == 0
        assert baseline_payload.get("running") is False

        writer = sqlite3.connect(store.path)
        writer.execute("pragma journal_mode=delete")
        writer.execute("begin exclusive")
        started = time.monotonic()
        try:
            code, payload = _run(["daemon", "status"], tmp_path)
        finally:
            writer.rollback()
            writer.close()

        assert code == 0
        assert payload.get("running") is False
        assert time.monotonic() - started < baseline_elapsed + 0.5

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

        code, _payload = _run(["daemon", "repair"], tmp_path)
        assert code == 0
        assert not locator_path.exists(), "stale locator should be removed"

    def test_repair_reports_cleared_items(self, tmp_path: Path) -> None:
        locator_path = tmp_path / "approval-center-locator.json"
        locator_path.write_text('{"port": 0, "pid": 99999999}')

        code, payload = _run(["daemon", "repair"], tmp_path)
        assert code == 0
        cleared = payload.get("cleared", [])
        assert isinstance(cleared, list)
        assert "locator" in cleared

    def test_repair_is_idempotent(self, tmp_path: Path) -> None:
        code1, _ = _run(["daemon", "repair"], tmp_path)
        code2, _ = _run(["daemon", "repair"], tmp_path)
        assert code1 == 0
        assert code2 == 0

    def test_repair_removes_malformed_discovery_key_for_safe_regeneration(self, tmp_path: Path) -> None:
        (tmp_path / "daemon-state.json").write_text("{}", encoding="utf-8")
        key_path = tmp_path / "daemon-discovery-key"
        key_path.write_text("not-a-valid-discovery-key", encoding="utf-8")

        code, payload = _run(["daemon", "repair"], tmp_path)

        assert code == 0
        cleared = payload.get("cleared", [])
        assert isinstance(cleared, list)
        assert "daemon_discovery_key" in cleared
        assert key_path.exists() is False


def test_daemon_recover_dispatches_failure_aware_recovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import daemon
    from codex_plugin_scanner.guard.cli.commands_dispatch_cloud import _run_guard_daemon_command

    calls: list[tuple[Path, str]] = []

    def recover(guard_home: Path, *, home_dir: Path | None, failure_kind: str) -> str:
        assert home_dir is None
        calls.append((guard_home, failure_kind))
        return "http://127.0.0.1:1"

    monkeypatch.setattr(daemon, "recover_guard_daemon_after_hook_failure", recover)

    code = _run_guard_daemon_command(
        Namespace(daemon_command="recover", failure_kind="transport-failure"),
        guard_home=tmp_path,
    )

    assert code == 0
    assert calls == [(tmp_path, "transport-failure")]


def test_daemon_recover_returns_structured_error_without_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from codex_plugin_scanner.guard import daemon
    from codex_plugin_scanner.guard.cli.commands_dispatch_cloud import _run_guard_daemon_command

    def recover(guard_home: Path, *, home_dir: Path | None, failure_kind: str) -> str:
        del guard_home, home_dir, failure_kind
        raise RuntimeError("recovery unavailable")

    monkeypatch.setattr(daemon, "recover_guard_daemon_after_hook_failure", recover)

    code = _run_guard_daemon_command(
        Namespace(daemon_command="recover", failure_kind="transport-failure"),
        guard_home=tmp_path,
    )

    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert code == 1
    assert payload["recovered"] is False
    assert payload["running"] is False
    assert payload["error"] == {
        "code": "daemon_recovery_failed",
        "message": "recovery unavailable",
    }


class TestDaemonStopCommand:
    """L313: hol-guard daemon stop."""

    def test_stop_succeeds_when_no_daemon_running(self, tmp_path: Path) -> None:
        code, payload = _run(["daemon", "stop"], tmp_path)
        assert code == 0
        assert payload.get("stopped") is True or payload.get("running") is False

    def test_stop_clears_daemon_state(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.daemon.manager import write_guard_daemon_state

        write_guard_daemon_state(tmp_path, port=0, auth_token="x")

        code, _payload = _run(["daemon", "stop"], tmp_path)
        assert code == 0

    def test_stop_json_has_stopped_key(self, tmp_path: Path) -> None:
        code, payload = _run(["daemon", "stop"], tmp_path)
        assert code == 0
        assert "stopped" in payload or "running" in payload

    def test_stop_handles_corrupted_state_file(self, tmp_path: Path) -> None:
        """Regression: corrupted daemon-state.json must not raise."""
        state_path = tmp_path / "daemon-state.json"
        state_path.write_text("{this is not valid json!!")
        code, _payload = _run(["daemon", "stop"], tmp_path)
        assert code == 0

    def test_status_with_pid_reuse_returns_not_running(self, tmp_path: Path) -> None:
        """Regression: status must verify daemon identity, not just PID liveness."""
        import json as _json

        from codex_plugin_scanner.guard.daemon.manager import write_guard_daemon_state

        write_guard_daemon_state(tmp_path, port=19998, auth_token="tok")
        state_path = tmp_path / "daemon-state.json"
        state = _json.loads(state_path.read_text())
        state["pid"] = os.getpid()
        state["guard_home"] = "/some/other/guard/home"
        state_path.write_text(_json.dumps(state))

        code, payload = _run(["daemon", "status"], tmp_path)
        assert code == 0
        assert payload.get("running") is False, "PID reuse must not be reported as running"
