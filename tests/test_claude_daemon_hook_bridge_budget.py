"""Timeout budget tests for the Claude daemon hook bridge."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge


def test_bridge_timeouts_stay_under_harness_budget() -> None:
    assert bridge._HARNESS_TIMEOUT_BUDGET_SECONDS == 10
    assert 0 < bridge._HOOK_DEADLINE_SECONDS < bridge._HARNESS_TIMEOUT_BUDGET_SECONDS
    assert bridge._DAEMON_IO_TIMEOUT_SECONDS <= bridge._HOOK_DEADLINE_SECONDS
    assert bridge._RECOVERY_TIMEOUT_SECONDS <= bridge._HOOK_DEADLINE_SECONDS
    assert bridge._FALLBACK_TIMEOUT_SECONDS <= bridge._HOOK_DEADLINE_SECONDS
    assert bridge._DAEMON_IO_TIMEOUT_SECONDS + bridge._FALLBACK_RESERVE_SECONDS < bridge._HOOK_DEADLINE_SECONDS
    leftover = (
        bridge._HOOK_DEADLINE_SECONDS
        - bridge._DAEMON_IO_TIMEOUT_SECONDS
        - bridge._FALLBACK_RESERVE_SECONDS
    )
    assert 0 < bridge._MINIMUM_RECOVERY_SECONDS <= bridge._RECOVERY_TIMEOUT_SECONDS
    assert leftover < bridge._MINIMUM_RECOVERY_SECONDS


def test_daemon_timeout_without_a_recovery_window_uses_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # The first daemon request already spent its whole IO budget. The leftover
    # is shorter than the recovery minimum, so no recovery process starts.
    deadline = time.monotonic() + bridge._HOOK_DEADLINE_SECONDS - bridge._DAEMON_IO_TIMEOUT_SECONDS
    seen: dict[str, float | None] = {}

    def fake_recover(command: tuple[str, ...], *, deadline: float | None = None, failure_kind: str = "") -> bool:
        del command, failure_kind
        seen["recovery"] = deadline
        return True

    def fake_post(endpoint: str, data: str, *, state_path: str | Path, deadline: float | None = None) -> str:
        del endpoint, data, state_path
        seen["retry"] = deadline
        raise TimeoutError("Guard daemon hook request exhausted its absolute deadline")

    def fake_fallback(reason: str, data: str, command: tuple[str, ...], *, deadline: float | None = None) -> str:
        del reason, command
        seen["fallback"] = deadline
        return data

    monkeypatch.setattr(bridge, "_run_recovery_command", fake_recover)
    monkeypatch.setattr(bridge, "_daemon_url", lambda state_path, fallback: "http://127.0.0.1:5474")
    monkeypatch.setattr(bridge, "_post_to_loopback_daemon", fake_post)
    monkeypatch.setattr(bridge, "_run_local_fallback", fake_fallback)

    assert (
        bridge._recover_retry_or_fallback(
            "daemon timed out",
            "{}",
            state_path=tmp_path / "daemon-state.json",
            fallback_daemon_url="http://127.0.0.1:5474",
            fallback_command=("fallback",),
            recovery_command=("recover",),
            query="guard-home=/tmp/guard-home",
            deadline=deadline,
        )
        == "{}"
    )

    assert seen == {"fallback": deadline}


def test_recovery_still_runs_when_its_window_can_finish(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    deadline = time.monotonic() + bridge._FALLBACK_RESERVE_SECONDS + bridge._MINIMUM_RECOVERY_SECONDS + 1.0
    seen: dict[str, float | None] = {}

    def fake_recover(command: tuple[str, ...], *, deadline: float | None = None, failure_kind: str = "") -> bool:
        del command, failure_kind
        seen["recovery"] = deadline
        return False

    def fake_fallback(reason: str, data: str, command: tuple[str, ...], *, deadline: float | None = None) -> str:
        del reason, command
        seen["fallback"] = deadline
        return data

    monkeypatch.setattr(bridge, "_run_recovery_command", fake_recover)
    monkeypatch.setattr(bridge, "_run_local_fallback", fake_fallback)

    assert (
        bridge._recover_retry_or_fallback(
            "daemon timed out",
            "{}",
            state_path=tmp_path / "daemon-state.json",
            fallback_daemon_url="http://127.0.0.1:5474",
            fallback_command=("fallback",),
            recovery_command=("recover",),
            query="guard-home=/tmp/guard-home",
            deadline=deadline,
        )
        == "{}"
    )

    assert seen["recovery"] == deadline - bridge._FALLBACK_RESERVE_SECONDS
    assert seen["fallback"] == deadline
