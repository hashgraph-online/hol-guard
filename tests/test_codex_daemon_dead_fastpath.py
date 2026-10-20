"""Fail-fast tests for the Codex bridge when the Guard daemon is provably dead."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from codex_plugin_scanner.guard.adapters._modules.codex import codex_daemon_dead_fastpath as fastpath
from codex_plugin_scanner.guard.adapters._modules.codex.codex_daemon_hook_auth import _DaemonResponseError

_DEAD_PID = 2**22 + 12345


def _state(guard_home: Path, pid: int | None) -> Path:
    path = guard_home / "daemon-state.json"
    if pid is not None:
        path.write_text(json.dumps({"pid": pid, "port": 1}), encoding="utf-8")
    return path


def _dead_pid() -> int:
    pid = _DEAD_PID
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return pid
        except OSError:
            pass
        pid += 1


def _mark_start(guard_home: Path, name: str = "daemon-recovery-reservation.json", *, age: float = 0.0) -> Path:
    marker = guard_home / name
    marker.write_text(json.dumps({"created_at": time.time(), "token": "t"}), encoding="utf-8")
    if age:
        stamp = time.time() - age
        os.utime(marker, (stamp, stamp))
    return marker


def test_missing_state_and_dead_pid_are_provably_dead(tmp_path: Path) -> None:
    assert fastpath.daemon_provably_dead(tmp_path / "daemon-state.json")
    assert fastpath.daemon_provably_dead(_state(tmp_path, _dead_pid()))


def test_tombstone_state_is_provably_dead(tmp_path: Path) -> None:
    state = tmp_path / "daemon-state.json"
    state.write_text("{}", encoding="utf-8")
    assert fastpath.daemon_provably_dead(state)
    state.write_text(json.dumps({"state": {}}), encoding="utf-8")
    assert fastpath.daemon_provably_dead(state)
    fastpath.record_start_failure(state)
    assert fastpath.should_fail_fast(state)


def test_live_pid_and_unreadable_state_are_not_provably_dead(tmp_path: Path) -> None:
    assert not fastpath.daemon_provably_dead(_state(tmp_path, os.getpid()))
    (tmp_path / "daemon-state.json").write_text("{not json", encoding="utf-8")
    assert not fastpath.daemon_provably_dead(tmp_path / "daemon-state.json")


def test_pidless_state_with_other_fields_is_not_provably_dead(tmp_path: Path) -> None:
    state = tmp_path / "daemon-state.json"
    for payload in ({"port": 1234}, {"pid": 0, "port": 1234}, {"state": {"port": 1234}}):
        state.write_text(json.dumps(payload), encoding="utf-8")
        fastpath.record_start_failure(state)
        assert not fastpath.daemon_provably_dead(state)
        assert not fastpath.should_fail_fast(state)


def test_marker_window_expires_and_clears(tmp_path: Path) -> None:
    state = _state(tmp_path, None)
    assert not fastpath.should_fail_fast(state)
    fastpath.record_start_failure(state)
    assert fastpath.should_fail_fast(state)
    later = time.time() + fastpath.FAILED_START_WINDOW_SECONDS + 1
    assert not fastpath.should_fail_fast(state, now=later)
    fastpath.clear_start_failure(state)
    assert not fastpath.should_fail_fast(state)


def test_marker_alone_does_not_fail_fast_when_daemon_is_alive(tmp_path: Path) -> None:
    state = _state(tmp_path, os.getpid())
    fastpath.record_start_failure(state)
    assert not fastpath.should_fail_fast(state)


def test_only_a_restart_circuit_503_is_a_native_runtime_refusal() -> None:
    plain = _DaemonResponseError(503, '{"error": "native_route_policy_unavailable"}', authenticated=False)
    refused = _DaemonResponseError(
        503, '{"error": "x", "reason_code": "native_resident_restart_circuit_open"}', authenticated=False
    )
    wrong_status = _DaemonResponseError(
        500, '{"reason_code": "native_resident_restart_circuit_open"}', authenticated=False
    )
    assert not fastpath.native_runtime_refused(plain)
    assert not fastpath.native_runtime_refused(wrong_status)
    assert not fastpath.native_runtime_refused(ValueError("nope"))
    assert not fastpath.native_runtime_refused(_DaemonResponseError(503, "{nope", authenticated=False))
    assert fastpath.native_runtime_refused(refused)


def test_unparseable_or_empty_markers_do_not_count(tmp_path: Path) -> None:
    state_path = tmp_path / "daemon-state.json"
    (tmp_path / "daemon-recovery-reservation.json").write_text("{}", encoding="utf-8")
    (tmp_path / "daemon-start-progress.json").write_text("not json", encoding="utf-8")
    (tmp_path / "daemon-launch-pending.json").write_text("[1]", encoding="utf-8")

    assert not fastpath.daemon_start_in_progress(state_path)
    _mark_start(tmp_path, "daemon-launch-pending.json")
    assert fastpath.daemon_start_in_progress(state_path)


def test_a_marker_older_than_live_daemon_state_does_not_extend_the_wait(tmp_path: Path) -> None:
    state_path = tmp_path / "daemon-state.json"
    marker = _mark_start(tmp_path, "daemon-start-progress.json", age=10)
    state_path.write_text('{"pid": 1}', encoding="utf-8")

    assert not fastpath.daemon_start_in_progress(state_path)

    # A stopped daemon's tombstone is not a live start, so the marker counts.
    state_path.write_text("{}", encoding="utf-8")
    assert fastpath.daemon_start_in_progress(state_path)

    # A launch newer than the live state is still in progress.
    state_path.write_text('{"pid": 1}', encoding="utf-8")
    stamp = time.time() - 20
    os.utime(state_path, (stamp, stamp))
    os.utime(marker, None)
    assert fastpath.daemon_start_in_progress(state_path)
