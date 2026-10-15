"""The Codex bridge keeps asking a daemon whose start has not settled."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_dead_fastpath as fastpath
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge_flow as bridge_flow
from codex_plugin_scanner.guard.adapters import codex_daemon_start_wait as start_wait

_ALLOW = {"hookSpecificOutput": {"permissionDecision": "allow"}}


def _guard_home(tmp_path: Path) -> Path:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    return guard_home


def _mark_start(guard_home: Path, name: str = "daemon-recovery-reservation.json", *, age: float = 0.0) -> Path:
    marker = guard_home / name
    marker.write_text(json.dumps({"created_at": time.time(), "token": "t"}), encoding="utf-8")
    if age:
        stamp = time.time() - age
        os.utime(marker, (stamp, stamp))
    return marker


class _Daemon:
    """Fails with the queued errors, then answers."""

    def __init__(self, errors: list[BaseException], on_call=None) -> None:
        self.errors = errors
        self.calls = 0
        self.on_call = on_call

    def __call__(self, **kwargs: object) -> dict[str, object]:
        del kwargs
        self.calls += 1
        if self.on_call is not None:
            self.on_call(self.calls)
        if self.errors:
            raise self.errors.pop(0)
        return dict(_ALLOW)


def _review(guard_home: Path, monkeypatch: pytest.MonkeyPatch, daemon: _Daemon, *, started: bool, seconds: float = 30):
    fallbacks: list[object] = []

    def fallback(**kwargs: object) -> None:
        fallbacks.append(kwargs)
        return None

    monkeypatch.setattr(bridge_flow, "_daemon_response", daemon)
    monkeypatch.setattr(bridge_flow, "_trusted_launch_for_fallback", lambda **_: (None, False))
    monkeypatch.setattr(bridge_flow, "_daemon_start_succeeded", lambda **_: started)
    monkeypatch.setattr(bridge_flow, "_fallback_response", fallback)
    monkeypatch.setattr(start_wait.time, "sleep", lambda _seconds: None)
    causes: list[bridge_flow.BridgeFailureCause] = []
    result = bridge_flow.bridge_review_response(
        state_path=guard_home / "daemon-state.json",
        fallback_command=[sys.executable, "-c", "pass"],
        start_command=[sys.executable, "-c", "pass"],
        query="",
        data="{}",
        deadline=time.monotonic() + seconds,
        manifest_path=None,
        config_json=None,
        failure_causes=causes,
    )
    return result, fallbacks, causes


@pytest.mark.parametrize(
    "marker",
    ["daemon-recovery-reservation.json", "daemon-start-progress.json", "daemon-launch-pending.json"],
)
def test_waits_for_a_starting_daemon_instead_of_denying(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, marker: str
) -> None:
    guard_home = _guard_home(tmp_path)
    _mark_start(guard_home, marker)
    daemon = _Daemon(
        [
            ConnectionRefusedError("down"),
            ValueError("daemon state is unavailable"),
            ConnectionRefusedError("down"),
            ValueError("daemon state records a stopped daemon"),
        ]
    )

    (response, overloaded, integrity_failed), fallbacks, _causes = _review(
        guard_home, monkeypatch, daemon, started=True
    )

    assert response == _ALLOW
    assert (overloaded, integrity_failed) == (False, False)
    assert daemon.calls == 5
    assert fallbacks == []


def test_start_command_timeout_still_waits_while_a_launch_is_in_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = _guard_home(tmp_path)
    _mark_start(guard_home)
    daemon = _Daemon([ConnectionRefusedError("down"), ConnectionRefusedError("down")])

    (response, _, _), fallbacks, _causes = _review(guard_home, monkeypatch, daemon, started=False)

    assert response == _ALLOW
    assert daemon.calls == 3
    assert fallbacks == []


def test_without_a_launch_marker_the_bridge_retries_once_then_falls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = _guard_home(tmp_path)
    daemon = _Daemon([ConnectionRefusedError("down")] * 5)

    (response, _, _), fallbacks, causes = _review(guard_home, monkeypatch, daemon, started=True)

    assert response is None
    assert daemon.calls == 2
    assert len(fallbacks) == 1
    assert [cause["stage"] for cause in causes][:2] == ["daemon_request", "daemon_retry"]


def test_failed_start_without_a_launch_marker_does_not_ask_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = _guard_home(tmp_path)
    daemon = _Daemon([ConnectionRefusedError("down")] * 5)

    (response, _, _), fallbacks, _causes = _review(guard_home, monkeypatch, daemon, started=False)

    assert response is None
    assert daemon.calls == 1
    assert len(fallbacks) == 1


@pytest.mark.parametrize(
    "error",
    [
        bridge_flow._DaemonResponseError(403, "{}", authenticated=True),
        bridge_flow._DaemonResponseError(503, "{}", authenticated=False),
        TimeoutError("slow"),
        ValueError("daemon state authentication failed"),
    ],
)
def test_only_not_yet_up_failures_are_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    guard_home = _guard_home(tmp_path)
    _mark_start(guard_home)
    daemon = _Daemon([ConnectionRefusedError("down"), error, ConnectionRefusedError("down")])

    (response, _, _), _fallbacks, _causes = _review(guard_home, monkeypatch, daemon, started=True)

    assert response is None
    assert daemon.calls == 2


def test_waiting_stops_when_the_launch_settles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = _guard_home(tmp_path)
    marker = _mark_start(guard_home)

    def settle(call: int) -> None:
        if call == 3:
            marker.write_text("{}", encoding="utf-8")

    daemon = _Daemon([ConnectionRefusedError("down")] * 10, on_call=settle)

    (response, _, _), fallbacks, _causes = _review(guard_home, monkeypatch, daemon, started=True)

    assert response is None
    assert daemon.calls == 3
    assert len(fallbacks) == 1


def test_a_stale_launch_marker_does_not_extend_the_wait(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = _guard_home(tmp_path)
    _mark_start(guard_home, age=fastpath.DAEMON_START_MARKER_WINDOW_SECONDS + 5)
    daemon = _Daemon([ConnectionRefusedError("down")] * 10)

    (response, _, _), _fallbacks, _causes = _review(guard_home, monkeypatch, daemon, started=True)

    assert response is None
    assert daemon.calls == 2


def test_the_wait_leaves_the_fallback_its_turn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = _guard_home(tmp_path)
    _mark_start(guard_home)
    daemon = _Daemon([ConnectionRefusedError("down")] * 10)

    (response, _, _), fallbacks, _causes = _review(
        guard_home,
        monkeypatch,
        daemon,
        started=True,
        seconds=bridge_flow._FALLBACK_TIMEOUT_SECONDS + 0.1,
    )

    assert response is None
    assert daemon.calls == 2
    assert len(fallbacks) == 1


@pytest.mark.skipif(os.name == "nt", reason="the dead-daemon fast path is POSIX-only")
def test_a_start_in_progress_is_not_recorded_as_a_failed_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = _guard_home(tmp_path)
    _mark_start(guard_home)
    # No state yet, so the daemon looks dead; the launch marker says it is starting.
    daemon = _Daemon([ConnectionRefusedError("down")] * 10)
    _review(guard_home, monkeypatch, daemon, started=True, seconds=bridge_flow._FALLBACK_TIMEOUT_SECONDS + 0.1)

    assert not fastpath.recent_start_failure(guard_home / "daemon-state.json")


def test_unparseable_or_empty_markers_do_not_count(tmp_path: Path) -> None:
    guard_home = _guard_home(tmp_path)
    state_path = guard_home / "daemon-state.json"
    (guard_home / "daemon-recovery-reservation.json").write_text("{}", encoding="utf-8")
    (guard_home / "daemon-start-progress.json").write_text("not json", encoding="utf-8")
    (guard_home / "daemon-launch-pending.json").write_text("[1]", encoding="utf-8")

    assert not fastpath.daemon_start_in_progress(state_path)
    _mark_start(guard_home, "daemon-launch-pending.json")
    assert fastpath.daemon_start_in_progress(state_path)


def test_only_the_post_start_retry_runs_once_the_fallback_slice_has_begun(tmp_path: Path) -> None:
    guard_home = _guard_home(tmp_path)
    _mark_start(guard_home)
    calls: list[str] = []

    def request(kind: str):
        def call() -> dict[str, object]:
            calls.append(kind)
            raise ConnectionRefusedError("down")

        return call

    for started in (True, False):
        with pytest.raises(ConnectionRefusedError) if started else contextlib.nullcontext():
            result = start_wait.await_started_daemon(
                state_path=guard_home / "daemon-state.json",
                stop_at=time.monotonic() - 1,
                first_request=request("first"),
                request=request("poll"),
                started=started,
                failure_reason=lambda _error: "daemon_connection_refused",
            )
            assert result is None

    assert calls == ["first"]


def test_a_wait_request_cannot_spend_the_fallback_window(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = _guard_home(tmp_path)
    _mark_start(guard_home)
    timeouts: list[float] = []

    class _Recording(_Daemon):
        def __call__(self, **kwargs: object) -> dict[str, object]:
            timeout = kwargs.get("timeout_seconds")
            assert isinstance(timeout, (int, float))
            timeouts.append(float(timeout))
            return super().__call__(**kwargs)

    budget = 0.6
    daemon = _Recording([ConnectionRefusedError("down"), ConnectionRefusedError("down")])
    (response, _, _), fallbacks, _causes = _review(
        guard_home,
        monkeypatch,
        daemon,
        started=True,
        seconds=bridge_flow._FALLBACK_TIMEOUT_SECONDS + budget,
    )

    assert response == _ALLOW
    assert fallbacks == []
    assert len(timeouts) == 3
    # The first ask and the post-start retry keep the full hook deadline;
    # the poll that follows stays inside the window before the fallback.
    assert timeouts[1] > budget
    assert timeouts[2] <= budget


@pytest.mark.skipif(os.name == "nt", reason="the dead-daemon fast path is POSIX-only")
def test_a_fresh_launch_is_not_denied_by_an_older_start_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = _guard_home(tmp_path)
    state_path = guard_home / "daemon-state.json"
    fastpath.record_start_failure(state_path)
    _mark_start(guard_home)
    daemon = _Daemon([ConnectionRefusedError("down")])

    (response, _, _), fallbacks, causes = _review(guard_home, monkeypatch, daemon, started=True)

    assert response == _ALLOW
    assert fallbacks == []
    assert daemon.calls == 2
    assert not any(cause["stage"] == "daemon_dead_fast" for cause in causes)


def test_a_marker_older_than_live_daemon_state_does_not_extend_the_wait(tmp_path: Path) -> None:
    guard_home = _guard_home(tmp_path)
    state_path = guard_home / "daemon-state.json"
    marker = _mark_start(guard_home, "daemon-start-progress.json", age=10)
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
