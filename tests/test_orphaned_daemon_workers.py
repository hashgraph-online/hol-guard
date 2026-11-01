"""Detached hook workers must die with the daemon that spawned them.

The native runtime selects and stops the orphaned workers; its tests cover the
process-table parsing, the ancestry rules and the signal sequence. These tests
pin when the daemon manager asks for a reap and what it sends.
"""

from __future__ import annotations

import os
import time

import pytest

from codex_plugin_scanner.guard.daemon import manager
from codex_plugin_scanner.guard.mdm import runtime_request


def _record_requests(monkeypatch: pytest.MonkeyPatch) -> list[tuple[tuple[object, ...], dict[str, object]]]:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def fake_answer(*args: object, **kwargs: object) -> dict[str, object]:
        feature, command, request = args
        built = request() if callable(request) else request
        calls.append(((feature, command, built), kwargs))
        return {"listed": True, "selected": [], "signalled": [], "forced": []}

    monkeypatch.setattr(runtime_request, "runtime_answer", fake_answer)
    return calls


def test_replacement_start_reaps_orphaned_workers_before_choosing_a_port(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    monkeypatch.setattr(manager, "_live_or_newer_daemon_url", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(manager, "_schedule_stale_ephemeral_guard_daemon_reap", lambda **_kwargs: None)
    monkeypatch.setattr(manager, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(manager, "_adopt_existing_guard_daemon", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(manager, "_load_state", lambda _home: None)
    monkeypatch.setattr(manager, "_guard_daemon_start_in_progress", lambda _home: False)
    monkeypatch.setattr(manager, "clear_guard_daemon_state", lambda _home: order.append("clear"))
    monkeypatch.setattr(manager, "reap_orphaned_daemon_workers", lambda **_kwargs: order.append("reap"))
    monkeypatch.setattr(
        manager,
        "_candidate_ports",
        lambda *_args, **_kwargs: order.append("ports") or [],
    )
    home = tmp_path / "home"
    guard_home = home / ".hol-guard"
    home.mkdir()
    guard_home.mkdir()

    with pytest.raises(RuntimeError, match="approval center did not start"):
        manager.ensure_guard_daemon(guard_home, home_dir=home, start_timeout=1)

    assert order == ["clear", "reap", "ports"]


def test_daemon_retirement_reaps_orphaned_workers(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[bool] = []
    monkeypatch.setattr(manager, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
    monkeypatch.setattr(manager, "load_authenticated_daemon_state", lambda _home: None)
    monkeypatch.setattr(manager, "load_authenticated_guard_daemon_pending_launch", lambda _home: None)
    monkeypatch.setattr(manager, "reap_orphaned_daemon_workers", lambda **_kwargs: seen.append(True))

    assert manager.retire_all_guard_daemons_for_home(tmp_path / "guard-home") == []
    assert seen == [True]


@pytest.mark.skipif(os.name == "nt", reason="hook workers are reaped on POSIX only")
def test_reap_asks_the_runtime_with_the_caller_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _record_requests(monkeypatch)
    monkeypatch.setattr(manager.time, "monotonic", lambda: 100.0)

    manager.reap_orphaned_daemon_workers()

    # Without a caller deadline the status check and the reap share one timeout.
    assert calls == [
        (
            (
                "native-orphaned-worker-reap-v1",
                "orphaned-worker-reap",
                {"schema": "orphaned-worker-reap.v1", "self_pid": os.getpid(), "budget_ms": 14750},
            ),
            {
                "output_limit": manager._ORPHAN_REAP_OUTPUT_LIMIT,
                "deadline": 100.0 + manager._ORPHAN_REAP_TIMEOUT_SECONDS,
            },
        )
    ]


@pytest.mark.skipif(os.name == "nt", reason="hook workers are reaped on POSIX only")
def test_reap_sizes_the_budget_after_the_status_check(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [100.0]
    monkeypatch.setattr(manager.time, "monotonic", lambda: clock[0])
    built: list[object] = []

    def slow_status_answer(*args: object, **_kwargs: object) -> None:
        clock[0] += 1.5
        request = args[2]
        assert callable(request)
        built.append(request())

    monkeypatch.setattr(runtime_request, "runtime_answer", slow_status_answer)

    manager.reap_orphaned_daemon_workers(deadline=102.0)

    assert built == [{"schema": "orphaned-worker-reap.v1", "self_pid": os.getpid(), "budget_ms": 250}]


@pytest.mark.skipif(os.name == "nt", reason="hook workers are reaped on POSIX only")
def test_reap_hands_the_runtime_what_is_left_of_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _record_requests(monkeypatch)
    monkeypatch.setattr(manager.time, "monotonic", lambda: 100.0)

    manager.reap_orphaned_daemon_workers(deadline=102.0)

    ((_feature, _command, request), options) = calls[0]
    assert request == {"schema": "orphaned-worker-reap.v1", "self_pid": os.getpid(), "budget_ms": 1750}
    assert options["deadline"] == 102.0


@pytest.mark.parametrize("remaining", [-1.0, 0.0, manager._ORPHAN_REAP_LAUNCH_RESERVE_SECONDS])
def test_reap_returns_when_the_deadline_leaves_no_budget(monkeypatch: pytest.MonkeyPatch, remaining: float) -> None:
    calls = _record_requests(monkeypatch)

    manager.reap_orphaned_daemon_workers(deadline=time.monotonic() + remaining)

    assert calls == []


def test_runtime_answer_builds_a_callable_request_after_the_status_check(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import native_runtime

    order: list[str] = []
    sent: list[str] = []

    def status(**_kwargs: object) -> SimpleNamespace:
        order.append("status")
        return SimpleNamespace(
            available=True,
            compatible=True,
            identity=SimpleNamespace(path="/runtime"),
            capabilities=SimpleNamespace(features=("feature",)),
        )

    def run(_path: str, _args: tuple[str, ...], *, input_text: str, **_kwargs: object) -> str:
        sent.append(input_text)
        return '{"ok": true}'

    monkeypatch.setattr(native_runtime, "native_runtime_status", status)
    monkeypatch.setattr(native_runtime, "_run_native_process", run)

    def build() -> dict[str, object]:
        order.append("build")
        return {"a": 1}

    answer = runtime_request.runtime_answer("feature", "command", build, output_limit=64, timeout_seconds=1.0)

    assert answer == {"ok": True}
    assert order == ["status", "build"]
    assert sent == ['{"a": 1}']
    assert (
        runtime_request.runtime_answer("feature", "command", lambda: None, output_limit=64, timeout_seconds=1.0) is None
    )
    assert sent == ['{"a": 1}']
