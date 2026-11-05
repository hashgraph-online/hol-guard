# pyright: reportPrivateUsage=false
"""Publisher shutdown must confirm thread exit before releasing ownership."""

from __future__ import annotations

import threading
from pathlib import Path

import codex_plugin_scanner.guard.native_policy_snapshot as snapshots
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore


def test_publisher_close_retries_join_and_retains_live_thread(tmp_path: Path) -> None:
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "guard-home"))
    entered = threading.Event()
    release = threading.Event()

    def blocked_publication() -> None:
        entered.set()
        release.wait(timeout=10)

    thread = threading.Thread(target=blocked_publication)
    publisher._thread = thread
    key = snapshots._publisher_key(publisher.guard_home)
    thread.start()
    try:
        assert entered.wait(timeout=1)
        assert publisher.close_contained(timeout_seconds=0) is False
        assert publisher.closed is True
        assert thread.is_alive()
        with snapshots._PUBLISHER_LOCK:
            assert publisher in snapshots._PUBLISHERS[key]
        assert publisher.close_contained(timeout_seconds=0) is False
    finally:
        release.set()
        assert publisher.close_contained(timeout_seconds=1) is True
        thread.join(timeout=1)
    assert not thread.is_alive()
    with snapshots._PUBLISHER_LOCK:
        assert publisher not in snapshots._PUBLISHERS.get(key, ())
    assert publisher.close_contained(timeout_seconds=0) is True


def test_publisher_close_cancels_native_helpers_mid_pass(tmp_path: Path, monkeypatch) -> None:
    """Close must not wait out a reconcile pass that is running native helpers.

    On Windows one pass starts many native helper processes and can run for
    several seconds, longer than the daemon's one-second shutdown budget.
    """

    import codex_plugin_scanner.guard.native_policy_snapshot_publication as publication
    import codex_plugin_scanner.guard.native_runtime as native_runtime
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult

    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "guard-home"))
    helper_running = threading.Event()
    helpers_started: list[str] = []

    def fake_helper_process(argv, *, stop_event=None, **_kwargs) -> BoundedHookProcessResult:
        helpers_started.append(argv[1])
        helper_running.set()
        # A real helper is killed when stop_event is set; without one it runs
        # to completion, which is the multi-second Windows pass.
        if stop_event is None or not stop_event.wait(timeout=5):
            threading.Event().wait(timeout=5)
        return BoundedHookProcessResult(returncode=None, stdout="", output_limit_exceeded=False, timed_out=False)

    def reconcile_with_helpers(_publisher) -> None:
        for name in ("first", "second", "third"):
            assert (
                native_runtime._run_native_process(
                    Path("hol-guard-runtime"), (name,), input_text="", timeout_seconds=30
                )
                is None
            )

    monkeypatch.setattr(native_runtime, "run_isolated_hook_process", fake_helper_process)
    monkeypatch.setattr(publication, "reconcile_policy_inputs", reconcile_with_helpers)
    thread = threading.Thread(target=publisher._run, daemon=True)
    publisher._thread = thread
    thread.start()
    assert helper_running.wait(timeout=2)

    assert publisher.close_contained(timeout_seconds=1) is True
    assert not thread.is_alive()
    assert helpers_started == ["first"]


def test_runtime_answer_skips_status_and_process_once_stopped(monkeypatch) -> None:
    import codex_plugin_scanner.guard.native_runtime as native_runtime
    from codex_plugin_scanner.guard.mdm.runtime_request import runtime_answer
    from codex_plugin_scanner.guard.native_process_stop_scope import native_process_stop_scope

    def unexpected(*_args, **_kwargs):
        raise AssertionError("a stopped scope must not hash or start the native runtime")

    monkeypatch.setattr(native_runtime, "native_runtime_status", unexpected)
    monkeypatch.setattr(native_runtime, "_run_native_process", unexpected)
    stopped = threading.Event()
    stopped.set()
    with native_process_stop_scope(stopped):
        assert runtime_answer("feature", "command", {}, output_limit=1024) is None
