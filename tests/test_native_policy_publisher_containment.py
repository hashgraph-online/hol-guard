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

    import sys

    import codex_plugin_scanner.guard.codex_hook_launch_runtime as launch_runtime
    import codex_plugin_scanner.guard.native_policy_snapshot_publication as publication
    import codex_plugin_scanner.guard.native_runtime as native_runtime

    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "guard-home"))
    helper_running = threading.Event()
    spawned: list[object] = []
    real_spawn = launch_runtime._spawn_hook_process

    def counting_spawn(*args, **kwargs):
        spawned.append(args[0])
        result = real_spawn(*args, **kwargs)
        helper_running.set()
        return result

    def reconcile_with_helpers(_publisher) -> None:
        # Each helper would outlive the close budget unless it is killed.
        for _ in range(3):
            native_runtime._run_native_process(
                Path(sys.executable), ("-c", "import time; time.sleep(30)"), input_text="", timeout_seconds=30
            )

    monkeypatch.setattr(launch_runtime, "_spawn_hook_process", counting_spawn)
    monkeypatch.setattr(publication, "reconcile_policy_inputs", reconcile_with_helpers)
    thread = threading.Thread(target=publisher._run, daemon=True)
    publisher._thread = thread
    thread.start()
    assert helper_running.wait(timeout=10)

    assert publisher.close_contained(timeout_seconds=1) is True
    assert not thread.is_alive()
    assert len(spawned) == 1


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


def test_native_publish_stops_when_its_owner_closes(tmp_path: Path, monkeypatch) -> None:
    """A close during the publisher's generation-lock wait must not block in readline."""

    import os
    import time
    from types import SimpleNamespace

    import pytest

    import codex_plugin_scanner.guard.native_policy_snapshot_business_bridge as bridge
    import codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport as transport
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
    from codex_plugin_scanner.guard.native_process_stop_scope import native_process_stop_scope

    if os.name == "nt":
        pytest.skip("the stand-in publisher is a POSIX shell script")
    stand_in = tmp_path / "hol-guard-runtime"
    stand_in.write_text("#!/bin/sh\nexec sleep 30\n")
    stand_in.chmod(0o700)
    status = SimpleNamespace(
        identity=SimpleNamespace(path=stand_in),
        capabilities=SimpleNamespace(features=(transport._PUBLISH_FEATURE,)),
    )
    monkeypatch.setattr(bridge, "_selected_runtime", lambda **_kwargs: status)
    stop = threading.Event()
    threading.Timer(0.3, stop.set).start()
    started = time.monotonic()
    with native_process_stop_scope(stop), pytest.raises(NativePolicySnapshotError) as stopped:
        transport._run_publish(lambda: (bytearray(b"{}\n{}\n"), 60.0), lambda _payload, _timeout: None, business=False)
    assert stopped.value.args[0] == "native_policy_snapshot_runtime_unavailable"
    assert time.monotonic() - started < 5
