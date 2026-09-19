from __future__ import annotations

import multiprocessing
import os
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_control_runtime as runtime_control
from codex_plugin_scanner.guard import native_policy_control_transport as transport
from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.native_policy_publication_lock import hold_policy_publication_mutation
from tests.test_native_policy_control_runtime import _fixture


def _lock_competitor(home: str, channel) -> None:
    channel.send("ready")
    while channel.recv() == "try":
        try:
            with hold_policy_publication_mutation(Path(home), timeout_seconds=0.04):
                channel.send(True)
        except TimeoutError:
            channel.send(False)


@pytest.mark.skipif(os.name == "nt", reason="actual helper uses a POSIX shell")
def test_actual_selection_and_control_share_one_owned_slot(tmp_path, monkeypatch):
    binary, _ = _fixture(tmp_path, monkeypatch)
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(transport, "_CONTROL_SLOTS", slots)
    observed = []
    deadline = time.monotonic() + 1

    def run(cancelled):
        status = runtime_control._native_policy_control_runtime_status_owned(
            cancelled=cancelled, deadline_monotonic=deadline
        )
        assert status.compatible
        observed.append(status)
        binary.write_text("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{\"ok\":true}'\n")
        binary.chmod(0o700)
        return transport._native_policy_control_request_owned(
            executable=binary,
            guard_home=tmp_path,
            environment=os.environ,
            payload=b'{"request":true}',
            deadline_monotonic=deadline,
            cancelled=cancelled,
        )

    assert transport.run_native_control_worker(run, deadline_monotonic=deadline) == b'{"ok":true}'
    assert len(observed) == 1
    assert slots.acquire(blocking=False)
    slots.release()


def test_cancelled_owned_selection_never_starts_setup(monkeypatch):
    cancelled = threading.Event()
    cancelled.set()
    monkeypatch.setattr(native_runtime, "_runtime_candidates", lambda: pytest.fail("late selection"))
    with pytest.raises(TimeoutError):
        runtime_control._native_policy_control_runtime_status_owned(
            cancelled=cancelled, deadline_monotonic=time.monotonic() + 1
        )


def test_cancelled_owned_control_never_starts_helper(tmp_path, monkeypatch):
    cancelled = threading.Event()
    cancelled.set()
    monkeypatch.setattr(transport, "run_isolated_hook_process", lambda *a, **k: pytest.fail("late dispatch"))
    assert (
        transport._native_policy_control_request_owned(
            executable=tmp_path / "runtime",
            guard_home=tmp_path,
            environment={},
            payload=b"{}",
            deadline_monotonic=time.monotonic() + 1,
            cancelled=cancelled,
        )
        is None
    )


def test_owned_control_passes_the_exact_cancellation_and_deadline(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult

    cancelled = threading.Event()
    deadline = time.monotonic() + 1
    calls = []

    def run(*args, **kwargs):
        calls.append(kwargs)
        return BoundedHookProcessResult(0, "{}\n", False, False)

    monkeypatch.setattr(transport, "run_isolated_hook_process", run)
    assert (
        transport._native_policy_control_request_owned(
            executable=tmp_path / "runtime",
            guard_home=tmp_path,
            environment={},
            payload=b"{}",
            deadline_monotonic=deadline,
            cancelled=cancelled,
        )
        == b"{}"
    )
    assert calls[0]["stop_event"] is cancelled
    assert calls[0]["deadline_monotonic"] == deadline
    assert calls[0]["bound_input_to_deadline"] is True


def test_owner_retains_real_publication_lock_after_caller_timeout(tmp_path, monkeypatch):
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    context = multiprocessing.get_context("spawn")
    parent_channel, child_channel = context.Pipe()
    child = context.Process(target=_lock_competitor, args=(str(home), child_channel))
    child.start()
    assert parent_channel.poll(5) and parent_channel.recv() == "ready"
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(transport, "_CONTROL_SLOTS", slots)

    def run(cancelled):
        try:
            with hold_policy_publication_mutation(home):
                entered.set()
                assert release.wait(2)
                return "late result"
        finally:
            finished.set()

    try:
        assert transport.run_native_control_worker(run, deadline_monotonic=time.monotonic() + 0.04) is None
        assert entered.is_set()
        assert not slots.acquire(blocking=False)
        parent_channel.send("try")
        assert parent_channel.poll(1) and parent_channel.recv() is False
        release.set()
        assert finished.wait(1)
        parent_channel.send("try")
        assert parent_channel.poll(1) and parent_channel.recv() is True
        assert slots.acquire(timeout=1)
        slots.release()
    finally:
        release.set()
        parent_channel.send("stop")
        child.join(2)
        if child.is_alive():
            child.terminate()
            child.join(2)
        parent_channel.close()
        child_channel.close()
