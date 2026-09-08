from __future__ import annotations

import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.daemon import hook_process_entrypoint as hook_entrypoint_module
from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner
from codex_plugin_scanner.guard.daemon.hook_process_worker import HookProcessReview, HookWorkerSlot
from codex_plugin_scanner.guard.native_route_receipt import (
    record_native_hook_route,
    reset_native_hook_route,
)


def test_route_receipt_requires_a_current_native_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hook_entrypoint_module, "_native_mode_requires_rust", lambda: True)
    reset_native_hook_route()
    assert hook_entrypoint_module._current_decision_route() == "native_fail_safe"  # pyright: ignore[reportPrivateUsage]

    record_native_hook_route("native_resident")
    assert hook_entrypoint_module._current_decision_route() == "native_resident"  # pyright: ignore[reportPrivateUsage]

    reset_native_hook_route()
    assert hook_entrypoint_module._current_decision_route() == "native_fail_safe"  # pyright: ignore[reportPrivateUsage]

    monkeypatch.setattr(hook_entrypoint_module, "_native_mode_requires_rust", lambda: False)
    assert hook_entrypoint_module._current_decision_route() == "python_semantic"  # pyright: ignore[reportPrivateUsage]


def test_route_receipt_waits_for_metrics_lock(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    runner._metrics_lock.acquire()  # pyright: ignore[reportPrivateUsage]
    thread = threading.Thread(
        target=runner._record_route_metric,  # pyright: ignore[reportPrivateUsage]
        args=("native_resident",),
    )
    try:
        thread.start()
        thread.join(timeout=0.05)
        assert thread.is_alive()
    finally:
        runner._metrics_lock.release()  # pyright: ignore[reportPrivateUsage]
        thread.join(timeout=1)

    assert runner.stats()["routes"] == {"native_resident": 1}


def test_null_payload_records_attached_fail_safe_route(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=1)
    runner._started = True  # pyright: ignore[reportPrivateUsage]
    process = MagicMock()
    process.pid = 4242
    process.is_alive.return_value = True
    connection = MagicMock()
    connection.poll.return_value = True
    connection.recv.return_value = (
        "result",
        {
            "payload": None,
            "reason_code": "native_post_tool_unavailable",
            "route": "native_fail_safe",
        },
    )
    runner._slots.put_nowait(HookWorkerSlot(process=process, connection=connection))  # pyright: ignore[reportPrivateUsage]
    runner._ready_slot_ids.add(process.pid)  # pyright: ignore[reportPrivateUsage]

    result = runner.review(
        payload={"hook_event_name": "SessionStart"},
        harness="pi",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        hook_env={},
        deadline=time.monotonic() + 1,
    )

    assert result == HookProcessReview(None, "native_post_tool_unavailable")
    assert runner.stats()["routes"] == {"native_fail_safe": 1}
