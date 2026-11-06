"""The hook's evidence runs behind its answer, in order, and never silently."""

from __future__ import annotations

import threading
from types import SimpleNamespace

from codex_plugin_scanner.guard.daemon.hook_evidence_dispatch import (
    HookEvidenceDispatch,
    run_hook_evidence,
)


def test_evidence_is_submitted_in_the_order_the_hooks_left_it() -> None:
    dispatch = HookEvidenceDispatch()
    recorded: list[int] = []
    try:
        for index in range(50):
            dispatch.run(lambda index=index: recorded.append(index))
        assert dispatch.flush(timeout_seconds=5.0)
    finally:
        assert dispatch.stop(timeout_seconds=5.0)
    assert recorded == list(range(50))


def test_work_runs_off_the_calling_thread() -> None:
    dispatch = HookEvidenceDispatch()
    threads: list[int] = []
    try:
        dispatch.run(lambda: threads.append(threading.get_ident()))
        assert dispatch.flush(timeout_seconds=5.0)
    finally:
        assert dispatch.stop(timeout_seconds=5.0)
    assert threads and threads[0] != threading.get_ident()


def test_a_full_dispatch_drops_the_record_rather_than_overtaking_the_queue() -> None:
    dispatch = HookEvidenceDispatch(max_pending=1)
    held = threading.Event()
    released = threading.Event()
    recorded: list[str] = []
    try:
        dispatch.run(lambda: (held.set(), released.wait(5.0)))
        assert held.wait(5.0)
        dispatch.run(lambda: recorded.append("queued"))
        # The worker is held and the one queue slot is taken. Running this
        # record here would put it in front of the queued one, which is how a
        # post event comes to be written before its own pre event.
        dispatch.run(lambda: recorded.append("dropped"))
        assert recorded == []
    finally:
        released.set()
        assert dispatch.stop(timeout_seconds=5.0)
    assert recorded == ["queued"]


def test_a_stopped_dispatch_still_records_what_it_is_given() -> None:
    dispatch = HookEvidenceDispatch()
    assert dispatch.stop(timeout_seconds=5.0)
    recorded: list[str] = []
    dispatch.run(lambda: recorded.append("late"))
    assert recorded == ["late"]


def test_evidence_that_raises_never_reaches_the_caller() -> None:
    dispatch = HookEvidenceDispatch()
    reached: list[str] = []

    def explode() -> None:
        raise RuntimeError("the resident refused")

    try:
        dispatch.run(explode)
        dispatch.run(lambda: reached.append("after"))
        assert dispatch.flush(timeout_seconds=5.0)
    finally:
        assert dispatch.stop(timeout_seconds=5.0)
    assert reached == ["after"]


def test_a_host_without_a_dispatch_runs_the_work_inline() -> None:
    recorded: list[str] = []
    run_hook_evidence(SimpleNamespace(), lambda: recorded.append("inline"))
    run_hook_evidence(SimpleNamespace(evidence_dispatch=None), lambda: recorded.append("none"))
    assert recorded == ["inline", "none"]


def test_a_host_with_a_dispatch_hands_the_work_to_it() -> None:
    dispatch = HookEvidenceDispatch()
    threads: list[int] = []
    try:
        run_hook_evidence(
            SimpleNamespace(evidence_dispatch=dispatch),
            lambda: threads.append(threading.get_ident()),
        )
        assert dispatch.flush(timeout_seconds=5.0)
    finally:
        assert dispatch.stop(timeout_seconds=5.0)
    assert threads and threads[0] != threading.get_ident()
