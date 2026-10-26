"""Process inventory must distinguish reader scheduling lag from unavailable output."""

from __future__ import annotations

import io
import threading
import time

from codex_plugin_scanner.guard.daemon import manager


class CompletedQuery:
    pid = None
    returncode = 0

    def __init__(self) -> None:
        self.stdout = io.BytesIO(b"verified inventory\n")

    def poll(self) -> int | None:
        return 0

    def wait(self, *, timeout: float) -> int:
        return 0


def test_completed_query_accepts_reader_lag_within_original_deadline(monkeypatch):
    query = CompletedQuery()
    gate = threading.Event()
    readers: list[threading.Thread] = []
    capture = manager._capture_bounded_process_query_stdout

    def delayed_capture(*args):
        readers.append(threading.current_thread())
        gate.wait()
        capture(*args)

    monkeypatch.setattr(manager, "_spawn_bounded_process_query", lambda _command: query)
    monkeypatch.setattr(manager, "_capture_bounded_process_query_stdout", delayed_capture)
    release = threading.Timer(1.0, gate.set)
    release.start()
    try:
        assert manager._bounded_process_query_stdout(["fixture-query"], timeout_seconds=5.0) == "verified inventory\n"
    finally:
        gate.set()
        release.cancel()
        release.join()
        for reader in readers:
            reader.join(timeout=1.0)


def test_completed_query_rejects_reader_that_misses_original_deadline(monkeypatch):
    query = CompletedQuery()
    gate = threading.Event()
    readers: list[threading.Thread] = []
    capture = manager._capture_bounded_process_query_stdout

    def delayed_capture(*args):
        readers.append(threading.current_thread())
        gate.wait()
        capture(*args)

    monkeypatch.setattr(manager, "_spawn_bounded_process_query", lambda _command: query)
    monkeypatch.setattr(manager, "_capture_bounded_process_query_stdout", delayed_capture)
    started = time.monotonic()
    try:
        assert manager._bounded_process_query_stdout(["fixture-query"], timeout_seconds=0.05) is None
        assert time.monotonic() - started < 2.0
    finally:
        gate.set()
        for reader in readers:
            reader.join(timeout=1.0)


def test_expired_query_remains_rejected_when_child_and_reader_finish(monkeypatch):
    class QueryExitedAfterTimeout(CompletedQuery):
        polls = 0

        def poll(self) -> int | None:
            self.polls += 1
            return None if self.polls == 1 else 0

    class ReaderFinishesOnJoin:
        def __init__(self, *, target, args, **_kwargs):
            self.target = target
            self.args = args
            self.alive = True

        def start(self):
            pass

        def is_alive(self):
            return self.alive

        def join(self, *, timeout):
            if self.alive:
                self.target(*self.args)
                self.alive = False

    query = QueryExitedAfterTimeout()
    clock = iter((0.0, 1.0))
    monkeypatch.setattr(manager, "_spawn_bounded_process_query", lambda _command: query)
    monkeypatch.setattr(manager.time, "monotonic", lambda: next(clock, 1.0))
    monkeypatch.setattr(manager.threading, "Thread", ReaderFinishesOnJoin)

    assert manager._bounded_process_query_stdout(["fixture-query"], timeout_seconds=0.05) is None
