"""Foreground interruption succeeds only after confirmed service shutdown."""

from __future__ import annotations

import select
import signal
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.service_lifecycle import start_serve_thread


class ForegroundService:
    """Exercise the real foreground/lifecycle methods with a bounded transport."""

    def __init__(self, *, contained: bool = True, worker_error: BaseException | None = None):
        self._finish_service_lock = threading.Lock()
        self._shutdown_started = threading.Event()
        self._serve_loop_started = threading.Event()
        self._serve_loop_finished = threading.Event()
        self._serve_thread_error = None
        self._active_start_generation = 1
        self._lifecycle_generation = 1
        self._lifecycle_lock = threading.Lock()
        self._thread = None
        self._finish_service_completed = False
        self.contained = contained
        self.worker_error = worker_error
        self.stop_calls = 0
        self.events = []
        self._diagnostics = self

    def _begin_service(self, *, publish_before_workers):
        assert publish_before_workers
        start_serve_thread(self)
        assert self._serve_loop_started.wait(2)

    def _serve_forever(self):
        self._serve_loop_started.set()
        if self.worker_error is not None:
            raise self.worker_error
        assert self._shutdown_started.wait(5), "foreground fixture was not stopped"

    def stop(self):
        self.stop_calls += 1
        self._shutdown_started.set()
        if self._thread is not None:
            self._thread.join(2)
            assert not self._thread.is_alive()
        self._finish_service_completed = self.contained

    def _is_quarantined(self):
        return not self.contained

    def _record_lifecycle(self, event, **metadata):
        self.events.append((event, metadata))

    def record(self, event):
        self.events.append((event, {}))


def test_foreground_interrupt_returns_only_after_containment(monkeypatch):
    service = ForegroundService()
    real_join = threading.Thread.join

    def interrupt_join(thread, timeout=None):
        if timeout is None:
            raise KeyboardInterrupt
        return real_join(thread, timeout)

    real_wait = threading.Event.wait

    def interrupt_foreground_wait(event, timeout=None):
        if event is service._serve_loop_finished and timeout is None:
            raise KeyboardInterrupt
        return real_wait(event, timeout)

    monkeypatch.setattr(threading.Thread, "join", interrupt_join)
    monkeypatch.setattr(threading.Event, "wait", interrupt_foreground_wait)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server.contain_failed_service_start",
        lambda server, error, *, serve_thread_started: server.stop(),
    )
    try:
        try:
            GuardDaemonServer.serve(service)
        except KeyboardInterrupt:
            pytest.fail("confirmed foreground shutdown propagated KeyboardInterrupt")
        assert service.stop_calls == 1
        assert service._finish_service_completed and service._serve_loop_finished.is_set()
        assert ("shutdown_requested", {"reason": "keyboard_interrupt"}) in service.events
    finally:
        service.stop()


def test_foreground_interrupt_does_not_hide_unconfirmed_containment(monkeypatch):
    service = ForegroundService(contained=False)
    real_wait = threading.Event.wait

    def interrupt_wait(event, timeout=None):
        if event is service._serve_loop_finished and timeout is None:
            raise KeyboardInterrupt
        return real_wait(event, timeout)

    monkeypatch.setattr(threading.Event, "wait", interrupt_wait)
    try:
        with pytest.raises(KeyboardInterrupt):
            GuardDaemonServer.serve(service)
        assert service.stop_calls == 1 and not service._finish_service_completed
    finally:
        service.stop()


@pytest.mark.parametrize("failure", [KeyboardInterrupt(), RuntimeError("synthetic serve failure")])
def test_worker_failure_is_propagated_instead_of_treated_as_foreground_interrupt(monkeypatch, failure):
    service = ForegroundService(worker_error=failure)
    contained = []

    def contain(server, error, *, serve_thread_started):
        assert server is service and error is failure and serve_thread_started
        contained.append(error)
        service.stop()

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.server.contain_failed_service_start", contain)
    try:
        with pytest.raises(type(failure)) as raised:
            GuardDaemonServer.serve(service)
        assert raised.value is failure and contained == [failure]
    finally:
        service.stop()


@pytest.mark.parametrize("thread_started", [False, True])
@pytest.mark.parametrize("contained", [True, False])
def test_startup_interrupt_returns_only_after_confirmed_containment(monkeypatch, thread_started, contained):
    service = ForegroundService(contained=contained)
    begin = service._begin_service

    def interrupted_begin(**kwargs):
        if thread_started:
            begin(**kwargs)
        raise KeyboardInterrupt

    monkeypatch.setattr(service, "_begin_service", interrupted_begin)
    try:
        if contained:
            try:
                GuardDaemonServer.serve(service)
            except KeyboardInterrupt:
                pytest.fail("confirmed startup containment propagated KeyboardInterrupt")
        else:
            with pytest.raises(KeyboardInterrupt):
                GuardDaemonServer.serve(service)
        assert service.stop_calls == 1
        assert service._finish_service_completed == contained
        if thread_started:
            assert service._serve_loop_finished.is_set()
    finally:
        service.stop()


@pytest.mark.skipif(sys.platform == "win32", reason="uses POSIX SIGINT and pipe readiness")
def test_actual_foreground_process_handles_sigint_without_an_unhandled_exception(tmp_path):
    from scripts.cigar_benchmark_processes import kernel_image

    repo = Path(__file__).resolve().parents[1]
    child = """
from tests.test_guard_daemon_foreground_interrupt import ForegroundService, GuardDaemonServer
service = ForegroundService()
original_begin = service._begin_service
def begin(**kwargs):
    original_begin(**kwargs)
    real_wait = service._serve_loop_finished.wait
    def ready_wait(timeout=None):
        if timeout is None:
            print('foreground-wait-ready', flush=True)
        return real_wait(timeout)
    service._serve_loop_finished.wait = ready_wait
service._begin_service = begin
GuardDaemonServer.serve(service)
assert service._finish_service_completed and service._serve_loop_finished.is_set()
print('contained', flush=True)
"""
    with (tmp_path / "stderr.log").open("w+") as errors:
        process = subprocess.Popen(
            [sys.executable, "-c", child], cwd=repo, stdout=subprocess.PIPE, stderr=errors, text=True
        )
        try:
            assert process.stdout is not None
            assert select.select([process.stdout], [], [], 10)[0], "child never reached foreground wait"
            assert process.stdout.readline().strip() == "foreground-wait-ready"
            assert process.poll() is None and kernel_image(process.pid) == Path(sys.executable).resolve()
            process.send_signal(signal.SIGINT)
            output, _ = process.communicate(timeout=10)
            errors.seek(0)
            assert process.returncode == 0, errors.read()
            assert output.strip() == "contained"
            assert errors.read() == ""
        finally:
            if process.poll() is None:
                assert kernel_image(process.pid) == Path(sys.executable).resolve()
                process.kill()
                process.wait(timeout=5)
