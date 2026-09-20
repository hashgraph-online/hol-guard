from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import BinaryIO, cast

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime as launch
from codex_plugin_scanner.guard import codex_hook_process_runtime as process_runtime
from codex_plugin_scanner.guard import native_policy_control_transport as transport
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult


def _request(tmp_path: Path, *, timeout: float = 1.0) -> bytes | None:
    return transport.native_policy_control_request(
        executable=Path(sys.executable),
        guard_home=tmp_path,
        environment={},
        payload=b"{}",
        deadline_monotonic=time.monotonic() + timeout,
    )


def _child(monkeypatch, tmp_path, *, delay: float = 0, code: str | None = None):
    original = launch._spawn_hook_process
    marker = tmp_path / "dispatched"
    processes = []
    finished = threading.Event()
    original_runner = transport.run_isolated_hook_process
    source = code or (
        "import pathlib,sys; data=sys.stdin.buffer.read(); "
        f"pathlib.Path({str(marker)!r}).write_bytes(data); "
        "sys.stdout.buffer.write(b'{}\\n');sys.stdout.buffer.flush()"
    )

    def spawn(_command, **kwargs):
        if delay:
            time.sleep(delay)
        result = original((sys.executable, "-I", "-c", source), **kwargs)
        processes.append(result[0])
        return result

    def run(*args, **kwargs):
        try:
            return original_runner(*args, **kwargs)
        finally:
            finished.set()

    monkeypatch.setattr(launch, "_spawn_hook_process", spawn)
    monkeypatch.setattr(transport, "run_isolated_hook_process", run)
    return marker, processes, finished


def test_real_child_success_retains_one_attempt_and_exact_frame(tmp_path, monkeypatch):
    marker, processes, finished = _child(monkeypatch, tmp_path)
    assert _request(tmp_path) == b"{}"
    assert finished.wait(1)
    assert marker.read_bytes() == b"{}"
    assert len(processes) == 1
    assert processes[0].poll() == 0


def test_real_cold_start_cannot_send_after_parent_deadline(tmp_path, monkeypatch):
    marker, processes, finished = _child(monkeypatch, tmp_path, delay=0.2)
    begin = time.monotonic()
    assert _request(tmp_path, timeout=0.05) is None
    assert time.monotonic() - begin < 0.15
    assert finished.wait(2)
    assert len(processes) == 1
    assert processes[0].poll() is not None
    assert not marker.exists()


def test_control_ignores_held_persistent_registry_and_request_locks(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard import native_resident_client as clients
    from codex_plugin_scanner.guard.native_resident_stream import _PersistentNativeClient

    client = _PersistentNativeClient(executable=Path(sys.executable), state_dir=tmp_path, environment={})
    marker, _, finished = _child(monkeypatch, tmp_path)
    with clients._CLIENTS_LOCK, clients._RESIDENTS_LOCK, client._request_lock, client._lifecycle_lock, client._lock:
        assert _request(tmp_path) == b"{}"
    assert finished.wait(1)
    assert marker.read_bytes() == b"{}"


def test_expired_or_cancelled_launch_never_spawns(tmp_path, monkeypatch):
    monkeypatch.setattr(launch, "_spawn_hook_process", lambda *args, **kwargs: pytest.fail("spawned"))
    stop = threading.Event()
    stop.set()
    for deadline, event in ((time.monotonic() - 1, None), (time.monotonic() + 1, stop)):
        result = launch.run_isolated_hook_process(
            ("unused",),
            input_text="{}",
            cwd=tmp_path,
            environment={},
            deadline_monotonic=deadline,
            stop_event=event,
            bound_input_to_deadline=True,
        )
        assert result.timed_out
        assert result.stdout == ""


@pytest.mark.parametrize("phase", ["before", "write", "flush"])
def test_control_writer_never_signals_eof_after_cancellation(phase):
    stop = threading.Event()
    events = []

    class Stream:
        def write(self, data):
            events.append(("write", data))
            if phase == "write":
                stop.set()

        def flush(self):
            events.append(("flush",))
            if phase == "flush":
                stop.set()

        def close(self):
            events.append(("eof",))

    if phase == "before":
        stop.set()
    process_runtime._write_hook_input(
        cast(BinaryIO, cast(object, Stream())),
        "{}",
        deadline_monotonic=time.monotonic() + 1,
        stop_event=stop,
    )
    assert ("eof",) not in events
    if phase == "before":
        assert events == []
    elif phase == "write":
        assert events == [("write", b"{}")]
    else:
        assert events == [("write", b"{}"), ("flush",)]


@pytest.mark.parametrize("phase", ["write", "flush"])
def test_real_buffered_input_is_contained_before_cancelled_eof(tmp_path, monkeypatch, phase):
    marker, processes, finished = _child(monkeypatch, tmp_path)
    original_spawn = launch._spawn_hook_process
    closed = []

    def spawn(*args, **kwargs):
        process, job, fd = original_spawn(*args, **kwargs)
        original_stdin = process.stdin
        assert original_stdin is not None

        class DelayedInput:
            def write(self, data):
                result = original_stdin.write(data)
                if phase == "write":
                    time.sleep(0.2)
                return result

            def flush(self):
                result = original_stdin.flush()
                if phase == "flush":
                    time.sleep(0.2)
                return result

            def close(self):
                closed.append(process.poll() is not None)
                original_stdin.close()

        process.stdin = cast(BinaryIO, cast(object, DelayedInput()))
        return process, job, fd

    monkeypatch.setattr(launch, "_spawn_hook_process", spawn)
    assert _request(tmp_path, timeout=0.07) is None
    assert finished.wait(2)
    assert len(processes) == 1
    assert processes[0].poll() is not None
    assert closed and all(closed)
    assert not marker.exists()


def test_default_writer_still_closes_after_write_error():
    events = []

    class Stream:
        def write(self, data):
            events.append("write")
            raise BrokenPipeError

        def close(self):
            events.append("close")

    process_runtime._write_hook_input(cast(BinaryIO, cast(object, Stream())), "{}")
    assert events == ["write", "close"]


def test_slot_remains_owned_until_timed_out_worker_finishes(tmp_path, monkeypatch):
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(transport, "_CONTROL_SLOTS", slots)
    started = threading.Event()
    release = threading.Event()
    calls = []

    def slow_runner(*args, **kwargs):
        calls.append(kwargs)
        started.set()
        assert release.wait(2)
        return BoundedHookProcessResult(0, "{}\n", False, False)

    monkeypatch.setattr(transport, "run_isolated_hook_process", slow_runner)
    try:
        assert _request(tmp_path, timeout=0.04) is None
        assert started.is_set()
        assert _request(tmp_path, timeout=0.02) is None
        assert len(calls) == 1
        assert calls[0]["stop_event"].is_set()
    finally:
        release.set()
    assert slots.acquire(timeout=1)
    slots.release()


def test_thread_start_failure_releases_slot(tmp_path, monkeypatch):
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(transport, "_CONTROL_SLOTS", slots)
    monkeypatch.setattr(threading.Thread, "start", lambda self: (_ for _ in ()).throw(RuntimeError("private detail")))
    assert _request(tmp_path) is None
    assert slots.acquire(blocking=False)
    slots.release()


@pytest.mark.parametrize("stdout,expected", [("{}\n", b"{}"), ("{}", None), ("{}\n\n", b"{}\n"), ("\n", None)])
def test_only_one_terminal_lf_is_removed(tmp_path, monkeypatch, stdout, expected):
    monkeypatch.setattr(
        transport, "run_isolated_hook_process", lambda *a, **kw: BoundedHookProcessResult(0, stdout, False, False)
    )
    assert _request(tmp_path) == expected


@pytest.mark.parametrize("field", ["returncode", "timed_out", "output_limit_exceeded", "containment_failed"])
def test_failed_results_never_return_response(tmp_path, monkeypatch, field):
    result = BoundedHookProcessResult(
        returncode=1 if field == "returncode" else 0,
        stdout="{}\n",
        timed_out=field == "timed_out",
        output_limit_exceeded=field == "output_limit_exceeded",
        containment_failed=field == "containment_failed",
    )
    monkeypatch.setattr(transport, "run_isolated_hook_process", lambda *a, **kw: result)
    assert _request(tmp_path) is None


def test_actual_output_overflow_is_refused_and_child_reaped(tmp_path, monkeypatch):
    _, processes, finished = _child(
        monkeypatch, tmp_path, code="import sys;sys.stdin.buffer.read();sys.stdout.write('x'*8192)"
    )
    assert _request(tmp_path) is None
    assert finished.wait(2)
    assert processes[0].poll() is not None


@pytest.mark.parametrize("deadline", [True, float("inf"), float("nan"), -1.0, 10**1000, 1e100])
def test_invalid_deadline_never_starts_worker(tmp_path, monkeypatch, deadline):
    monkeypatch.setattr(transport, "run_isolated_hook_process", lambda *a, **kw: pytest.fail("ran"))
    assert (
        transport.native_policy_control_request(
            executable=Path(sys.executable),
            guard_home=tmp_path,
            environment={},
            payload=b"{}",
            deadline_monotonic=deadline,
        )
        is None
    )


def test_io_thread_start_failure_contains_and_reaps_spawned_helper(tmp_path, monkeypatch):
    marker, processes, finished = _child(monkeypatch, tmp_path)
    original_start = threading.Thread.start

    def start(thread):
        if thread.name == "hol-guard-native-control":
            return original_start(thread)
        raise RuntimeError("private thread setup detail")

    monkeypatch.setattr(threading.Thread, "start", start)
    assert _request(tmp_path) is None
    assert finished.wait(2)
    assert len(processes) == 1
    assert processes[0].poll() is not None
    assert not marker.exists()


def test_actual_inherited_output_pipe_is_contained(tmp_path, monkeypatch):
    source = (
        "import subprocess,sys;sys.stdin.buffer.read();"
        "subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(5)']);"
        "sys.stdout.buffer.write(b'{}\\n');sys.stdout.buffer.flush()"
    )
    _, processes, finished = _child(monkeypatch, tmp_path, code=source)
    assert _request(tmp_path, timeout=1.0) == b"{}"
    assert finished.wait(2)
    assert processes[0].poll() is not None
    assert not launch._HOOK_PROCESS_QUARANTINE


def test_new_control_keeps_native_windows_job_lifetime_option(tmp_path, monkeypatch):
    calls = []

    def run(*args, **kwargs):
        calls.append((args, kwargs))
        return BoundedHookProcessResult(0, "{}\n", False, False)

    monkeypatch.setattr(transport, "run_isolated_hook_process", run)
    assert _request(tmp_path) == b"{}"
    assert len(calls) == 1
    assert calls[0][0][0][1] == "resident-client"
    assert calls[0][1]["windows_kill_on_job_close"] is False
    assert calls[0][1]["bound_input_to_deadline"] is True


@pytest.mark.parametrize("delay", [0.0, 0.2])
def test_actual_default_adapter_observes_only_an_on_time_authenticated_child(tmp_path, monkeypatch, delay):
    from codex_plugin_scanner.guard import native_policy_snapshot_control as control
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

    key = b"v" * 32
    source = """
import hashlib,hmac,json,pathlib,sys
raw=sys.stdin.buffer.read()
pathlib.Path(MARKER).write_bytes(raw)
envelope=json.loads(raw)
request=envelope['request']
intent=request['intent']
encode=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
response={'schema':'guard-policy-snapshot-observation-response.v1','runtime_identity':intent['runtime_identity'],'scope_digest':intent['scope_digest'],'resident_generation':1,'nonce':intent['nonce'],'request_sha256':hashlib.sha256(encode(request)).hexdigest(),'authority':None}
mac=hmac.new(b'v'*32,b'hol-guard-policy-snapshot-observation-response-v1\\0'+encode(response),hashlib.sha256).hexdigest()
sys.stdout.buffer.write(encode({'response':response,'mac':mac})+b'\\n')
sys.stdout.buffer.flush()
""".replace("MARKER", repr(str(tmp_path / "dispatched")))
    marker, processes, finished = _child(monkeypatch, tmp_path, delay=delay, code=source)
    deadline = time.monotonic() + (0.05 if delay else 1.0)

    def observe():
        return control.observe_native_authority(
            executable=Path(sys.executable),
            guard_home=tmp_path,
            runtime_identity="a" * 64,
            verifier_key=key,
            deadline_monotonic=deadline,
        )

    if delay:
        with pytest.raises(NativePolicySnapshotError, match="control_deadline_exceeded"):
            observe()
        assert finished.wait(2)
        assert not marker.exists()
    else:
        observed = observe()
        assert observed.runtime_identity == "a" * 64
        assert observed.authority is None
        assert marker.exists()
        assert finished.wait(1)
    assert len(processes) == 1
    assert processes[0].poll() is not None


def test_postspawn_exception_keeps_one_cleanup_owner(tmp_path, monkeypatch):
    _marker, processes, finished = _child(monkeypatch, tmp_path)
    original = launch.wait_for_hook_process
    calls = []

    def wait(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("private wait detail")
        return original(*args, **kwargs)

    monkeypatch.setattr(launch, "wait_for_hook_process", wait)
    assert _request(tmp_path) is None
    assert finished.wait(2)
    assert len(processes) == 1
    assert processes[0].poll() is not None
    assert len(calls) == 2


def test_unresolved_cleanup_is_quarantined_and_never_returns_ack(tmp_path, monkeypatch):
    _, processes, finished = _child(monkeypatch, tmp_path)
    original = launch.join_and_cleanup_hook_process
    monkeypatch.setattr(
        launch,
        "join_and_cleanup_hook_process",
        lambda *a, **kw: (_ for _ in ()).throw(OSError("private cleanup detail")),
    )
    try:
        assert _request(tmp_path) is None
        assert finished.wait(2)
        assert len(processes) == 1
        assert launch._HOOK_PROCESS_CONTAINMENT_FAILED.is_set()
        assert len(launch._HOOK_PROCESS_QUARANTINE) == 1
    finally:
        monkeypatch.setattr(launch, "join_and_cleanup_hook_process", original)
        assert launch._retry_quarantined_hook_processes()
    assert not launch._HOOK_PROCESS_QUARANTINE
    assert processes[0].poll() is not None


@pytest.mark.skipif(os.name == "nt", reason="POSIX detached process group control")
def test_helper_timeout_preserves_separately_contained_service(tmp_path, monkeypatch):
    service_pid_path = tmp_path / "service-pid"
    source = (
        "import pathlib,subprocess,sys,time;"
        "child=subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(5)'],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True);"
        f"pathlib.Path({str(service_pid_path)!r}).write_text(str(child.pid));"
        "sys.stdin.buffer.read();time.sleep(5)"
    )
    _, processes, finished = _child(monkeypatch, tmp_path, code=source)
    service_pid = None
    try:
        assert _request(tmp_path, timeout=0.2) is None
        assert finished.wait(2)
        assert processes[0].poll() is not None
        service_pid = int(service_pid_path.read_text())
        os.kill(service_pid, 0)
        assert os.getpgid(service_pid) == service_pid
        assert not launch._HOOK_PROCESS_QUARANTINE
    finally:
        if service_pid is None and service_pid_path.exists():
            service_pid = int(service_pid_path.read_text())
        if service_pid is not None:
            os.killpg(service_pid, signal.SIGKILL)
