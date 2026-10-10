"""Native stream cleanup spends one budget and retains unfinished ownership."""

import os
import subprocess
import sys
import threading
import time
from collections import deque
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_package_authority as package_authority
from codex_plugin_scanner.guard import native_resident_client as pools
from codex_plugin_scanner.guard import native_resident_stream as streams
from codex_plugin_scanner.guard import native_resident_transport as transport


def test_expired_request_does_not_start_helper(tmp_path, monkeypatch):
    client = streams._PersistentNativeClient(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "state",
        environment={},
    )

    def forbidden_snapshot(**kwargs):
        raise AssertionError("expired request started a helper")

    monkeypatch.setattr(client, "_request_snapshot", forbidden_snapshot)
    assert client.request(b"fixture", deadline_monotonic=time.monotonic() - 1) is None


@pytest.mark.parametrize(
    ("inherited_budget_seconds", "timeout_seconds"),
    [(0.05, 2.0), (2.0, 0.05)],
)
def test_package_intent_capacity_wait_uses_the_earlier_deadline(
    tmp_path, monkeypatch, inherited_budget_seconds, timeout_seconds
):
    home = tmp_path / "guard-home"
    runtime = tmp_path / "runtime"
    pool = pools._PersistentNativeClientPool(executable=runtime, state_dir=home / "native-runtime", environment={})
    pool._clients = {
        streams._PersistentNativeClient(executable=runtime, state_dir=home / "native-runtime", environment={})
        for _ in range(pools._MAX_PERSISTENT_CLIENTS)
    }
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=runtime, sha256="a" * 64),
        capabilities=SimpleNamespace(features=("resident-protocol-v2", "package-authority-v1")),
    )
    monkeypatch.setattr(package_authority, "native_runtime_status", lambda: status)
    monkeypatch.setattr(package_authority, "_isolated_environment", lambda: {})
    monkeypatch.setattr(package_authority, "native_record_resident_failure", lambda *args, **kwargs: None)
    monkeypatch.setattr(pools, "_client_pool_for", lambda *args: pool)
    failure_token = pools._LAST_FAILURE_CODE.set(None)
    try:
        started = time.monotonic()
        result = package_authority.package_intent_parse_native(
            "npm install fixture@1.0.0",
            guard_home=home,
            environment={"PATH": "/fixture/bin"},
            timeout_seconds=timeout_seconds,
            deadline_monotonic=started + inherited_budget_seconds,
        )
        assert result is None
        assert pools.native_resident_client_failure_code() == "native_client_pool_exhausted"
        assert time.monotonic() - started < 0.5
    finally:
        pools._LAST_FAILURE_CODE.reset(failure_token)


def test_close_lock_contention_is_bounded_and_recoverable(tmp_path):
    client = streams._PersistentNativeClient(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "state",
        environment={},
    )
    acquired, release = threading.Event(), threading.Event()

    def hold_lifecycle():
        with client._lifecycle_lock:
            acquired.set()
            release.wait(timeout=2)

    owner = threading.Thread(target=hold_lifecycle, daemon=True)
    owner.start()
    try:
        assert acquired.wait(timeout=1)
        started = time.monotonic()
        assert client.close(deadline_monotonic=started + 0.05) is False
        assert time.monotonic() - started < 0.5
        assert client._closing
    finally:
        release.set()
        owner.join(timeout=1)
    assert not owner.is_alive()
    assert client.close(deadline_monotonic=time.monotonic() + 1) is True


@pytest.mark.parametrize("lock_name", ["_request_lock", "_lifecycle_lock", "_lock"])
def test_request_lock_contention_expires_without_starting_helper(tmp_path, monkeypatch, lock_name):
    failures = []
    client = streams._PersistentNativeClient(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "state",
        environment={},
        failure_recorder=failures.append,
    )
    acquired, release = threading.Event(), threading.Event()

    def forbidden_start(**kwargs):
        raise AssertionError("contended request started helper")

    monkeypatch.setattr(client, "_start", forbidden_start)

    def hold_lock():
        with getattr(client, lock_name):
            acquired.set()
            release.wait(timeout=2)

    owner = threading.Thread(target=hold_lock, daemon=True)
    owner.start()
    try:
        assert acquired.wait(timeout=1)
        started = time.monotonic()
        assert client.request(b"fixture", deadline_monotonic=started + 0.05) is None
        assert time.monotonic() - started < 0.5
        assert failures[-1] == "native_client_timed_out"
        assert client._process is None
    finally:
        release.set()
        owner.join(timeout=1)
    assert not owner.is_alive()


def test_close_waits_share_deadline_and_unfinished_handles_are_retained(tmp_path, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(streams.time, "monotonic", lambda: clock[0])
    waits = []

    class Process:
        stdin = stdout = None

        def poll(self):
            return None

        def terminate(self):
            pass

        def kill(self):
            pass

        def wait(self, *, timeout):
            waits.append(timeout)
            clock[0] += timeout
            raise subprocess.TimeoutExpired("fixture", timeout)

    class Reader:
        def join(self, *, timeout):
            waits.append(timeout)
            clock[0] += timeout

        def is_alive(self):
            return True

    client = streams._PersistentNativeClient(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "state",
        environment={},
    )
    process, reader = Process(), Reader()
    client._process, client._reader = process, reader
    assert client.close(deadline_monotonic=100.1) is False
    assert sum(waits) <= 0.100001
    assert client._process is process and client._reader is reader
    assert client._start() is False


def test_pending_pool_remains_registered_until_recovery_close(tmp_path, monkeypatch):
    home = tmp_path / "home"
    state = home / "native-runtime"
    pool = pools._PersistentNativeClientPool(executable=tmp_path / "runtime", state_dir=state, environment={})
    client = pools._PersistentNativeClient(executable=tmp_path / "runtime", state_dir=state, environment={})
    pool._clients.add(client)
    key = ("fixture", str(state))
    monkeypatch.setattr(pools, "_CLIENT_POOLS", {key: pool})
    budgets = []

    def unfinished(*, deadline_monotonic):
        budgets.append(deadline_monotonic)
        return False

    monkeypatch.setattr(client, "close", unfinished)
    assert pools.close_native_resident_clients(home, deadline_monotonic=101.0) is False
    assert budgets == [101.0]
    assert pools._CLIENT_POOLS[key] is pool and client in pool._clients
    monkeypatch.setattr(client, "close", lambda **kwargs: True)
    assert pools.close_native_resident_clients(home, deadline_monotonic=102.0) is True
    assert key not in pools._CLIENT_POOLS


def test_real_ignored_termination_is_killed_and_stream_reader_is_reaped(tmp_path):
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('ready',flush=True); time.sleep(30)",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    client = streams._PersistentNativeClient(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "state",
        environment={},
    )
    try:
        assert process.stdout.readline() == b"ready\n"
        reader = threading.Thread(target=process.stdout.read, daemon=True)
        client._process, client._reader = process, reader
        reader.start()
        started = time.monotonic()
        complete = client.close(deadline_monotonic=started + 0.1)
        assert time.monotonic() - started < 0.75
        if not complete:
            assert client._process is process
            assert client.close(deadline_monotonic=time.monotonic() + 1)
        assert process.poll() is not None and not reader.is_alive()
        assert client._process is None and client._reader is None
        assert process.stdin.closed and process.stdout.closed
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        client.close(deadline_monotonic=time.monotonic() + 2)


def test_failed_request_keeps_incomplete_client_out_of_idle_reuse(tmp_path, monkeypatch):
    pool = pools._PersistentNativeClientPool(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "state",
        environment={},
    )
    client = pools._PersistentNativeClient(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "state",
        environment={},
    )
    pool._clients.add(client)
    pool._idle.append(client)
    monkeypatch.setattr(client, "request", lambda *args, **kwargs: None)
    monkeypatch.setattr(client, "close", lambda **kwargs: False)
    assert pool.request(b"fixture", deadline_monotonic=time.monotonic() + 1) is None
    assert client in pool._clients and client not in pool._idle
    assert pool.close(deadline_monotonic=time.monotonic()) is False
    monkeypatch.setattr(client, "close", lambda **kwargs: True)
    assert pool.close(deadline_monotonic=time.monotonic() + 1) is True


def test_unfinished_writer_prevents_buffered_stream_close_and_keeps_ownership(tmp_path):
    release = threading.Event()
    writer = threading.Thread(target=lambda: release.wait(timeout=2), daemon=True)

    class Stream:
        closed = False

        def close(self):
            assert not writer.is_alive(), "closing a stream still owned by the writer"
            self.closed = True

    class Process:
        stdin, stdout = Stream(), Stream()

        def poll(self):
            return 0

    process = Process()
    client = streams._PersistentNativeClient(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "state",
        environment={},
    )
    client._process, client._writer = process, writer
    writer.start()
    try:
        assert client.close(deadline_monotonic=time.monotonic() + 0.02) is False
        assert client._writer is writer and client._process is process
        assert not process.stdin.closed and not process.stdout.closed
    finally:
        release.set()
        writer.join(timeout=1)
    assert client.close(deadline_monotonic=time.monotonic() + 1) is True
    assert client._writer is None and client._process is None
    assert process.stdin.closed and process.stdout.closed


def test_real_full_pipe_fallback_writer_is_owned_until_child_retirement(tmp_path, monkeypatch):
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; print('ready',flush=True); time.sleep(30)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    client = streams._PersistentNativeClient(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "state",
        environment={},
    )
    monkeypatch.setattr(transport, "_write_frame_nonblocking", lambda *args, **kwargs: None)
    try:
        assert process.stdout.readline() == b"ready\n"
        client._process = process
        started = time.monotonic()
        assert not client._write_frame(
            process.stdin,
            b"x" * (2 * 1024 * 1024),
            deadline_monotonic=started + 0.05,
            launch_worker=lambda worker: client._launch_writer(
                worker,
                process,
                deadline_monotonic=started + 0.05,
            ),
        )
        assert time.monotonic() - started < 0.5
        writer = client._writer
        assert writer is not None and writer.is_alive()
        assert not process.stdin.closed
        assert client.close(deadline_monotonic=time.monotonic() + 1)
        assert process.poll() is not None and not writer.is_alive()
        assert client._writer is None and client._process is None
        assert process.stdin.closed and process.stdout.closed
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        client.close(deadline_monotonic=time.monotonic() + 2)


def test_fallback_without_owner_starts_no_writer(monkeypatch):
    monkeypatch.setattr(transport, "_write_frame_nonblocking", lambda *args, **kwargs: None)

    class Stream:
        def write(self, frame):
            raise AssertionError("unowned fallback writer started")

    assert not transport.write_frame(Stream(), b"fixture", deadline_monotonic=time.monotonic() + 1)


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor ownership and permissions")
@pytest.mark.parametrize("unsafe", ["file_mode", "directory_mode", "symlink", "hardlink", "fifo", "oversized"])
def test_timeout_diagnostics_reject_unsafe_shared_files(tmp_path, monkeypatch, caplog, unsafe):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    path = state / "managed-resident-phases.v1.log"
    row = b"native_resident_phase phase=resident_evaluate status=start elapsed_ms=0\n"
    target = tmp_path / "target"
    if unsafe == "symlink":
        target.write_bytes(row)
        target.chmod(0o600)
        path.symlink_to(target)
    elif unsafe == "fifo":
        os.mkfifo(path, mode=0o600)
    else:
        path.write_bytes(row if unsafe != "oversized" else row + b"x" * 65536)
        path.chmod(0o644 if unsafe == "file_mode" else 0o600)
        if unsafe == "hardlink":
            os.link(path, target)
        elif unsafe == "directory_mode":
            state.chmod(0o755)
    client = streams._PersistentNativeClient(executable=tmp_path / "runtime", state_dir=state, environment={})
    monkeypatch.setenv("HOL_GUARD_NATIVE_DIAGNOSTIC", "1")
    client._record_phase_failure("native_client_timed_out", "response_wait")
    assert caplog.messages == ["native_client_timed_out phase=response_wait"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX private file setup")
def test_timeout_diagnostics_filter_raw_shared_content_after_helper_retirement(tmp_path, monkeypatch, caplog):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    path = state / "managed-resident-phases.v1.log"
    row = "native_resident_phase phase=resident_evaluate status=start elapsed_ms=0"
    path.write_text(f"private payload\n{row}\nnative_resident_phase phase=private_payload status=start elapsed_ms=0\n")
    path.chmod(0o600)
    client = streams._PersistentNativeClient(executable=tmp_path / "runtime", state_dir=state, environment={})
    client._close_diagnostic_output()
    monkeypatch.setenv("HOL_GUARD_NATIVE_DIAGNOSTIC", "1")
    client._record_phase_failure("native_client_timed_out", "response_wait")
    assert caplog.messages == ["native_client_timed_out phase=response_wait", row]


@pytest.mark.parametrize("count", [0, 10000])
def test_real_diagnostic_pipe_bounds_burst_history_and_discards_fragmented_private_lines(count):
    script = (
        "import sys\n"
        "sys.stderr.write('x' * 193 + 'native_resident_phase phase=resident_evaluate status=error elapsed_ms=99\\n')\n"
        f"for index in range({count}):\n"
        " sys.stderr.write(f'native_resident_phase phase=stream_dispatch status=ok elapsed_ms={index}\\n')\n"
    )
    process = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    lines = deque(maxlen=64)
    try:
        streams._PersistentNativeClient._read_diagnostics(process, lines, threading.Lock())
        assert process.wait(timeout=5) == 0
        assert list(lines) == [
            f"native_resident_phase phase=stream_dispatch status=ok elapsed_ms={index}".encode()
            for index in range(max(0, count - 64), count)
        ]
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if process.stderr is not None:
            process.stderr.close()
