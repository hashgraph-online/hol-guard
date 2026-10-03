from __future__ import annotations

import hashlib
import select
import subprocess
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import runtime_transition_native_capture as capture
from codex_plugin_scanner.guard.daemon.live_identity import DaemonArtifactBinding


@pytest.mark.skipif(capture.sys.platform != "darwin", reason="Darwin native waitid ABI")
def test_darwin_child_exit_observation_preserves_owner_status():
    child = subprocess.Popen(["/bin/sh", "-c", "read gate; exit 7"], stdin=subprocess.PIPE)
    try:
        assert not capture.darwin_child_has_exited(child.pid)
        assert not capture.darwin_child_has_exited(capture.os.getpid())
        assert not capture.darwin_child_has_exited(-1)
        assert child.stdin is not None
        child.stdin.write(b"finish\n")
        child.stdin.close()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not capture.darwin_child_has_exited(child.pid):
            time.sleep(0.01)
        assert capture.darwin_child_has_exited(child.pid)
        assert capture.darwin_child_has_exited(child.pid), "observing must not reap the owner's status"
        assert child.wait(timeout=2) == 7
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2)


@pytest.fixture
def owned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    main = tmp_path / "hol-guard"
    main.write_bytes(b"main")
    native = tmp_path / "hol-guard-runtime"
    native.write_bytes(b"native")
    native.chmod(0o700)
    binding = DaemonArtifactBinding(main, hashlib.sha256(b"main").hexdigest(), "3.12.3")
    parent = capture.ProcessSnapshot(100, 1, capture.os.getuid(), "start-main", main)
    child = capture.ProcessSnapshot(101, 100, capture.os.getuid(), "start-native", native)
    state = {"pid": 100, "daemon_url": "http://127.0.0.1:1"}
    monkeypatch.setattr(capture, "verified_live_guard_daemon_identity", lambda *a, **k: state.copy())
    monkeypatch.setattr(capture, "_process_snapshot", lambda pid, deadline: {100: parent, 101: child}[pid])
    monkeypatch.setattr(capture, "_child_pids", lambda pid, deadline: (101,))
    return binding, native, parent, child


def collect(binding: DaemonArtifactBinding, tmp_path: Path):
    return capture.capture_owned_native_candidate(tmp_path, binding, deadline_monotonic=time.monotonic() + 2)


def test_owned_candidate_is_content_identity_not_protection(owned, tmp_path: Path):
    binding, native, parent, child = owned
    result = collect(binding, tmp_path)
    assert result.identity.path == native
    assert result.identity.sha256 == hashlib.sha256(b"native").hexdigest()
    assert result.daemon == parent
    assert result.processes == (child,)
    assert not hasattr(result, "proof")


@pytest.mark.parametrize("change", ["parent", "child", "reparent", "uid", "exe", "state"])
def test_identity_changes_refuse(owned, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str):
    binding, native, parent, child = owned
    calls = {100: 0, 101: 0}

    def snapshot(pid, deadline):
        calls[pid] += 1
        value = parent if pid == 100 else child
        if change == "parent" and pid == 100 and calls[pid] > 1:
            return capture.ProcessSnapshot(pid, 1, value.uid, "reused", value.executable)
        if change == "child" and pid == 101 and calls[pid] > 1:
            return capture.ProcessSnapshot(pid, 100, value.uid, "reused", native)
        if change == "reparent" and pid == 101:
            return capture.ProcessSnapshot(pid, 999, value.uid, value.start_token, native)
        if change == "uid" and pid == 101:
            return capture.ProcessSnapshot(pid, 100, value.uid + 1, value.start_token, native)
        if change == "exe" and pid == 100:
            return capture.ProcessSnapshot(pid, 1, value.uid, value.start_token, native)
        return value

    monkeypatch.setattr(capture, "_process_snapshot", snapshot)
    if change == "state":
        states = iter([{"pid": 100}, {"pid": 101}])
        monkeypatch.setattr(capture, "verified_live_guard_daemon_identity", lambda *a, **k: next(states))
    with pytest.raises(capture.NativeCaptureError):
        collect(binding, tmp_path)


def test_no_authenticated_owner_never_enumerates(owned, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    binding, *_ = owned
    monkeypatch.setattr(capture, "verified_live_guard_daemon_identity", lambda *a, **k: None)
    monkeypatch.setattr(capture, "_child_pids", lambda *a: pytest.fail("enumerated without owner"))
    with pytest.raises(capture.NativeCaptureError, match="daemon_unverified"):
        collect(binding, tmp_path)


def test_expired_original_deadline_never_authenticates(owned, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    binding, *_ = owned
    monkeypatch.setattr(capture, "verified_live_guard_daemon_identity", lambda *a, **k: pytest.fail("expired"))
    with pytest.raises(capture.NativeCaptureError, match="deadline"):
        capture.capture_owned_native_candidate(tmp_path, binding, deadline_monotonic=time.monotonic() - 1)


@pytest.mark.parametrize("mode", ["symlink", "oversized", "not_executable", "writable"])
def test_unsafe_native_file_refuses(owned, tmp_path: Path, mode: str):
    binding, native, *_ = owned
    if mode == "symlink":
        other = tmp_path / "other"
        native.rename(other)
        native.symlink_to(other)
    elif mode == "oversized":
        with native.open("wb") as handle:
            handle.truncate(capture.MAX_NATIVE_BYTES + 1)
    else:
        native.chmod(0o600 if mode == "not_executable" else 0o722)
    with pytest.raises(capture.NativeCaptureError):
        collect(binding, tmp_path)


def test_excess_children_refuse_before_inspection(owned, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    binding, *_ = owned
    monkeypatch.setattr(capture, "_child_pids", lambda *a: tuple(range(101, 101 + capture.MAX_CHILDREN + 1)))
    with pytest.raises(capture.NativeCaptureError, match="capacity"):
        collect(binding, tmp_path)


def test_actual_kernel_snapshot_current_process():
    if capture.sys.platform not in {"darwin", "linux"}:
        pytest.skip("unsupported platform fails closed")
    result = capture._process_snapshot(capture.os.getpid(), time.monotonic() + 2)
    assert result.pid == capture.os.getpid()
    assert result.ppid == capture.os.getppid()
    assert result.uid == capture.os.getuid()
    assert result.start_token
    assert result.executable.is_absolute()


def test_actual_kernel_direct_child_ownership():
    if capture.sys.platform not in {"darwin", "linux"}:
        pytest.skip("unsupported platform fails closed")
    with subprocess.Popen(
        [capture.sys.executable, "-c", "import sys; print('ready', flush=True); sys.stdin.read(1)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    ) as child:
        try:
            assert child.stdout is not None
            assert select.select([child.stdout], [], [], 2)[0]
            assert child.stdout.readline(6) == b"ready\n"
            deadline = time.monotonic() + 2
            assert child.pid in capture._child_pids(capture.os.getpid(), deadline)
            snapshot = capture._process_snapshot(child.pid, deadline)
            assert snapshot.ppid == capture.os.getpid()
            assert snapshot.uid == capture.os.getuid()
            assert capture._process_snapshot(child.pid, deadline) == snapshot
        finally:
            child.terminate()
            child.wait(timeout=2)


def test_distinct_native_paths_refuse_without_hashing(owned, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    binding, _, parent, child = owned
    second = capture.ProcessSnapshot(102, 100, parent.uid, "second", tmp_path / "second" / "hol-guard-runtime")
    monkeypatch.setattr(capture, "_child_pids", lambda *a: (101, 102))
    monkeypatch.setattr(capture, "_process_snapshot", lambda pid, deadline: {100: parent, 101: child, 102: second}[pid])
    monkeypatch.setattr(capture, "_native_identity", lambda *a: pytest.fail("ambiguous hash"))
    with pytest.raises(capture.NativeCaptureError, match="ambiguous"):
        collect(binding, tmp_path)


def test_same_binary_pool_is_hashed_once(owned, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    binding, native, parent, child = owned
    second = capture.ProcessSnapshot(102, 100, parent.uid, "second", native)
    monkeypatch.setattr(capture, "_child_pids", lambda *a: (101, 102))
    monkeypatch.setattr(capture, "_process_snapshot", lambda pid, deadline: {100: parent, 101: child, 102: second}[pid])
    original = capture._native_identity
    hashes = []

    def hash_once(path, deadline):
        hashes.append(path)
        return original(path, deadline)

    monkeypatch.setattr(capture, "_native_identity", hash_once)
    assert len(collect(binding, tmp_path).processes) == 2
    assert hashes == [native]


def test_native_below_exact_core_worker_is_captured(owned, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    binding, native, parent, _ = owned
    worker = capture.ProcessSnapshot(102, 100, parent.uid, "worker", parent.executable)
    child = capture.ProcessSnapshot(101, 102, parent.uid, "native", native)
    monkeypatch.setattr(capture, "_child_pids", lambda pid, deadline: {100: (102,), 102: (101,)}[pid])
    monkeypatch.setattr(capture, "_process_snapshot", lambda pid, deadline: {100: parent, 101: child, 102: worker}[pid])
    result = collect(binding, tmp_path)
    assert result.processes == (child,)
    assert result.workers == (worker,)


def test_arbitrary_intermediate_process_is_not_traversed(owned, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    binding, _, parent, _ = owned
    unrelated = capture.ProcessSnapshot(102, 100, parent.uid, "unrelated", tmp_path / "unrelated")

    def children(pid, deadline):
        assert pid == 100
        return (102,)

    monkeypatch.setattr(capture, "_child_pids", children)
    monkeypatch.setattr(capture, "_process_snapshot", lambda pid, deadline: {100: parent, 102: unrelated}[pid])
    with pytest.raises(capture.NativeCaptureError, match="missing"):
        collect(binding, tmp_path)


def test_intermediate_worker_reuse_refuses(owned, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    binding, native, parent, _ = owned
    worker = capture.ProcessSnapshot(102, 100, parent.uid, "worker", parent.executable)
    child = capture.ProcessSnapshot(101, 102, parent.uid, "native", native)
    count = 0

    def snapshot(pid, deadline):
        nonlocal count
        if pid == 102:
            count += 1
            if count > 1:
                return capture.ProcessSnapshot(102, 100, parent.uid, "reused", parent.executable)
        return {100: parent, 101: child, 102: worker}[pid]

    monkeypatch.setattr(capture, "_child_pids", lambda pid, deadline: {100: (102,), 102: (101,)}[pid])
    monkeypatch.setattr(capture, "_process_snapshot", snapshot)
    with pytest.raises(capture.NativeCaptureError, match="process_changed"):
        collect(binding, tmp_path)


def test_worker_chain_depth_is_bounded(owned, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    binding, _, parent, _ = owned
    monkeypatch.setattr(capture, "_child_pids", lambda pid, deadline: (pid + 1,))
    monkeypatch.setattr(
        capture,
        "_process_snapshot",
        lambda pid, deadline: (
            parent if pid == 100 else capture.ProcessSnapshot(pid, pid - 1, parent.uid, str(pid), parent.executable)
        ),
    )
    with pytest.raises(capture.NativeCaptureError, match="capacity"):
        collect(binding, tmp_path)


def test_child_capacity_is_global_across_workers(owned, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    binding, _, parent, _ = owned
    children = tuple(range(101, 101 + capture.MAX_CHILDREN))
    monkeypatch.setattr(capture, "_child_pids", lambda pid, deadline: children if pid == 100 else (200,))
    monkeypatch.setattr(
        capture,
        "_process_snapshot",
        lambda pid, deadline: (
            parent if pid == 100 else capture.ProcessSnapshot(pid, 100, parent.uid, str(pid), parent.executable)
        ),
    )
    with pytest.raises(capture.NativeCaptureError, match="capacity"):
        collect(binding, tmp_path)


def test_file_mutation_during_hash_refuses(owned, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    binding, native, *_ = owned
    original = capture.hashlib.sha256

    class MutatingHash:
        def __init__(self):
            self.digest = original()

        def update(self, value):
            self.digest.update(value)
            native.write_bytes(b"changed")

        def hexdigest(self):
            return self.digest.hexdigest()

    monkeypatch.setattr(capture.hashlib, "sha256", MutatingHash)
    with pytest.raises(capture.NativeCaptureError, match="file_changed"):
        collect(binding, tmp_path)


def test_original_deadline_expires_during_hash(owned, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    binding, *_ = owned
    deadline = time.monotonic() + 2
    original = capture.hashlib.sha256

    class ExpiringHash:
        def __init__(self):
            self.digest = original()

        def update(self, value):
            self.digest.update(value)
            monkeypatch.setattr(capture.time, "monotonic", lambda: deadline + 1)

        def hexdigest(self):
            return self.digest.hexdigest()

    monkeypatch.setattr(capture.hashlib, "sha256", ExpiringHash)
    with pytest.raises(capture.NativeCaptureError, match="deadline"):
        capture.capture_owned_native_candidate(tmp_path, binding, deadline_monotonic=deadline)
