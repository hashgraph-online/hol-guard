from __future__ import annotations

import multiprocessing
import os
import socket
import stat
import sys
import tempfile
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

import pytest

import codex_plugin_scanner.guard.native_runtime_resident as resident
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeStatus
from codex_plugin_scanner.guard.native_runtime_resident import (
    close_resident_native_runtimes,
    resident_native_request,
    resident_service_starts,
)
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewResponse
from codex_plugin_scanner.guard.store import GuardStore

pytestmark = pytest.mark.skipif(os.name == "nt", reason="resident runtime currently uses owner-only Unix sockets")


class _ResultQueue(Protocol):
    def put(self, value: bool) -> None: ...


class _ReleaseEvent(Protocol):
    def wait(self, timeout: float | None = None) -> bool: ...


def _fake_runtime(path: Path) -> Path:
    executable = path / "fake-native-runtime"
    executable.write_text(
        f"""#!{sys.executable}
import hashlib
import hmac
import socket
import sys
import tempfile

REQUEST_MAGIC = b'HGR2'
RESPONSE_MAGIC = b'HGS2'
SERVER_LABEL = b'hol-guard-resident-server-v1\\x00'
CLIENT_LABEL = b'hol-guard-resident-client-v1\\x00'
HEADER_BYTES = 72

def read_exact(client, length):
    chunks = []
    while length:
        chunk = client.recv(length)
        if not chunk:
            return None
        chunks.append(chunk)
        length -= len(chunk)
    return b''.join(chunks)

token = bytes.fromhex(sys.stdin.readline().strip())
assert len(token) == 32
socket_path = sys.argv[3]
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(socket_path)
server.listen(8)
while True:
    client, _ = server.accept()
    with client:
        client.settimeout(1.0)
        nonce = read_exact(client, 32)
        if nonce is None:
            continue
        client.sendall(hmac.new(token, SERVER_LABEL + nonce, hashlib.sha256).digest())
        proof = read_exact(client, 32)
        expected = hmac.new(token, CLIENT_LABEL + nonce, hashlib.sha256).digest()
        if proof is None or not hmac.compare_digest(proof, expected):
            continue
        header = read_exact(client, HEADER_BYTES)
        if header is None or header[:4] != REQUEST_MAGIC:
            continue
        request_id = header[4:36]
        request_digest = header[36:68]
        length = int.from_bytes(header[68:72], 'big')
        request = read_exact(client, length)
        if request is None or hashlib.sha256(request).digest() != request_digest:
            continue
        if request == b'{{"operation":"health","request":{{}}}}':
            response = b'{{"status":"ready","protocol_version":2}}'
        else:
            response = (
                b'{{"decision":"allow","model_output_action":'
                b'"allow_original","notice":"none",'
                b'"reason_code":"ok"}}'
            )
        response_header = (
            RESPONSE_MAGIC
            + request_id
            + hashlib.sha256(response).digest()
            + len(response).to_bytes(4, 'big')
        )
        client.sendall(response_header + response)
""",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable


def _socket_replacing_fake_runtime(path: Path, starts_path: Path) -> Path:
    executable = path / "socket-replacing-native-runtime"
    executable.write_text(
        _fake_runtime(path)
        .read_text(encoding="utf-8")
        .replace(
            "server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\nserver.bind(socket_path)",
            (
                f"with open({str(starts_path)!r}, 'a', encoding='utf-8') as starts:\n"
                "    starts.write(str(os.getpid()) + '\\n')\n"
                "try:\n"
                "    os.unlink(socket_path)\n"
                "except FileNotFoundError:\n"
                "    pass\n"
                "server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
                "server.bind(socket_path)"
            ),
        )
        .replace("import hmac\n", "import hmac\nimport os\n"),
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable


def _resident_process_worker(
    executable: str,
    guard_home: str,
    identity: str,
    result_queue: _ResultQueue,
    release_event: _ReleaseEvent,
) -> None:
    service = resident._ResidentService(  # pyright: ignore[reportPrivateUsage]
        executable=Path(executable),
        identity_sha256=identity,
        guard_home=Path(guard_home),
        environment={"HOME": str(Path(guard_home).parent)},
    )
    try:
        response = service.request(b"{}", timeout_seconds=3.0)
        result_queue.put(response is not None)
        release_event.wait(5.0)
    finally:
        service.close()


def test_resident_runtime_reuses_one_contained_service(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resident, "_START_TIMEOUT_SECONDS", 2.0)
    with tempfile.TemporaryDirectory(prefix="hgr-") as short_tmp:
        root = Path(short_tmp)
        executable = _fake_runtime(root)
        guard_home = root / "guard-home"
        guard_home.mkdir(mode=0o700)
        identity = "a" * 64
        environment = {"HOME": str(root)}
        try:
            first = resident_native_request(
                executable=executable,
                identity_sha256=identity,
                guard_home=guard_home,
                environment=environment,
                payload=b"{}",
                timeout_seconds=3.0,
            )
            second = resident_native_request(
                executable=executable,
                identity_sha256=identity,
                guard_home=guard_home,
                environment=environment,
                payload=b"{}",
                timeout_seconds=3.0,
            )
            assert first == second
            assert first is not None and b'"decision":"allow"' in first
            assert (
                resident_service_starts(
                    executable=executable,
                    identity_sha256=identity,
                    guard_home=guard_home,
                )
                == 1
            )
            runtime_dir = guard_home / "native-runtime"
            assert stat.S_IMODE(runtime_dir.stat().st_mode) == 0o700
        finally:
            close_resident_native_runtimes()

        assert not any((guard_home / "native-runtime").glob("*.sock"))


def test_independent_supervisors_do_not_replace_one_live_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resident, "_START_TIMEOUT_SECONDS", 2.0)
    with tempfile.TemporaryDirectory(prefix="hgr-", dir="/tmp") as short_tmp:
        root = Path(short_tmp)
        starts_path = root / "starts.log"
        executable = _socket_replacing_fake_runtime(root, starts_path)
        guard_home = root / "guard-home"
        guard_home.mkdir(mode=0o700)
        identity = "c" * 64
        environment = {"HOME": str(root)}
        first = resident._ResidentService(  # pyright: ignore[reportPrivateUsage]
            executable=executable,
            identity_sha256=identity,
            guard_home=guard_home,
            environment=environment,
        )
        second = resident._ResidentService(  # pyright: ignore[reportPrivateUsage]
            executable=executable,
            identity_sha256=identity,
            guard_home=guard_home,
            environment=environment,
        )
        try:
            assert first.request(b"{}", timeout_seconds=3.0) is not None
            assert second.request(b"{}", timeout_seconds=3.0) is None
            assert len(starts_path.read_text(encoding="utf-8").splitlines()) == 1

            second.close()
            socket_path = resident._resident_socket_path(  # pyright: ignore[reportPrivateUsage]
                guard_home,
                identity,
            )
            assert socket_path is not None and socket_path.exists()
        finally:
            second.close()
            first.close()

        assert not any((guard_home / "native-runtime").glob("*.sock"))


def test_spawned_supervisors_share_one_resident_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resident, "_START_TIMEOUT_SECONDS", 2.0)
    with tempfile.TemporaryDirectory(prefix="hgr-", dir="/tmp") as short_tmp:
        root = Path(short_tmp)
        starts_path = root / "starts.log"
        executable = _socket_replacing_fake_runtime(root, starts_path)
        guard_home = root / "guard-home"
        guard_home.mkdir(mode=0o700)
        identity = "e" * 64
        context = multiprocessing.get_context("spawn")
        result_queue = context.Queue()
        release_event = context.Event()
        processes = [
            context.Process(
                target=_resident_process_worker,
                args=(str(executable), str(guard_home), identity, result_queue, release_event),
            )
            for _ in range(4)
        ]
        try:
            for process in processes:
                process.start()
            results = [result_queue.get(timeout=10.0) for _ in processes]

            assert results.count(True) == 1
            assert results.count(False) == 3
            assert len(starts_path.read_text(encoding="utf-8").splitlines()) == 1
        finally:
            release_event.set()
            for process in processes:
                process.join(timeout=5.0)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=1.0)
            result_queue.close()
            result_queue.join_thread()

        assert all(process.exitcode == 0 for process in processes)
        assert not any((guard_home / "native-runtime").glob("*.sock"))


def test_resident_close_preserves_replacement_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resident, "_START_TIMEOUT_SECONDS", 2.0)
    with tempfile.TemporaryDirectory(prefix="hgr-", dir="/tmp") as short_tmp:
        root = Path(short_tmp)
        executable = _fake_runtime(root)
        guard_home = root / "guard-home"
        guard_home.mkdir(mode=0o700)
        identity = "d" * 64
        service = resident._ResidentService(  # pyright: ignore[reportPrivateUsage]
            executable=executable,
            identity_sha256=identity,
            guard_home=guard_home,
            environment={"HOME": str(root)},
        )
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        owned_path = root / "owned.sock"
        try:
            assert service.request(b"{}", timeout_seconds=3.0) is not None
            socket_path = service.socket_path
            assert socket_path is not None
            socket_path.rename(owned_path)
            replacement.bind(str(socket_path))
            replacement.listen(1)

            service.close()

            assert socket_path.is_socket()
        finally:
            service.close()
            replacement.close()
            for path in (owned_path, service.socket_path):
                if path is not None:
                    path.unlink(missing_ok=True)


def test_start_lock_wait_stays_inside_request_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    real_start_lock = resident._resident_start_lock  # pyright: ignore[reportPrivateUsage]

    @contextmanager
    def delayed_lock(_socket_path: Path | None, *, timeout_seconds: float) -> Generator[bool]:
        time.sleep(timeout_seconds + 0.02)
        yield True

    monkeypatch.setattr(resident, "_resident_start_lock", delayed_lock)
    with tempfile.TemporaryDirectory(prefix="hgr-", dir="/tmp") as short_tmp:
        root = Path(short_tmp)
        starts_path = root / "starts.log"
        executable = _socket_replacing_fake_runtime(root, starts_path)
        guard_home = root / "guard-home"
        guard_home.mkdir(mode=0o700)
        service = resident._ResidentService(  # pyright: ignore[reportPrivateUsage]
            executable=executable,
            identity_sha256="f" * 64,
            guard_home=guard_home,
            environment={"HOME": str(root)},
        )
        started = time.monotonic()
        try:
            assert service.request(b"{}", timeout_seconds=0.05) is None
        finally:
            monkeypatch.setattr(resident, "_resident_start_lock", real_start_lock)
            service.close()

        assert time.monotonic() - started < 0.2
        assert not starts_path.exists()


def test_resident_runtime_falls_back_for_overlong_socket_path(tmp_path: Path) -> None:
    executable = _fake_runtime(tmp_path)
    guard_home = tmp_path
    for index in range(8):
        guard_home = guard_home / (f"very-long-private-runtime-directory-{index}" * 2)
    guard_home.mkdir(parents=True, mode=0o700)
    try:
        assert (
            resident_native_request(
                executable=executable,
                identity_sha256="b" * 64,
                guard_home=guard_home,
                environment={"HOME": str(tmp_path)},
                payload=b"{}",
                timeout_seconds=0.25,
            )
            is None
        )
    finally:
        close_resident_native_runtimes()


def _allow_response(reason_code: str) -> HookReviewResponse:
    return HookReviewResponse(
        decision="allow",
        reason=None,
        model_output_action="allow_original",
        notice="none",
        reason_code=reason_code,
        policy_action="allow",
    )


def _install_test_oracle(worker: HookWorker, review: Callable[..., object]) -> None:
    class _Oracle:
        def __init__(self, callback: Callable[..., object]) -> None:
            self.review: Callable[..., object] = callback

    worker._python_oracle_object = _Oracle(review)
    worker._python_oracle = review


def test_hook_worker_auto_is_native_first(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    worker = HookWorker(store=store)
    native_calls = 0

    def fake_native(*args: object, **kwargs: object) -> dict[str, object]:
        nonlocal native_calls
        native_calls += 1
        return {
            "schema": "guard-hook-edge-result.v2",
            "authority": "rust",
            "harness": "claude-code",
            "event_name": "PostToolUse",
            "payload_kind": "inline",
            "result": {
                "decision": "allow",
                "model_output_action": "allow_original",
                "reason_code": "native_allow",
            },
        }

    def fail_python(*args: object, **kwargs: object) -> HookReviewResponse:
        raise AssertionError("Python engine should not run after an authoritative native result")

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "auto")
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native", fake_native)
    result = worker.review_http_payload(
        payload={"hook_event_name": "PostToolUse", "tool_response": "clean output"},
        params={},
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=store.guard_home,
        workspace=tmp_path,
    )
    assert native_calls == 1
    assert result == {"policy_action": "allow", "hookSpecificOutput": {"hookEventName": "PostToolUse"}}


def test_hook_worker_auto_fails_closed_when_native_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    worker = HookWorker(store=store)
    python_calls = 0

    def fake_python(*args: object, **kwargs: object) -> HookReviewResponse:
        nonlocal python_calls
        python_calls += 1
        return _allow_response("python_fallback")

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "auto")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="auto",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *args, **kwargs: None,
    )
    result = worker.review_http_payload(
        payload={"hook_event_name": "PostToolUse", "tool_response": "clean output"},
        params={},
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=store.guard_home,
        workspace=tmp_path,
    )
    assert python_calls == 0
    assert result["decision"] == "block"
    assert result["reason_code"] == "native_post_tool_unavailable"


def test_hook_worker_shadow_compares_explicit_python_oracle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    worker = HookWorker(store=store)
    native_calls = 0
    python_calls = 0

    def fake_python(*args: object, **kwargs: object) -> HookReviewResponse:
        nonlocal python_calls
        python_calls += 1
        return _allow_response("python_authoritative")

    def fake_native(*args: object, **kwargs: object) -> HookReviewResponse:
        nonlocal native_calls
        native_calls += 1
        return HookReviewResponse(
            decision="deny",
            reason="native mismatch",
            model_output_action="block",
            notice="warning",
            reason_code="native_deny",
        )

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "shadow")
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.review_post_tool_native", fake_native)
    monkeypatch.setenv("HOL_GUARD_TEST_MODE", "1")
    monkeypatch.setenv("HOL_GUARD_PYTHON_ORACLE", "1")
    monkeypatch.setenv("HOL_GUARD_NATIVE_DIAGNOSTIC", "1")
    _install_test_oracle(worker, fake_python)

    result = worker.review_http_payload(
        payload={"hook_event_name": "PostToolUse", "tool_response": "clean output"},
        params={},
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=store.guard_home,
        workspace=tmp_path,
    )
    assert python_calls == 1
    assert native_calls == 1
    assert result["policy_action"] == "allow"


def test_hook_worker_shadow_ignores_native_exception(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    worker = HookWorker(store=store)

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "shadow")
    monkeypatch.setenv("HOL_GUARD_TEST_MODE", "1")
    monkeypatch.setenv("HOL_GUARD_PYTHON_ORACLE", "1")
    monkeypatch.setenv("HOL_GUARD_NATIVE_DIAGNOSTIC", "1")
    _install_test_oracle(worker, lambda *args, **kwargs: _allow_response("python_authoritative"))

    def fail_native(*args: object, **kwargs: object) -> HookReviewResponse:
        raise RuntimeError("synthetic native failure")

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.review_post_tool_native", fail_native)

    result = worker.review_http_payload(
        payload={"hook_event_name": "PostToolUse", "tool_response": "clean output"},
        params={},
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=store.guard_home,
        workspace=tmp_path,
    )
    assert result == {"policy_action": "allow", "hookSpecificOutput": {"hookEventName": "PostToolUse"}}
