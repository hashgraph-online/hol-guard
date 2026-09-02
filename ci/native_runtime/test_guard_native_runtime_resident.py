from __future__ import annotations

import os
import stat
import tempfile
import threading
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from pathlib import Path

import pytest
from resident_test_support import fake_runtime as _fake_runtime
from resident_test_support import socket_replacing_fake_runtime as _socket_replacing_fake_runtime

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


def test_resident_runtime_reuses_one_contained_service(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resident, "_START_TIMEOUT_SECONDS", 2.0)
    with tempfile.TemporaryDirectory(prefix="hgr-", dir="/tmp") as short_tmp:
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


def test_startup_timeout_signals_new_resident_for_containment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = resident._ResidentService(  # pyright: ignore[reportPrivateUsage]
        executable=tmp_path / "runtime",
        identity_sha256="c" * 64,
        guard_home=tmp_path,
        environment={},
    )
    stop_event = threading.Event()
    stop_observed = threading.Event()
    thread = threading.Thread(
        target=lambda: (stop_event.wait(timeout=1.0), stop_observed.set()),
        daemon=True,
    )
    service._thread = thread  # pyright: ignore[reportPrivateUsage]
    thread.start()
    monkeypatch.setattr(service, "_transport_accepts_authenticated_connections", lambda **_kwargs: False)

    deadline = time.monotonic() + 0.02
    assert not service._wait_until_ready(  # pyright: ignore[reportPrivateUsage]
        thread=thread,
        started=(b"t" * resident._AUTH_TOKEN_BYTES, stop_event, 0),  # pyright: ignore[reportPrivateUsage]
        deadline=deadline,
    )
    assert stop_observed.wait(timeout=1.0)
    thread.join(timeout=1.0)
    assert not thread.is_alive()


def test_ensure_started_replaces_supervisor_after_external_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with tempfile.TemporaryDirectory(prefix="hgr-", dir="/tmp") as short_tmp:
        root = Path(short_tmp)
        service = resident._ResidentService(  # pyright: ignore[reportPrivateUsage]
            executable=root / "runtime",
            identity_sha256="e" * 64,
            guard_home=root,
            environment={},
        )
        stale = threading.Thread(daemon=True)
        stale.is_alive = lambda: True  # type: ignore[method-assign]
        stale.join = lambda timeout=None: None  # type: ignore[method-assign]
        service._thread = stale  # pyright: ignore[reportPrivateUsage]
        service._auth_token = b"\x01" * 32  # pyright: ignore[reportPrivateUsage]
        replacement = threading.Thread(daemon=True)
        replacement.is_alive = lambda: True  # type: ignore[method-assign]
        started = (b"\x02" * 32, threading.Event(), 2)

        def fake_start() -> tuple[threading.Thread, tuple[bytes, threading.Event, int]]:
            assert service._thread is not stale  # pyright: ignore[reportPrivateUsage]
            assert service._stop_event.is_set()  # pyright: ignore[reportPrivateUsage]
            service._thread = replacement  # pyright: ignore[reportPrivateUsage]
            return replacement, started

        monkeypatch.setattr(service, "_transport_configured", lambda: True)
        monkeypatch.setattr(service, "_transport_accepts_authenticated_connections", lambda **_kwargs: False)
        monkeypatch.setattr(service, "_start_thread_if_needed", fake_start)
        monkeypatch.setattr(service, "_wait_until_ready", lambda **_kwargs: True)

        assert service._ensure_started(timeout_seconds=1.0) is True  # pyright: ignore[reportPrivateUsage]
        assert service._thread is replacement  # pyright: ignore[reportPrivateUsage]


def test_close_retains_tracking_until_resident_thread_stops(
    tmp_path: Path,
) -> None:
    service = resident._ResidentService(  # pyright: ignore[reportPrivateUsage]
        executable=tmp_path / "runtime",
        identity_sha256="d" * 64,
        guard_home=tmp_path,
        environment={},
    )
    thread = threading.Thread(daemon=True)
    thread.is_alive = lambda: True  # type: ignore[method-assign]
    thread.join = lambda timeout=None: None  # type: ignore[method-assign]
    service._thread = thread  # pyright: ignore[reportPrivateUsage]

    assert service.close() is False
    assert service._thread is thread  # pyright: ignore[reportPrivateUsage]

    thread.is_alive = lambda: False  # type: ignore[method-assign]
    assert service.close() is True
    assert service._thread is None  # pyright: ignore[reportPrivateUsage]


def test_request_shares_one_deadline_across_probe_start_and_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [10.0]
    send_timeouts: list[float] = []
    start_timeouts: list[float] = []
    service = resident._ResidentService(  # pyright: ignore[reportPrivateUsage]
        executable=tmp_path / "runtime",
        identity_sha256="a" * 64,
        guard_home=tmp_path,
        environment={},
    )

    def fake_send(_payload: bytes, *, timeout_seconds: float) -> bytes | None:
        send_timeouts.append(timeout_seconds)
        clock[0] += timeout_seconds
        return None if len(send_timeouts) == 1 else b"ready"

    def fake_start(*, timeout_seconds: float) -> bool:
        start_timeouts.append(timeout_seconds)
        clock[0] += 0.12
        return True

    monkeypatch.setattr(resident.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(service, "_transport_configured", lambda: True)
    monkeypatch.setattr(service, "_send", fake_send)
    monkeypatch.setattr(service, "_ensure_started", fake_start)

    assert service.request(b"{}", timeout_seconds=0.25) == b"ready"
    assert send_timeouts == pytest.approx([0.05, 0.08])
    assert start_timeouts == pytest.approx([0.2])
    assert clock[0] == pytest.approx(10.25)


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
