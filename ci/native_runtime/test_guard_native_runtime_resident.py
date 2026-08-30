from __future__ import annotations

import os
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

import codex_plugin_scanner.guard.native_runtime_resident as resident
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker, HookWorkerUnsupported
from codex_plugin_scanner.guard.native_runtime_resident import (
    close_resident_native_runtimes,
    resident_native_request,
    resident_service_starts,
)
from codex_plugin_scanner.guard.store import GuardStore

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="this lifecycle fixture uses owner-only Unix runtime paths"
)


def _fake_runtime(path: Path) -> Path:
    """Create a contained long-lived process for Python lifecycle-only tests."""
    executable = path / "fake-native-runtime"
    executable.write_text(
        f"""#!{sys.executable}
import time
while True:
    time.sleep(1)
""",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable


def _force_auto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "auto"
    )


def test_resident_runtime_reuses_one_contained_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lifecycle reuse is Python-owned; client protocol is tested by the real Rust binary suite."""
    monkeypatch.setattr(resident, "_START_TIMEOUT_SECONDS", 2.0)

    def fake_native_client(
        self: Any, payload: bytes, *, timeout_seconds: float
    ) -> bytes | None:
        del timeout_seconds
        if self._auth_token is None:
            return None
        if payload == resident._HEALTH_REQUEST:
            return b'{"status":"ready","protocol_version":2}'
        return b'{"decision":"allow","model_output_action":"allow_original","notice":"none","reason_code":"ok"}'

    monkeypatch.setattr(resident._ResidentService, "_send", fake_native_client)

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


def _posttool_allow() -> dict[str, object]:
    return {
        "authority": "rust",
        "event_name": "PostToolUse",
        "decision": "allow",
        "model_output_action": "allow_original",
        "notice": "none",
        "reason_code": "native_allow",
        "policy_action": "allow",
    }


def test_hook_worker_uses_raw_native_hook_edge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_auto(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    worker = HookWorker(store=store)
    calls = 0

    def fake_native(**kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        assert kwargs["payload"] == {
            "hook_event_name": "PostToolUse",
            "tool_response": "clean output",
        }
        return _posttool_allow()

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_hook_edge_native",
        fake_native,
    )

    result = worker.review_http_payload(
        payload={"hook_event_name": "PostToolUse", "tool_response": "clean output"},
        params={},
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=store.guard_home,
        workspace=tmp_path,
    )
    assert calls == 1
    assert result == {
        "policy_action": "allow",
        "reason_code": "native_allow",
        "hookSpecificOutput": {"hookEventName": "PostToolUse"},
    }


def test_hook_worker_fails_closed_when_native_hook_edge_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_auto(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    worker = HookWorker(store=store)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_hook_edge_native",
        lambda **_kwargs: None,
    )

    result = worker.review_http_payload(
        payload={"hook_event_name": "PostToolUse", "tool_response": "clean output"},
        params={},
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=store.guard_home,
        workspace=tmp_path,
    )
    assert result["decision"] == "block"
    assert result["reason_code"] == "native_hook_edge_unavailable"


def test_hook_worker_non_command_pretool_stays_native_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_auto(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    worker = HookWorker(store=store)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_hook_edge_native",
        lambda **_kwargs: {
            "authority": "rust",
            "event_name": "PreToolUse",
            "decision": "deny",
            "minimum_action": "review",
            "policy_action": "review",
            "reason_code": "native_pre_tool_unsupported_review",
            "reason": "review required",
            "explicitly_benign": False,
        },
    )

    result = worker.review_http_payload(
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "README.md"},
        },
        params={},
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=store.guard_home,
        workspace=tmp_path,
    )
    assert result["policy_action"] == "review"
    assert result["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_hook_worker_explicit_off_stays_outside_native_pretool_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    worker = HookWorker(store=store)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "off"
    )

    with pytest.raises(HookWorkerUnsupported):
        worker.review_http_payload(
            payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
            params={},
            default_harness="pi",
            home_dir=tmp_path,
            guard_home=store.guard_home,
            workspace=tmp_path,
        )


def test_lifecycle_fixture_process_is_terminated_on_close(tmp_path: Path) -> None:
    """Smoke the fixture itself so shutdown tests cannot leave an orphan process."""
    executable = _fake_runtime(tmp_path)
    assert executable.exists()
    time.sleep(0.001)
