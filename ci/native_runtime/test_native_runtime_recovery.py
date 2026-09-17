from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_runtime as native_runtime
from ci.native_runtime.native_hook_client_support import _push_snapshot
from ci.native_runtime.resident_test_support import process_is_alive
from ci.native_runtime.test_native_hook_client import (
    _request as _native_request,
)
from ci.native_runtime.test_native_hook_client import _state_files
from codex_plugin_scanner.guard.native_policy_test_support import native_policy_snapshot
from codex_plugin_scanner.guard.native_runtime import native_runtime_status, review_post_tool_native
from codex_plugin_scanner.guard.native_runtime_resident import close_resident_native_runtimes
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest

_NATIVE_BINARY = os.environ.get("HOL_GUARD_NATIVE_BINARY")


def _request(workspace: Path, *, guard_home: Path, request_id: str) -> HookReviewRequest:
    return HookReviewRequest(
        harness="claude-code",
        event_name="PostToolUse",
        payload={
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": [{"type": "text", "text": "const value = 1;\n"}],
        },
        payload_kind="inline",
        config_path=None,
        cwd=workspace,
        home_dir=workspace,
        guard_home=guard_home,
        source_scope="project",
        request_id=request_id,
    )


def _fake_capability_runtime(tmp_path: Path, *, runtime_version: str) -> Path:
    path = tmp_path / "fake-runtime"
    capabilities = json.dumps(
        {
            "protocol_version": 1,
            "runtime_version": runtime_version,
            "rule_digest": "a" * 64,
            "build_sha": "test",
            "target": "test",
            "features": [],
        },
        separators=(",", ":"),
    )
    path.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = capabilities ] && [ "$2" = --json ]; then\n'
        f"  printf '%s\\n' {capabilities!r}\n"
        "else\n"
        "  exit 2\n"
        "fi\n",
        encoding="utf-8",
    )
    path.chmod(0o700)
    return path


def test_auto_rejects_version_mismatched_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _fake_capability_runtime(tmp_path, runtime_version="0.0.0-mismatch")
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setattr(native_runtime, "_runtime_candidates", lambda: (runtime,))
    monkeypatch.setattr(native_runtime, "_python_package_version", lambda: "test")
    native_runtime._capabilities_for_identity.cache_clear()
    status = native_runtime_status()
    assert status.available is True
    assert status.compatible is False
    assert status.reason == "native_version_mismatch"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are required")
def test_runtime_rejects_group_writable_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _fake_capability_runtime(tmp_path, runtime_version="test")
    runtime.chmod(0o720)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setattr(native_runtime, "_runtime_candidates", lambda: (runtime,))
    status = native_runtime_status()
    assert status.available is False
    assert status.reason == "native_unavailable"


@pytest.mark.skipif(os.name == "nt", reason="symlink runtime fixture is POSIX-only")
def test_runtime_rejects_symlink_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _fake_capability_runtime(tmp_path, runtime_version="test")
    link = tmp_path / "runtime-link"
    link.symlink_to(target)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setattr(native_runtime, "_runtime_candidates", lambda: (link,))
    status = native_runtime_status()
    assert status.available is False
    assert status.reason == "native_unavailable"


@pytest.mark.skipif(not _NATIVE_BINARY or os.name == "nt", reason="compiled POSIX resident runtime is required")
def test_poisoned_socket_symlink_falls_back_without_touching_target(tmp_path: Path) -> None:
    status = native_runtime_status()
    assert status.available and status.compatible and status.identity is not None
    with tempfile.TemporaryDirectory(prefix="hgr-poison-", dir=tempfile.gettempdir()) as short_tmp:
        guard_home = Path(short_tmp) / "guard-home"
        guard_home.mkdir(mode=0o700)
        request = _request(tmp_path, guard_home=guard_home, request_id="poisoned-socket")
        runtime_dir = request.guard_home / "native-runtime"
        runtime_dir.mkdir(mode=0o700, exist_ok=True)
        victim = tmp_path / "victim.txt"
        victim.write_text("keep", encoding="utf-8")
        socket_path = runtime_dir / f"hook-v2-{status.identity.sha256[:16]}.sock"
        socket_path.symlink_to(victim)
        try:
            with native_policy_snapshot(guard_home) as snapshot:
                response = review_post_tool_native(request, observe_mode=False, policy_snapshot=snapshot)
            assert response is not None
            assert response.decision == "allow"
            assert victim.read_text(encoding="utf-8") == "keep"
            assert socket_path.is_symlink()
        finally:
            close_resident_native_runtimes()
            socket_path.unlink(missing_ok=True)


@pytest.mark.skipif(not _NATIVE_BINARY or os.name == "nt", reason="compiled POSIX resident runtime is required")
def test_resident_runtime_restarts_after_contained_shutdown(tmp_path: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="hgr-restart-", dir=tempfile.gettempdir()) as short_tmp:
        guard_home = Path(short_tmp) / "guard-home"
        guard_home.mkdir(mode=0o700)
        first_request = _request(
            tmp_path,
            guard_home=guard_home,
            request_id="before-shutdown",
        )
        try:
            with native_policy_snapshot(guard_home) as snapshot:
                first = review_post_tool_native(first_request, observe_mode=False, policy_snapshot=snapshot)
                assert first is not None and first.decision == "allow"
                close_resident_native_runtimes()

                second_request = _request(
                    tmp_path,
                    guard_home=guard_home,
                    request_id="after-shutdown",
                )
                second = review_post_tool_native(second_request, observe_mode=False, policy_snapshot=snapshot)
                assert second is not None and second.decision == "allow"
        finally:
            close_resident_native_runtimes()


@pytest.mark.skipif(not _NATIVE_BINARY or os.name == "nt", reason="compiled POSIX resident runtime is required")
def test_native_clients_share_one_generation_across_processes(tmp_path: Path) -> None:
    runtime = Path(_NATIVE_BINARY).resolve(strict=True)
    state_dir = tmp_path / "native-runtime"
    state_dir.mkdir(mode=0o700)
    request = _native_request(runtime, tmp_path)
    _push_snapshot(runtime, state_dir, request)
    processes = [
        subprocess.Popen(
            (str(runtime), "hook-client", "--stdin", str(state_dir)),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(8)
    ]
    process_ids: tuple[int, int] = ()
    try:
        for process in processes:
            assert process.stdin is not None
            process.stdin.write(request)
            process.stdin.close()
        for process in processes:
            process.wait(timeout=5)
        outputs = [(process.stdout.read() if process.stdout is not None else b"") for process in processes]
        errors = [(process.stderr.read() if process.stderr is not None else b"") for process in processes]
        assert [process.returncode for process in processes] == [0] * len(processes), errors
        assert all(json.loads(output)["authority"] == "rust" for output in outputs)
        states = [json.loads(path.read_text(encoding="utf-8")) for path in _state_files(state_dir)]
        assert len(states) == 1
        process_ids = (states[0]["process_id"], states[0]["owner_process_id"])
    finally:
        subprocess.run(
            (str(runtime), "resident-stop", "--state-dir", str(state_dir)),
            check=False,
            capture_output=True,
            timeout=5,
        )
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)

    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and (
        _state_files(state_dir) or any(process_is_alive(process_id) for process_id in process_ids)
    ):
        time.sleep(0.01)
    assert not (_state_files(state_dir) or any(process_is_alive(process_id) for process_id in process_ids))
