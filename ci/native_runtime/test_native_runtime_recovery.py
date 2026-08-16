from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_runtime as native_runtime
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
            response = review_post_tool_native(request, observe_mode=False)
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
        first = review_post_tool_native(first_request, observe_mode=False)
        assert first is not None and first.decision == "allow"
        close_resident_native_runtimes()

        second_request = _request(
            tmp_path,
            guard_home=guard_home,
            request_id="after-shutdown",
        )
        second = review_post_tool_native(second_request, observe_mode=False)
        try:
            assert second is not None and second.decision == "allow"
        finally:
            close_resident_native_runtimes()
