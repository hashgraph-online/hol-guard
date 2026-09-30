from __future__ import annotations

from collections.abc import Callable, Generator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeStatus
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewResponse
from codex_plugin_scanner.guard.store import GuardStore


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


@pytest.fixture
def hook_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[HookWorker, None, None]:
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "auto")
    monkeypatch.setattr(HookWorker, "_test_python_oracle_factory", None)
    monkeypatch.setenv("HOL_GUARD_TEST_MODE", "1")
    monkeypatch.setenv("HOL_GUARD_PYTHON_ORACLE", "1")
    monkeypatch.setenv("HOL_GUARD_NATIVE_DIAGNOSTIC", "1")
    worker = HookWorker(
        store=GuardStore(tmp_path / "guard-home"),
        wait_for_native_policy=False,
        publish_native_policy=False,
    )
    try:
        yield worker
    finally:
        worker.close()


def test_hook_worker_auto_is_native_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hook_worker: HookWorker
) -> None:
    worker = hook_worker
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

    python_calls = 0

    def fail_python(*args: object, **kwargs: object) -> HookReviewResponse:
        nonlocal python_calls
        python_calls += 1
        raise AssertionError("Python engine should not run after an authoritative native result")

    _install_test_oracle(worker, fail_python)
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "auto")
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native", fake_native)
    result = worker.review_http_payload(
        payload={"hook_event_name": "PostToolUse", "tool_response": "clean output"},
        params={},
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=worker.guard_home,
        workspace=tmp_path,
    )
    assert native_calls == 1
    assert python_calls == 0
    assert result == {"policy_action": "allow", "hookSpecificOutput": {"hookEventName": "PostToolUse"}}


def test_hook_worker_auto_fails_closed_when_native_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hook_worker: HookWorker
) -> None:
    worker = hook_worker
    python_calls = 0

    def fake_python(*args: object, **kwargs: object) -> HookReviewResponse:
        nonlocal python_calls
        python_calls += 1
        return _allow_response("python_fallback")

    _install_test_oracle(worker, fake_python)
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
        guard_home=worker.guard_home,
        workspace=tmp_path,
    )
    assert python_calls == 0
    assert result["continue"] is True
    assert result["reason_code"] == "native_post_tool_unavailable"


def test_hook_worker_shadow_compares_explicit_python_oracle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hook_worker: HookWorker
) -> None:
    worker = hook_worker
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
        guard_home=worker.guard_home,
        workspace=tmp_path,
    )
    assert python_calls == 1
    assert native_calls == 1
    assert result["policy_action"] == "allow"


def test_hook_worker_shadow_ignores_native_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hook_worker: HookWorker
) -> None:
    worker = hook_worker

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
        guard_home=worker.guard_home,
        workspace=tmp_path,
    )
    assert result == {"policy_action": "allow", "hookSpecificOutput": {"hookEventName": "PostToolUse"}}
