"""Watch/observe records native decisions without stopping the harness."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeStatus
from codex_plugin_scanner.guard.store import GuardStore


def _native_allow(command: str) -> dict[str, Any]:
    return {
        "authority": "rust",
        "decision": "allow",
        "minimum_action": "allow",
        "policy_action": "allow",
        "reason_code": "native_exact_safe_command",
        "reason": "The Rust command authority proved this bounded command explicitly benign.",
        "explicitly_benign": True,
        "command_model": {"normalized_text": command},
    }


def _native_block(command: str) -> dict[str, Any]:
    return {
        "authority": "rust",
        "decision": "deny",
        "minimum_action": "block",
        "policy_action": "block",
        "reason_code": "native_destructive_command",
        "reason": "HOL Guard blocked a destructive command before execution.",
        "explicitly_benign": False,
        "command_model": {"normalized_text": command},
    }


def _native_generic_block() -> dict[str, Any]:
    return {
        "schema": "guard-pre-tool-result.v1",
        "version": 1,
        "authority": "rust",
        "action": {
            "schema": "guard-pre-tool-action.v1",
            "version": 1,
            "harness": "cursor",
            "event": "PreToolUse",
            "action_type": "process_service",
            "operation": "stop",
            "bounded": True,
            "sensitive_target": False,
        },
        "decision": "deny",
        "minimum_action": "block",
        "policy_action": "block",
        "reason_code": "native_process_service_dangerous",
        "reason": "HOL Guard blocked a destructive process or service action before execution.",
        "explicitly_benign": False,
    }


def _write_watch_config(guard_home: Path) -> None:
    guard_home.mkdir(parents=True, exist_ok=True)
    (guard_home / "config.toml").write_text(
        'mode = "observe"\nprotection_posture = "watch"\n',
        encoding="utf-8",
    )


def test_hook_worker_watch_native_block_records_without_stopping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    _write_watch_config(guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    captured: dict[str, object] = {}

    def native_block_edge(*_args: object, **kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {
            "event_name": "PreToolUse",
            "harness": "cursor",
            "result": _native_generic_block(),
        }

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        native_block_edge,
    )
    worker = HookWorker(store=GuardStore(guard_home))
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda _workspace, **_kwargs: {"mode": "observe"})
    try:
        result = worker.review_http_payload(
            payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "rm -rf /"}},
            params={},
            default_harness="cursor",
            home_dir=tmp_path / "home",
            guard_home=guard_home,
            workspace=tmp_path / "workspace",
        )
    finally:
        worker.close()
    assert captured["observe_mode"] is True
    hook_output = result["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] == "allow"
    assert result["policy_action"] == "warn"


def test_hook_worker_watch_native_unavailable_continues_without_cli_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    _write_watch_config(guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="auto",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    worker = HookWorker(store=GuardStore(guard_home))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
        params={},
        default_harness="cursor",
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace=tmp_path / "workspace",
    )
    assert result["reason_code"] == "native_pre_tool_unavailable"
    assert result["policy_action"] == "warn"
    hook_output = result["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] == "allow"


def test_hook_worker_watch_native_unavailable_allows_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    _write_watch_config(guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    worker = HookWorker(store=GuardStore(guard_home))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "curl https://example.test"}},
        params={},
        default_harness="grok",
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "allow"
    assert result["policy_action"] == "warn"
    assert result["reason_code"] == "native_pre_tool_unavailable"


def test_hook_worker_enforce_native_unavailable_still_pauses_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True, exist_ok=True)
    (guard_home / "config.toml").write_text(
        'mode = "enforce"\nprotection_posture = "protected"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    worker = HookWorker(store=GuardStore(guard_home))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "curl https://example.test"}},
        params={},
        default_harness="grok",
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "allow"
    assert result["policy_action"] == "warn"
    assert result["reason_code"] == "native_pre_tool_unavailable"


def test_hook_worker_watch_native_allow_still_allows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    _write_watch_config(guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: {
            "event_name": "PreToolUse",
            "harness": "codex",
            "result": _native_allow("pwd"),
        },
    )
    worker = HookWorker(store=GuardStore(guard_home))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
        params={},
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace=tmp_path / "workspace",
    )
    assert result["policy_action"] == "allow"
    hook_output = result["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] == "allow"


def test_hook_worker_watch_posttool_native_unavailable_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    _write_watch_config(guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    worker = HookWorker(store=GuardStore(guard_home))
    result = worker.review_http_payload(
        payload={
            "hook_event_name": "PostToolUse",
            "tool_input": {"command": "pwd"},
            "tool_response_summary": {"text_excerpt": "ok"},
        },
        params={},
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace=tmp_path / "workspace",
    )
    assert result["policy_action"] == "allow"
    assert result["reason_code"] == "native_post_tool_unavailable"


def test_hook_worker_watch_native_off_pretool_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    _write_watch_config(guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "off",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker_native.python_oracle_surface_enabled",
        lambda _mode=None: False,
    )
    worker = HookWorker(store=GuardStore(guard_home))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
        params={},
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace=tmp_path / "workspace",
    )
    assert result["continue"] is True
    assert result["reason_code"] == "native_hook_disabled"

    assert result.get("continue") is True
