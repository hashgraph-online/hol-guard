"""Watch/observe preserves native authority and fail-safe behavior."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker, HookWorkerUnsupported
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


def _write_watch_config(guard_home: Path) -> None:
    guard_home.mkdir(parents=True, exist_ok=True)
    (guard_home / "config.toml").write_text(
        'mode = "observe"\nprotection_posture = "watch"\n',
        encoding="utf-8",
    )


def test_hook_worker_watch_native_block_uses_cli_recording(
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
            "result": _native_block("rm -rf /"),
        }

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        native_block_edge,
    )
    worker = HookWorker(store=GuardStore(guard_home))
    with pytest.raises(HookWorkerUnsupported, match="CLI approval coordination"):
        worker.review_http_payload(
            payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "rm -rf /"}},
            params={},
            default_harness="cursor",
            home_dir=tmp_path / "home",
            guard_home=guard_home,
            workspace=tmp_path / "workspace",
        )
    assert captured["observe_mode"] is True


def test_hook_worker_watch_native_unavailable_uses_cli_recording(
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
    with pytest.raises(HookWorkerUnsupported, match="CLI recording"):
        worker.review_http_payload(
            payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
            params={},
            default_harness="cursor",
            home_dir=tmp_path / "home",
            guard_home=guard_home,
            workspace=tmp_path / "workspace",
        )


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
    assert result["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_hook_worker_watch_posttool_native_unavailable_fails_closed(
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
        "codex_plugin_scanner.guard.daemon.hook_worker.review_post_tool_native",
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
    assert result["policy_action"] == "block"
    assert result["reason_code"] == "native_post_tool_unavailable"
