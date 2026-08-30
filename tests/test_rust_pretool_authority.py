"""Tests for Rust PreToolUse authority and daemon fail-closed behavior."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker, HookWorkerUnsupported
from codex_plugin_scanner.guard.native_pretool import (
    _decode_pre_tool,
    native_pre_tool_policy_floor,
)
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeStatus
from codex_plugin_scanner.guard.store import GuardStore


def _native_allow(command: str) -> dict[str, Any]:
    return {
        "authority": "rust",
        "event_name": "PreToolUse",
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
        "event_name": "PreToolUse",
        "decision": "deny",
        "minimum_action": "block",
        "policy_action": "block",
        "reason_code": "native_destructive_command",
        "reason": "HOL Guard blocked a destructive command before execution.",
        "explicitly_benign": False,
        "command_model": {"normalized_text": command},
    }


def _native_review() -> dict[str, Any]:
    return {
        "authority": "rust",
        "event_name": "PreToolUse",
        "decision": "deny",
        "minimum_action": "review",
        "policy_action": "review",
        "reason_code": "native_pre_tool_unsupported_review",
        "reason": "HOL Guard requires review because the Rust authority could not prove this action benign.",
        "explicitly_benign": False,
    }


def _force_auto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "auto")


def test_decode_pre_tool_rejects_unbound_command_model() -> None:
    payload = _native_allow("pwd")
    payload["command_model"] = {"normalized_text": "whoami"}
    assert _decode_pre_tool(payload, command="pwd") is None


def test_policy_floor_uses_native_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.review_pre_tool_native",
        lambda *_args, **_kwargs: _native_block("rm -rf /"),
    )
    assert (
        native_pre_tool_policy_floor(
            "rm -rf /",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        == "block"
    )


def test_policy_floor_fails_closed_when_native_is_forced_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.review_pre_tool_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="force",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    assert (
        native_pre_tool_policy_floor(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        == "block"
    )


def test_policy_floor_compatibility_helper_still_skips_explicit_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.review_pre_tool_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: NativeRuntimeStatus(mode="off", available=True, compatible=True, reason="off"),
    )
    assert (
        native_pre_tool_policy_floor(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


def test_hook_worker_returns_native_allow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_auto(monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_hook_edge_native",
        lambda **_kwargs: _native_allow("pwd"),
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
        params={},
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["policy_action"] == "allow"
    assert result["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_hook_worker_fails_closed_when_native_hook_edge_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_auto(monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_hook_edge_native",
        lambda **_kwargs: None,
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "deny"
    assert result["reason_code"] == "native_hook_edge_unavailable"


def test_hook_worker_explicit_off_remains_compatibility_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "off")
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    with pytest.raises(HookWorkerUnsupported):
        worker.review_http_payload(
            payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
            params={},
            default_harness="pi",
            home_dir=tmp_path / "home",
            guard_home=tmp_path / "guard-home",
            workspace=tmp_path / "workspace",
        )


def test_hook_worker_keeps_non_command_pretool_in_native_review_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_auto(monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_hook_edge_native",
        lambda **_kwargs: _native_review(),
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
        },
        params={},
        default_harness="claude-code",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["policy_action"] == "review"
    assert result["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert result["reason_code"] == "native_pre_tool_unsupported_review"
