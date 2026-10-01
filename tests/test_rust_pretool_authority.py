"""Tests for Rust PreToolUse authority transport and daemon fail-closed behavior."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_pretool as pretool
from codex_plugin_scanner.guard import native_route_receipt as routes
from codex_plugin_scanner.guard import native_runtime as runtime
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
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


def test_decode_pre_tool_rejects_unbound_command_model() -> None:
    payload = _native_allow("pwd")
    payload["command_model"] = {"normalized_text": "whoami"}
    assert pretool._decode_pre_tool(payload, command="pwd") is None


def test_unavailable_native_pretool_records_fail_safe_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: runtime.NativeRuntimeStatus(
            mode="force",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    routes.reset_native_hook_route()

    assert (
        pretool.review_pre_tool_native(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )
    assert routes.native_hook_route() == "native_fail_safe"


def test_missing_pretool_feature_records_fail_safe_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_path = tmp_path / "hol-guard-runtime"
    runtime_path.write_bytes(b"runtime")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: runtime.NativeRuntimeStatus(
            mode="auto",
            available=True,
            compatible=True,
            reason="ready",
            identity=runtime.NativeRuntimeIdentity(
                path=runtime_path,
                size=runtime_path.stat().st_size,
                mtime_ns=runtime_path.stat().st_mtime_ns,
                sha256="0" * 64,
            ),
            capabilities=runtime.NativeRuntimeCapabilities(
                protocol_version=2,
                runtime_version="test",
                rule_digest="1" * 64,
                build_sha="2" * 40,
                target="test",
                features=("resident-protocol-v2",),
            ),
        ),
    )
    routes.reset_native_hook_route()

    assert (
        pretool.review_pre_tool_native(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )
    assert routes.native_hook_route() == "native_fail_safe"


def test_policy_floor_uses_native_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.review_pre_tool_native",
        lambda *_args, **_kwargs: _native_block("rm -rf /"),
    )
    assert (
        pretool.native_pre_tool_policy_floor(
            "rm -rf /",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        == "block"
    )


def test_policy_floor_defers_contextual_git_helper_review_to_python(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native_review = _native_block("git diff --check")
    native_review.update(
        {
            "decision": "deny",
            "minimum_action": "review",
            "policy_action": "review",
            "reason_code": "native_git_helper_context_review",
        }
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.review_pre_tool_native",
        lambda *_args, **_kwargs: native_review,
    )

    assert (
        pretool.native_pre_tool_policy_floor(
            "git diff --check",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
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
        lambda: runtime.NativeRuntimeStatus(
            mode="force",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    assert (
        pretool.native_pre_tool_policy_floor(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        == "block"
    )


def test_policy_floor_skips_when_native_mode_is_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.review_pre_tool_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: runtime.NativeRuntimeStatus(mode="off", available=True, compatible=True, reason="off"),
    )
    assert (
        pretool.native_pre_tool_policy_floor(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


def test_hook_worker_returns_fail_safe_when_native_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "off")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: _native_allow("pwd"),
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
    assert result["reason_code"] == "native_hook_disabled"
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_worker_fails_closed_when_forced_native_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "force",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_runtime_status",
        lambda: runtime.NativeRuntimeStatus(
            mode="force",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "git push"}},
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "deny" and result["reason_code"] == "native_pre_tool_unavailable"


def test_hook_worker_fails_closed_when_auto_pretool_native_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
        lambda: runtime.NativeRuntimeStatus(
            mode="auto",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "git push"}},
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "deny"
    assert result["reason_code"] == "native_pre_tool_unavailable"


def test_hook_worker_falls_back_when_native_mode_is_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "off",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_runtime_status",
        lambda: runtime.NativeRuntimeStatus(mode="off", available=True, compatible=True, reason="off"),
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
    assert result["reason_code"] == "native_hook_disabled"


def test_hook_worker_denies_unreviewed_non_command_pretool_without_native_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "src/foo.ts"}},
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "deny"
    assert result["reason_code"] == "native_pre_tool_unavailable"


def test_hook_worker_leaves_out_of_scope_events_to_existing_handling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PermissionRequest", "tool_input": {"command": "pwd"}},
        params={},
        default_harness="claude-code",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["reason_code"] == "native_hook_event_unavailable" and result["continue"] is True
