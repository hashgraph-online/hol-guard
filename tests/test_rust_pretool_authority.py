"""Tests for Rust PreToolUse authority transport and daemon fail-closed behavior."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_pretool import (
    _decode_pre_tool,
    native_pre_tool_policy_floor,
    review_pre_tool_native,
)
from codex_plugin_scanner.guard.native_route_receipt import native_hook_route, reset_native_hook_route
from codex_plugin_scanner.guard.native_runtime import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
)


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
    assert _decode_pre_tool(payload, command="pwd") is None


def test_unavailable_native_pretool_records_fail_safe_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="force",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    reset_native_hook_route()

    assert (
        review_pre_tool_native(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )
    assert native_hook_route() == "native_fail_safe"


def test_missing_pretool_feature_records_fail_safe_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"runtime")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="auto",
            available=True,
            compatible=True,
            reason="ready",
            identity=NativeRuntimeIdentity(
                path=runtime,
                size=runtime.stat().st_size,
                mtime_ns=runtime.stat().st_mtime_ns,
                sha256="0" * 64,
            ),
            capabilities=NativeRuntimeCapabilities(
                protocol_version=2,
                runtime_version="test",
                rule_digest="1" * 64,
                build_sha="2" * 40,
                target="test",
                features=("resident-protocol-v2",),
            ),
        ),
    )
    reset_native_hook_route()

    assert (
        review_pre_tool_native(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )
    assert native_hook_route() == "native_fail_safe"


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
        native_pre_tool_policy_floor(
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
